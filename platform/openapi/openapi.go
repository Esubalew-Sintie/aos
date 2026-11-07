// Package openapi builds an OpenAPI 3.1 document from Go types by
// reflection: one schema per struct, named after the type.
package openapi

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Operation is one route to describe.
type Operation struct {
	Method   string
	Path     string
	Summary  string
	Tag      string
	Security string // name of the security scheme, or ""
	Request  any
	Response any
	// Envelope wraps the response in {status, message, data, error}.
	Envelope bool
	Form     bool
}

// Document is an OpenAPI 3.1 document under construction.
type Document struct {
	doc     map[string]any
	schemas map[string]any
	names   map[reflect.Type]string
	used    map[string]reflect.Type
}

func New(title, version, description string, security map[string]any) *Document {
	d := &Document{schemas: map[string]any{}, names: map[reflect.Type]string{}, used: map[string]reflect.Type{}}
	d.doc = map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]any{"title": title, "version": version, "description": description},
		"paths":   map[string]any{},
		"components": map[string]any{
			"schemas":         d.schemas,
			"securitySchemes": security,
		},
	}
	return d
}

var pathParam = strings.NewReplacer()

// Add describes one operation.
func (d *Document) Add(op Operation) {
	paths := d.doc["paths"].(map[string]any)
	item, _ := paths[op.Path].(map[string]any)
	if item == nil {
		item = map[string]any{}
		paths[op.Path] = item
	}
	o := map[string]any{
		"summary":     op.Summary,
		"operationId": operationID(op.Method, op.Path),
		"tags":        []string{op.Tag},
	}
	var params []any
	for _, seg := range strings.Split(op.Path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			params = append(params, map[string]any{"name": seg[1 : len(seg)-1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
	}
	if params != nil {
		o["parameters"] = params
	}
	if op.Security != "" {
		o["security"] = []any{map[string]any{op.Security: []string{}}}
	}
	if op.Request != nil {
		ct := "application/json"
		if op.Form {
			ct = "application/x-www-form-urlencoded"
		}
		o["requestBody"] = map[string]any{"required": true, "content": map[string]any{ct: map[string]any{"schema": d.Schema(reflect.TypeOf(op.Request))}}}
	} else if op.Form {
		o["requestBody"] = map[string]any{"content": map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": map[string]any{"type": "object"}}}}
	}
	var body map[string]any
	switch {
	case op.Envelope:
		data := any(map[string]any{"type": "null"})
		if op.Response != nil {
			data = d.Schema(reflect.TypeOf(op.Response))
		}
		body = map[string]any{"allOf": []any{map[string]any{"$ref": "#/components/schemas/Envelope"}, map[string]any{"type": "object", "properties": map[string]any{"data": data}}}}
	case op.Response != nil:
		body = d.Schema(reflect.TypeOf(op.Response))
	default:
		body = map[string]any{"type": "object"}
	}
	o["responses"] = map[string]any{
		"2XX":     map[string]any{"description": "Success", "content": map[string]any{"application/json": map[string]any{"schema": body}}},
		"default": map[string]any{"description": "Error", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Envelope"}}}},
	}
	item[strings.ToLower(op.Method)] = o
}

// SetSchema adds a hand-written schema.
func (d *Document) SetSchema(name string, schema map[string]any) { d.schemas[name] = schema }

// JSON returns the document, stable from run to run.
func (d *Document) JSON() ([]byte, error) {
	return json.MarshalIndent(d.doc, "", "  ")
}

func operationID(method, path string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	for _, seg := range strings.Split(path, "/") {
		seg = strings.Trim(seg, "{}")
		for _, part := range strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			if part == "" {
				continue
			}
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String()
}

var (
	timeType = reflect.TypeOf(time.Time{})
	rawType  = reflect.TypeOf(json.RawMessage{})
)

// Schema returns the schema of a type, adding named structs to the
// components and referring to them.
func (d *Document) Schema(t reflect.Type) map[string]any {
	switch {
	case t == timeType:
		return map[string]any{"type": "string", "format": "date-time"}
	case t == rawType:
		return map[string]any{}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return d.Schema(t.Elem())
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": "string", "contentEncoding": "base64"}
		}
		return map[string]any{"type": "array", "items": d.Schema(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": d.Schema(t.Elem())}
	case reflect.Interface:
		return map[string]any{}
	case reflect.Struct:
		return map[string]any{"$ref": "#/components/schemas/" + d.structName(t)}
	}
	return map[string]any{}
}

func (d *Document) structName(t reflect.Type) string {
	if name, ok := d.names[t]; ok {
		return name
	}
	name := t.Name()
	if other, taken := d.used[name]; taken && other != t {
		// Two packages use one name: qualify by package.
		pkg := t.PkgPath()[strings.LastIndex(t.PkgPath(), "/")+1:]
		name = strings.ToUpper(pkg[:1]) + pkg[1:] + name
	}
	d.names[t] = name
	d.used[name] = t
	props := map[string]any{}
	d.schemas[name] = map[string]any{"type": "object", "properties": props}
	d.fields(t, props)
	return name
}

func (d *Document) fields(t reflect.Type, props map[string]any) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				d.fields(et, props)
				continue
			}
		}
		if name == "" {
			name = f.Name
		}
		props[name] = d.Schema(f.Type)
	}
}

// SortedKeys is a helper for stable output in callers.
func SortedKeys[M ~map[string]V, V any](m M) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
