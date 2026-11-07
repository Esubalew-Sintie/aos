package core

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Conditions on grants (user-flow PERM-9) are written in a small
// expression language, a subset of CEL: identifiers with dots that read
// the request's context, string and number and boolean literals, the
// comparisons == != < <= > >=, "in" against a list, "&&", "||", "!" and
// parentheses. A condition that fails to parse or to evaluate counts as
// false, which refuses an allow and keeps a deny.
//
//	request.amount <= 1000 && request.currency == "ETB"
//	request.branch in ["b1", "b2"] || principal.role == "manager"

// CheckCondition reports whether an expression is well formed.
func CheckCondition(expr string) error {
	p := &parser{tokens: tokenize(expr), parseOnly: true}
	if _, err := p.parseOr(); err != nil {
		return err
	}
	if p.pos < len(p.tokens) {
		return fmt.Errorf("unexpected %q", p.tokens[p.pos].text)
	}
	return nil
}

// EvalCondition evaluates an expression against a context. A missing
// value is an error, so a condition never passes by accident.
func EvalCondition(expr string, env map[string]any) (bool, error) {
	p := &parser{tokens: tokenize(expr), env: env}
	v, err := p.parseOr()
	if err != nil {
		return false, err
	}
	if p.pos < len(p.tokens) {
		return false, fmt.Errorf("unexpected %q", p.tokens[p.pos].text)
	}
	b, ok := v.(bool)
	if !ok {
		return false, errors.New("the condition is not a true or false question")
	}
	return b, nil
}

// A nil context means nothing can be read: every lookup fails.
func init() { _ = lookup }

type token struct {
	kind string // ident, string, number, op, bool
	text string
}

func tokenize(s string) []token {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '"' || c == '\'':
			j := i + 1
			var sb strings.Builder
			for j < len(s) && s[j] != c {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				sb.WriteByte(s[j])
				j++
			}
			out = append(out, token{"string", sb.String()})
			i = j + 1
		case c >= '0' && c <= '9' || (c == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9'):
			j := i + 1
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.') {
				j++
			}
			out = append(out, token{"number", s[i:j]})
			i = j
		case unicode.IsLetter(rune(c)) || c == '_':
			j := i
			for j < len(s) && (unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j])) || s[j] == '_' || s[j] == '.') {
				j++
			}
			word := s[i:j]
			switch word {
			case "true", "false":
				out = append(out, token{"bool", word})
			case "in":
				out = append(out, token{"op", "in"})
			default:
				out = append(out, token{"ident", word})
			}
			i = j
		default:
			for _, op := range []string{"==", "!=", "<=", ">=", "&&", "||", "<", ">", "!", "(", ")", "[", "]", ","} {
				if strings.HasPrefix(s[i:], op) {
					out = append(out, token{"op", op})
					i += len(op)
					goto next
				}
			}
			out = append(out, token{"bad", string(c)})
			i++
		next:
		}
	}
	return out
}

type parser struct {
	tokens []token
	pos    int
	env    map[string]any
	// parseOnly checks the shape without reading any value.
	parseOnly bool
}

func (p *parser) peek() *token {
	if p.pos < len(p.tokens) {
		return &p.tokens[p.pos]
	}
	return nil
}

func (p *parser) accept(op string) bool {
	if t := p.peek(); t != nil && t.kind == "op" && t.text == op {
		p.pos++
		return true
	}
	return false
}

func (p *parser) parseOr() (any, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.accept("||") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		if p.parseOnly {
			left = true
			continue
		}
		l, lok := left.(bool)
		r, rok := right.(bool)
		if !lok || !rok {
			return nil, errors.New("|| needs true or false on both sides")
		}
		left = l || r
	}
	return left, nil
}

func (p *parser) parseAnd() (any, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.accept("&&") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		if p.parseOnly {
			left = true
			continue
		}
		l, lok := left.(bool)
		r, rok := right.(bool)
		if !lok || !rok {
			return nil, errors.New("&& needs true or false on both sides")
		}
		left = l && r
	}
	return left, nil
}

func (p *parser) parseNot() (any, error) {
	if p.accept("!") {
		v, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		if p.parseOnly {
			return true, nil
		}
		b, ok := v.(bool)
		if !ok {
			return nil, errors.New("! needs true or false")
		}
		return !b, nil
	}
	return p.parseComparison()
}

func (p *parser) parseComparison() (any, error) {
	left, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	if t == nil || t.kind != "op" {
		return left, nil
	}
	switch t.text {
	case "==", "!=", "<", "<=", ">", ">=":
		p.pos++
		right, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		if p.parseOnly {
			return true, nil
		}
		return compare(t.text, left, right)
	case "in":
		p.pos++
		right, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		if p.parseOnly {
			return true, nil
		}
		list, ok := right.([]any)
		if !ok {
			return nil, errors.New("in needs a list on the right")
		}
		for _, item := range list {
			if eq, _ := compare("==", left, item); eq == true {
				return true, nil
			}
		}
		return false, nil
	}
	return left, nil
}

func (p *parser) parseValue() (any, error) {
	t := p.peek()
	if t == nil {
		return nil, errors.New("the condition ends too early")
	}
	switch t.kind {
	case "op":
		switch t.text {
		case "(":
			p.pos++
			v, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			if !p.accept(")") {
				return nil, errors.New("missing )")
			}
			return v, nil
		case "[":
			p.pos++
			var list []any
			for !p.accept("]") {
				v, err := p.parseValue()
				if err != nil {
					return nil, err
				}
				list = append(list, v)
				if !p.accept(",") && !(p.peek() != nil && p.peek().text == "]") {
					return nil, errors.New("missing , in list")
				}
			}
			return list, nil
		}
		return nil, fmt.Errorf("unexpected %q", t.text)
	case "string":
		p.pos++
		return t.text, nil
	case "number":
		p.pos++
		f, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, fmt.Errorf("bad number %q", t.text)
		}
		return f, nil
	case "bool":
		p.pos++
		return t.text == "true", nil
	case "ident":
		p.pos++
		if p.parseOnly {
			return true, nil
		}
		return lookup(p.env, t.text)
	}
	return nil, fmt.Errorf("unexpected %q", t.text)
}

// lookup reads a dotted name from the context.
func lookup(env map[string]any, name string) (any, error) {
	var cur any = env
	for _, part := range strings.Split(name, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s is not in the context", name)
		}
		cur, ok = m[part]
		if !ok {
			return nil, fmt.Errorf("%s is not in the context", name)
		}
	}
	return normalize(cur), nil
}

func normalize(v any) any {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case float32:
		return float64(x)
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	}
	return v
}

func compare(op string, a, b any) (any, error) {
	a, b = normalize(a), normalize(b)
	switch x := a.(type) {
	case float64:
		y, ok := b.(float64)
		if !ok {
			return nil, errors.New("cannot compare a number with something else")
		}
		switch op {
		case "==":
			return x == y, nil
		case "!=":
			return x != y, nil
		case "<":
			return x < y, nil
		case "<=":
			return x <= y, nil
		case ">":
			return x > y, nil
		case ">=":
			return x >= y, nil
		}
	case string:
		y, ok := b.(string)
		if !ok {
			return nil, errors.New("cannot compare a string with something else")
		}
		switch op {
		case "==":
			return x == y, nil
		case "!=":
			return x != y, nil
		case "<":
			return x < y, nil
		case "<=":
			return x <= y, nil
		case ">":
			return x > y, nil
		case ">=":
			return x >= y, nil
		}
	case bool:
		y, ok := b.(bool)
		if !ok {
			return nil, errors.New("cannot compare true or false with something else")
		}
		switch op {
		case "==":
			return x == y, nil
		case "!=":
			return x != y, nil
		}
		return nil, errors.New("true and false can only be compared with == and !=")
	case nil:
		return nil, errors.New("cannot compare a missing value")
	}
	return nil, fmt.Errorf("cannot compare these values with %s", op)
}
