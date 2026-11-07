package initiator

import (
	"bytes"
	"os"
	"testing"
)

// TestOpenAPIIsCurrent fails when a route has no doc, or when the saved
// document was not regenerated after a change. The engine's is
// api/openapi.json; a build with the hosted service has more routes and
// keeps api/openapi.hosted.json. Regenerate with:
//
//	go run ./cmd openapi > api/openapi.json          (or openapi.hosted.json)
func TestOpenAPIIsCurrent(t *testing.T) {
	spec, err := OpenAPI(Version)
	if err != nil {
		t.Fatal(err)
	}
	spec = append(spec, '\n')
	file := "api/openapi.json"
	if Extended() {
		file = "api/openapi.hosted.json"
	}
	committed, err := os.ReadFile("../" + file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	if !bytes.Equal(spec, committed) {
		t.Fatalf("%s is out of date: run `go run ./cmd openapi > %s`", file, file)
	}
}
