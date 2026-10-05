package controller

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/xtls/reality"
)

func TestVlessRealityBufferLayout(t *testing.T) {
	// Xray's Vision reader casts these fields to bytes.Reader and bytes.Buffer.
	// A pointer-valued rawInput is incompatible with that unsafe field access.
	connType := reflect.TypeOf(reality.Conn{})
	for _, field := range []struct {
		name   string
		typeOf reflect.Type
	}{
		{name: "input", typeOf: reflect.TypeOf(bytes.Reader{})},
		{name: "rawInput", typeOf: reflect.TypeOf(bytes.Buffer{})},
	} {
		t.Run(field.name, func(t *testing.T) {
			got, ok := connType.FieldByName(field.name)
			if !ok {
				t.Fatalf("REALITY connection is missing the %s field required by Vision", field.name)
			}
			if got.Type != field.typeOf {
				t.Fatalf("Vision expects %s to be %v; REALITY provides %v", field.name, field.typeOf, got.Type)
			}
		})
	}
}
