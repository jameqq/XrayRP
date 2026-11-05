package controller

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/xtls/reality"
)

func TestVlessRealityBufferLayout(t *testing.T) {
	// Xray's Vision reader supports both historical value and current pointer
	// layouts for rawInput, while input remains a bytes.Reader value.
	connType := reflect.TypeOf(reality.Conn{})
	input, ok := connType.FieldByName("input")
	if !ok {
		t.Fatal("REALITY connection is missing the input field required by Vision")
	}
	if want := reflect.TypeOf(bytes.Reader{}); input.Type != want {
		t.Fatalf("Vision expects input to be %v; REALITY provides %v", want, input.Type)
	}

	rawInput, ok := connType.FieldByName("rawInput")
	if !ok {
		t.Fatal("REALITY connection is missing the rawInput field required by Vision")
	}
	valueType := reflect.TypeOf(bytes.Buffer{})
	pointerType := reflect.TypeOf(&bytes.Buffer{})
	if rawInput.Type != valueType && rawInput.Type != pointerType {
		t.Fatalf("Vision expects rawInput to be %v or %v; REALITY provides %v", valueType, pointerType, rawInput.Type)
	}
}
