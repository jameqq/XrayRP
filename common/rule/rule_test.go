package rule

import (
	"regexp"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestClearRules(t *testing.T) {
	m := New()
	rules := []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("blocked")}}
	if err := m.UpdateRule("node", rules); err != nil {
		t.Fatal(err)
	}
	if !m.Detect("node", "blocked.example", "1", "192.0.2.1") {
		t.Fatal("expected initial rule to match")
	}
	if err := m.UpdateRule("node", []api.DetectRule{}); err != nil {
		t.Fatal(err)
	}
	if m.Detect("node", "blocked.example", "1", "192.0.2.1") {
		t.Fatal("removed rule still blocks traffic")
	}
}
