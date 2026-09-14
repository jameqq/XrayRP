package versioninfo

import (
	"runtime/debug"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	info := &debug.BuildInfo{Deps: []*debug.Module{
		{Path: "github.com/xtls/xray-core", Version: "v1.2.3"},
		{Path: "github.com/apernet/hysteria/core/v2", Version: "v2.12.2"},
		{Path: "github.com/sagernet/sing-box", Version: "v1.14.0"},
	}}
	got := fromBuildInfo(info)
	if got.XrayCore != "v1.2.3" || got.Hysteria != "v2.12.2" || got.SingBox != "v1.14.0" {
		t.Fatalf("unexpected dependency versions: %+v", got)
	}
}

func TestReplacementVersionWins(t *testing.T) {
	info := &debug.BuildInfo{Deps: []*debug.Module{{
		Path:    "github.com/xtls/xray-core",
		Version: "v1.0.0",
		Replace: &debug.Module{Version: "v1.1.0"},
	}}}
	if got := fromBuildInfo(info).XrayCore; got != "v1.1.0" {
		t.Fatalf("replacement version not used: %s", got)
	}
}
