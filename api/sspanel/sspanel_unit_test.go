package sspanel

import (
	"encoding/json"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func newUnitTestClient() *APIClient {
	return New(&api.Config{
		APIHost:     "https://example.com",
		Key:         "test-key",
		NodeID:      550,
		NodeType:    "V2ray",
		EnableVless: true,
		VlessFlow:   "xtls-rprx-vision",
	})
}

func TestParseSSPanelNodeInfoUsesLocalVlessAndRealityConfig(t *testing.T) {
	client := newUnitTestClient()
	payload := CustomConfig{
		OffsetPortNode: "443",
		Host:           "panel.example.com",
		Network:        "tcp",
		Security:       "reality",
		EnableREALITY:  true,
		Sni:            "store.playstation.com",
		RealityOpts: &REALITYConfig{
			Dest:             "store.playstation.com:443",
			ProxyProtocolVer: 1,
			ServerNames:      []string{"store.playstation.com"},
			PrivateKey:       "private-key",
			ShortIds:         []string{"", "7896182B"},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal custom config: %v", err)
	}

	nodeInfo, err := client.ParseSSPanelNodeInfo(&NodeInfoResponse{SpeedLimit: 10, CustomConfig: raw})
	if err != nil {
		t.Fatalf("ParseSSPanelNodeInfo returned error: %v", err)
	}
	if nodeInfo.NodeType != "Vless" {
		t.Fatalf("expected node type Vless, got %q", nodeInfo.NodeType)
	}
	if !nodeInfo.EnableVless {
		t.Fatal("expected EnableVless to be true")
	}
	if !nodeInfo.EnableREALITY {
		t.Fatal("expected EnableREALITY to be true")
	}
	if nodeInfo.VlessFlow != client.VlessFlow {
		t.Fatalf("expected VlessFlow %q, got %q", client.VlessFlow, nodeInfo.VlessFlow)
	}
	if nodeInfo.REALITYConfig == nil || nodeInfo.REALITYConfig.PrivateKey != "private-key" {
		t.Fatalf("expected parsed reality config, got %#v", nodeInfo.REALITYConfig)
	}
}

func TestParseV2rayNodeResponseNormalizesLegacyV2rayToVless(t *testing.T) {
	client := newUnitTestClient()
	nodeInfo, err := client.ParseV2rayNodeResponse(&NodeInfoResponse{
		SpeedLimit:      10,
		RawServerString: "server;0;443;0;ws;tls;path=/ray|host=cdn.example.com",
	})
	if err != nil {
		t.Fatalf("ParseV2rayNodeResponse returned error: %v", err)
	}
	if nodeInfo.NodeType != "Vless" {
		t.Fatalf("expected node type Vless, got %q", nodeInfo.NodeType)
	}
	if !nodeInfo.EnableVless {
		t.Fatal("expected EnableVless to be true")
	}
}

func TestParseUserListResponseClearsLastReportSnapshot(t *testing.T) {
	client := newUnitTestClient()
	client.LastReportOnline[1] = 2

	users, err := client.ParseUserListResponse(&[]UserResponse{{
		ID:          1,
		UUID:        "uuid-1",
		SpeedLimit:  5,
		DeviceLimit: 3,
		AliveIP:     1,
	}})
	if err != nil {
		t.Fatalf("ParseUserListResponse returned error: %v", err)
	}
	if len(*users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(*users))
	}
	if got := (*users)[0].DeviceLimit; got != 4 {
		t.Fatalf("expected effective device limit 4, got %d", got)
	}
	if len(client.LastReportOnline) != 0 {
		t.Fatalf("expected LastReportOnline to be cleared, got %#v", client.LastReportOnline)
	}
}
