package controller

import (
	"strings"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/spf13/viper"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
)

const testVlessDecryption = "mlkem768x25519plus.native.600s.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEA"

func TestVlessDecryptionConfig(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader("ControllerConfig:\n  VlessDecryption: " + testVlessDecryption)); err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := v.UnmarshalKey("ControllerConfig", &config); err != nil {
		t.Fatal(err)
	}
	if config.VlessDecryption != testVlessDecryption {
		t.Fatalf("decryption not decoded: %q", config.VlessDecryption)
	}
}

func TestVlessEncryptionInbound(t *testing.T) {
	for _, tc := range []struct {
		name, decryption, wantKey string
		fallback, wantError       bool
	}{
		{name: "default", wantKey: "none"},
		{name: "disabled", decryption: "none", wantKey: "none"},
		{name: "native", decryption: testVlessDecryption, wantKey: strings.Split(testVlessDecryption, ".")[3]},
		{name: "trimmed", decryption: " " + testVlessDecryption + " ", wantKey: strings.Split(testVlessDecryption, ".")[3]},
		{name: "invalid", decryption: "invalid", wantError: true},
		{name: "fallback", decryption: testVlessDecryption, fallback: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{VlessDecryption: tc.decryption, EnableFallback: tc.fallback}
			if tc.fallback {
				config.FallBackConfigs = []*FallBackConfig{{Dest: "80"}}
			}
			node := &api.NodeInfo{NodeType: "V2ray", EnableVless: true, Port: 21636, TransportProtocol: "xhttp"}
			built, err := InboundBuilder(config, node, "test")
			if tc.wantError {
				if err == nil {
					t.Fatal("expected invalid configuration to fail")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			message, err := built.ProxySettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			settings := message.(*inbound.Config)
			if settings.Decryption != tc.wantKey {
				t.Fatalf("got decryption %q, want %q", settings.Decryption, tc.wantKey)
			}
			if tc.wantKey != "none" && (settings.XorMode != 0 || settings.SecondsFrom != 600) {
				t.Fatalf("native settings not preserved: %v", settings)
			}
		})
	}
}

func TestVlessEncryptionVision(t *testing.T) {
	for _, tc := range []struct {
		name, transport, decryption, wantFlow string
		tls                                   bool
	}{
		{"xhttp_encrypted", "xhttp", testVlessDecryption, vless.XRV, false},
		{"xhttp_disabled", "xhttp", "none", "", true},
		{"xhttp_default", "xhttp", "", "", true},
		{"tcp_tls", "tcp", "", vless.XRV, true},
		{"tcp_plain", "tcp", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Controller{config: &Config{VlessDecryption: tc.decryption}, nodeInfo: &api.NodeInfo{TransportProtocol: tc.transport, EnableTLS: tc.tls, VlessFlow: vless.XRV}}
			users := []api.UserInfo{{UID: 1, UUID: "5783a3e7-e373-51cd-8642-c83782b807c5"}}
			built := c.buildVlessUser(&users)
			message, err := built[0].Account.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if got := message.(*vless.Account).Flow; got != tc.wantFlow {
				t.Fatalf("flow = %q, want %q", got, tc.wantFlow)
			}
		})
	}
}
