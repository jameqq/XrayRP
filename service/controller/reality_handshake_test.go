package controller

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

// Updating the core must not silently reject valid, classical X25519 REALITY
// clients. Exercise actual authentication against a local TLS camouflage target.
func TestVlessRealityHandshakeCompatibility(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target.EnableHTTP2 = true
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	target.StartTLS()
	defer target.Close()
	// A synthetic target cannot finish the mirrored handshake. Seed the empty
	// post-handshake profile instead of waiting for REALITY's target sampler.
	for _, alpn := range []string{"0", "1", "2"} {
		cacheKey := target.Listener.Addr().String() + " example.com " + alpn
		reality.GlobalPostHandshakeRecordsLens.Store(cacheKey, []int{})
		defer reality.GlobalPostHandshakeRecordsLens.Delete(cacheKey)
	}

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := [8]byte{1, 2, 3, 4}
	for _, tc := range []struct {
		name, fingerprint string
		wrongKey          bool
	}{
		{"classical", "hellochrome_106_shuffle", false},
		{"hybrid", "chrome", false},
		{"wrong_key", "hellochrome_106_shuffle", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			serverResult := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverResult <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				secured, err := reality.Server(ctx, conn, &reality.Config{
					DialContext: (&net.Dialer{}).DialContext,
					Type:        "tcp", Dest: target.Listener.Addr().String(),
					ServerNames: map[string]bool{"example.com": true},
					PrivateKey:  key.Bytes(), ShortIds: map[[8]byte]bool{shortID: true},
				})
				if secured != nil {
					secured.Close()
				}
				serverResult <- err
			}()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			publicKey := key.PublicKey().Bytes()
			if tc.wrongKey {
				otherKey, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				publicKey = otherKey.PublicKey().Bytes()
			}
			secured, err := xreality.UClient(conn, &xreality.Config{
				ServerName: "example.com", Fingerprint: tc.fingerprint,
				PublicKey: publicKey, ShortId: shortID[:],
			}, ctx, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
			if tc.wrongKey {
				if secured != nil {
					defer secured.Close()
				}
				if err == nil && secured.(*xreality.UConn).Verified {
					t.Fatal("REALITY accepted an incorrect public key")
				}
				return
			}
			if err != nil {
				t.Fatalf("REALITY authentication failed: %v", err)
			}
			defer secured.Close()
			if !secured.(*xreality.UConn).Verified {
				t.Fatal("REALITY client received a fallback certificate")
			}
			select {
			case err := <-serverResult:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("REALITY server handshake timed out")
			}
		})
	}
}
