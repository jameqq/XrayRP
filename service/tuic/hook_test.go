package tuic

import (
	"errors"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"testing"
	"time"
)

type testPacketConn struct {
	N.PacketConn
	writeErr error
	writes   int
}

func (c *testPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	_, err := b.Write([]byte("upload"))
	return M.Socksaddr{}, err
}
func (c *testPacketConn) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	c.writes++
	b.Release()
	return c.writeErr
}
func TestPacketTraffic(t *testing.T) {
	s := &TuicService{traffic: make(map[string]*userTraffic), onlineIPs: make(map[string]map[string]struct{}), ipLastActive: make(map[string]map[string]time.Time)}
	upstream := &testPacketConn{}
	c := &packetConnCounter{PacketConn: upstream, svc: s, user: "user", host: "192.0.2.1"}
	b := buf.New()
	defer b.Release()
	if _, err := c.ReadPacket(b); err != nil {
		t.Fatal(err)
	}
	out := buf.As([]byte("down"))
	if err := c.WritePacket(out, M.Socksaddr{}); err != nil {
		t.Fatal(err)
	}
	got := s.traffic["user"]
	if got == nil || got.Upload != 6 || got.Download != 4 {
		t.Fatalf("wrong traffic: %+v", got)
	}
	if _, ok := s.onlineIPs["user"]["192.0.2.1"]; !ok {
		t.Fatal("missing online IP")
	}
	upstream.writeErr = io.ErrClosedPipe
	if err := c.WritePacket(buf.As([]byte("failed")), M.Socksaddr{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if got.Download != 4 {
		t.Fatal("counted failed write")
	}
	c.blocked = true
	if _, err := c.ReadPacket(b); !errors.Is(err, io.EOF) {
		t.Fatalf("blocked read: %v", err)
	}
	if err := c.WritePacket(buf.As([]byte("blocked")), M.Socksaddr{}); !errors.Is(err, io.EOF) {
		t.Fatalf("blocked write: %v", err)
	}
	if upstream.writes != 2 {
		t.Fatal("blocked write reached upstream")
	}
}
