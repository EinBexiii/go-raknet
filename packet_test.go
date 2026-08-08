package raknet

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/go-raknet/internal"
)

// TestPacketReadEmptyFragment checks that an encapsulated packet holding no
// content is accepted when it is a fragment of a split packet. Servers exist
// that split every packet they send in two, which leaves the first fragment of
// a one byte packet empty.
func TestPacketReadEmptyFragment(t *testing.T) {
	// Captured from a server that splits every packet in two. It holds the
	// first fragment (of two) of a one byte packet, so its content is empty.
	b, err := hex.DecodeString("7000000200000100000000000002000200000000")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	pk := new(packet)
	n, err := pk.read(b)
	if err != nil {
		t.Fatalf("read empty fragment: %v", err)
	}
	if n != len(b) {
		t.Errorf("read %v bytes, want %v", n, len(b))
	}
	if !pk.split {
		t.Error("packet should have been marked as split")
	}
	if pk.content == nil {
		t.Error("content of a received fragment must never be nil")
	}
	if len(pk.content) != 0 {
		t.Errorf("content length %v, want 0", len(pk.content))
	}
	if pk.splitCount != 2 || pk.splitID != 2 || pk.splitIndex != 0 {
		t.Errorf("splitCount=%v splitID=%v splitIndex=%v, want 2/2/0", pk.splitCount, pk.splitID, pk.splitIndex)
	}
}

// TestPacketReadEmptyNotSplit checks that an encapsulated packet that is not a
// fragment is still rejected when it holds no content, as it carries no data.
func TestPacketReadEmptyNotSplit(t *testing.T) {
	// Same packet as above with the split flag cleared from its header.
	b, err := hex.DecodeString("6000000200000100000000000002000200000000")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := new(packet).read(b); err == nil {
		t.Fatal("expected an error for a zero length packet that is not split")
	}
}

// TestReceiveSplitPacketEmptyFragment checks that a split packet of which one
// fragment is empty is still reassembled. An empty fragment must not be
// mistaken for a fragment that was not received yet.
func TestReceiveSplitPacketEmptyFragment(t *testing.T) {
	conn := testConn(t)
	defer conn.closeImmediately()

	// The first fragment is empty and the second holds the only byte, exactly
	// as a server splitting every packet in two sends a one byte packet.
	for _, frag := range []*packet{
		{reliability: reliabilityReliableOrdered, split: true, splitCount: 2, splitID: 9, splitIndex: 0, content: []byte{}},
		{reliability: reliabilityReliableOrdered, split: true, splitCount: 2, splitID: 9, splitIndex: 1, content: []byte{0x7f}},
	} {
		buf := new(bytes.Buffer)
		frag.write(buf)
		if err := conn.handleDatagram(buf.Bytes()); err != nil {
			t.Fatalf("handle datagram of fragment %v: %v", frag.splitIndex, err)
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	b, err := conn.ReadPacket()
	if err != nil {
		t.Fatalf("read reassembled packet: %v", err)
	}
	if !bytes.Equal(b, []byte{0x7f}) {
		t.Errorf("reassembled packet = %x, want 7f", b)
	}
}

// testConn returns a Conn backed by a local socket, usable for feeding
// datagrams into directly.
func testConn(t *testing.T) *Conn {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:19132")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return newConn(pc, raddr, maxMTUSize, passthroughHandler{})
}

// passthroughHandler is a connectionHandler that leaves every packet to be read
// from the Conn itself.
type passthroughHandler struct{}

func (passthroughHandler) handle(*Conn, []byte) (bool, error) { return false, nil }
func (passthroughHandler) limitsEnabled() bool                { return true }
func (passthroughHandler) close(*Conn)                        {}
func (passthroughHandler) log() *slog.Logger                  { return slog.New(internal.DiscardHandler{}) }
