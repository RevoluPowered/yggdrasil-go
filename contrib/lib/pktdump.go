package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// PacketInspector captures yggdrasil packets to pcap files and/or text logs.
// Attach one per Core node to see what's flowing through it.
//
// Usage in tests:
//
//	inspector := NewPacketInspector("node0", WithPcap("node0.pcap"), WithTextLog(os.Stderr))
//	defer inspector.Close()
//	// Then wrap Core.ReadFrom/WriteTo or pass to test helpers
type PacketInspector struct {
	name string

	mu     sync.Mutex
	pcapW  io.WriteCloser
	textW  io.Writer
	start  time.Time
	pktSeq uint64

	// pcap link type: we use DLT_RAW (101) since we're capturing raw IPv6
	// or DLT_USER0 (147) for custom yggdrasil frames
	linkType uint32
}

// PacketDir indicates whether a packet is inbound or outbound.
type PacketDir int

const (
	DirSend PacketDir = iota
	DirRecv
	DirForward
	DirDrop
	DirBroken // path broken
)

func (d PacketDir) String() string {
	switch d {
	case DirSend:
		return "TX"
	case DirRecv:
		return "RX"
	case DirForward:
		return "FWD"
	case DirDrop:
		return "DROP"
	case DirBroken:
		return "BROKEN"
	default:
		return "?"
	}
}

// InspectorOption configures a PacketInspector.
type InspectorOption func(*PacketInspector)

// WithPcap writes packets to a pcap file readable by Wireshark/tcpdump.
// Uses DLT_RAW (101) for raw IPv6 packets, or DLT_USER0 (147) for
// yggdrasil-framed packets.
func WithPcap(path string) InspectorOption {
	return func(pi *PacketInspector) {
		f, err := os.Create(path)
		if err != nil {
			panic(fmt.Sprintf("pktdump: cannot create pcap %s: %v", path, err))
		}
		pi.pcapW = f
	}
}

// WithPcapWriter writes pcap data to an arbitrary writer.
func WithPcapWriter(w io.WriteCloser) InspectorOption {
	return func(pi *PacketInspector) {
		pi.pcapW = w
	}
}

// WithTextLog writes human-readable packet summaries to the given writer.
func WithTextLog(w io.Writer) InspectorOption {
	return func(pi *PacketInspector) {
		pi.textW = w
	}
}

// WithLinkType sets the pcap link-layer type.
// Default is 101 (DLT_RAW) which works for raw IPv6 payloads.
// Use 147 (DLT_USER0) for custom framing.
func WithLinkType(lt uint32) InspectorOption {
	return func(pi *PacketInspector) {
		pi.linkType = lt
	}
}

// NewPacketInspector creates a packet inspector for a named node.
func NewPacketInspector(name string, opts ...InspectorOption) *PacketInspector {
	pi := &PacketInspector{
		name:     name,
		start:    time.Now(),
		linkType: 101, // DLT_RAW
	}
	for _, opt := range opts {
		opt(pi)
	}
	if pi.pcapW != nil {
		pi.writePcapHeader()
	}
	return pi
}

// Capture records a packet. Call this from instrumented ReadFrom/WriteTo paths.
//
//   - dir: send/recv/forward/drop/broken
//   - src, dst: yggdrasil addresses (16-byte IPv6 or 32-byte ed25519 pubkey)
//   - payload: the raw packet bytes
//   - meta: optional key=value metadata for text log (e.g. "hop=3", "peer=abc123")
func (pi *PacketInspector) Capture(dir PacketDir, src, dst net.Addr, payload []byte, meta ...string) {
	if pi == nil {
		return
	}
	now := time.Now()

	pi.mu.Lock()
	defer pi.mu.Unlock()

	pi.pktSeq++
	seq := pi.pktSeq

	if pi.pcapW != nil {
		pi.writePcapPacket(now, payload)
	}

	if pi.textW != nil {
		elapsed := now.Sub(pi.start)
		srcStr := addrStr(src)
		dstStr := addrStr(dst)

		fmt.Fprintf(pi.textW, "[%s] #%d %s +%v %s -> %s len=%d",
			pi.name, seq, dir, elapsed.Round(time.Microsecond), srcStr, dstStr, len(payload))

		for _, m := range meta {
			fmt.Fprintf(pi.textW, " %s", m)
		}

		// Hex dump first 32 bytes for quick eyeballing
		if len(payload) > 0 {
			n := len(payload)
			if n > 32 {
				n = 32
			}
			fmt.Fprintf(pi.textW, " head=%s", hex.EncodeToString(payload[:n]))
		}

		fmt.Fprintln(pi.textW)
	}
}

// CaptureEvent logs a non-packet event (e.g. connection established, tree change).
func (pi *PacketInspector) CaptureEvent(event string, meta ...string) {
	if pi == nil || pi.textW == nil {
		return
	}
	now := time.Now()

	pi.mu.Lock()
	defer pi.mu.Unlock()

	elapsed := now.Sub(pi.start)
	fmt.Fprintf(pi.textW, "[%s] EVENT +%v %s", pi.name, elapsed.Round(time.Microsecond), event)
	for _, m := range meta {
		fmt.Fprintf(pi.textW, " %s", m)
	}
	fmt.Fprintln(pi.textW)
}

// Close flushes and closes all outputs.
func (pi *PacketInspector) Close() error {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	if pi.pcapW != nil {
		return pi.pcapW.Close()
	}
	return nil
}

// --- pcap format ---

// writePcapHeader writes the pcap global header (24 bytes).
// https://wiki.wireshark.org/Development/LibpcapFileFormat
func (pi *PacketInspector) writePcapHeader() {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)   // magic
	binary.LittleEndian.PutUint16(hdr[4:6], 2)             // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)             // version minor
	binary.LittleEndian.PutUint32(hdr[8:12], 0)            // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0)           // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)       // snaplen
	binary.LittleEndian.PutUint32(hdr[20:24], pi.linkType) // link type
	pi.pcapW.Write(hdr[:])
}

// writePcapPacket writes one pcap packet record (16-byte header + payload).
func (pi *PacketInspector) writePcapPacket(ts time.Time, data []byte) {
	var hdr [16]byte
	sec := ts.Unix()
	usec := ts.Nanosecond() / 1000
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(sec))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(usec))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(data)))  // incl_len
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(data))) // orig_len
	pi.pcapW.Write(hdr[:])
	pi.pcapW.Write(data)
}

// --- helpers ---

func addrStr(a net.Addr) string {
	if a == nil {
		return "<nil>"
	}
	s := a.String()
	// Truncate long hex keys to first 8 chars for readability
	if len(s) > 20 {
		return s[:8] + ".." + s[len(s)-4:]
	}
	return s
}
