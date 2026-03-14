package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
)

// InspectedNode wraps a Core and ipv6rwc with packet inspection.
// It intercepts ReadFrom/WriteTo at the Core level and logs all traffic.
type InspectedNode struct {
	Core      *core.Core
	IPRWC     *ipv6rwc.ReadWriteCloser
	Inspector *PacketInspector
	index     int
}

// InspectedChain creates a chain of nodes with packet inspectors attached.
// pcapDir: directory to write pcap files (empty string = text-only to stderr).
// Returns the nodes and a cleanup function.
func InspectedChain(numNodes int, pcapDir string, logger interface{ EnableLevel(string) }) ([]*InspectedNode, func()) {
	nodes := make([]*InspectedNode, numNodes)

	for i := range nodes {
		name := fmt.Sprintf("node%d", i)
		var opts []InspectorOption

		if pcapDir != "" {
			os.MkdirAll(pcapDir, 0755)
			pcapPath := filepath.Join(pcapDir, name+".pcap")
			opts = append(opts, WithPcap(pcapPath))
		}
		opts = append(opts, WithTextLog(os.Stderr))

		inspector := NewPacketInspector(name, opts...)
		nodes[i] = &InspectedNode{
			Inspector: inspector,
			index:     i,
		}
	}

	cleanup := func() {
		for _, n := range nodes {
			if n.Core != nil {
				n.Core.Stop()
			}
			if n.Inspector != nil {
				n.Inspector.Close()
			}
		}
	}

	return nodes, cleanup
}

// CoreWriteTo wraps Core.WriteTo with packet capture.
func (n *InspectedNode) CoreWriteTo(p []byte, addr net.Addr) (int, error) {
	n.Inspector.Capture(DirSend, n.Core.LocalAddr(), addr, p,
		fmt.Sprintf("node=%d", n.index))
	nn, err := n.Core.WriteTo(p, addr)
	if err != nil {
		n.Inspector.CaptureEvent("WriteTo error",
			fmt.Sprintf("node=%d", n.index),
			fmt.Sprintf("err=%v", err))
	}
	return nn, err
}

// CoreReadFrom wraps Core.ReadFrom with packet capture.
func (n *InspectedNode) CoreReadFrom(p []byte) (int, net.Addr, error) {
	nn, from, err := n.Core.ReadFrom(p)
	if err == nil && nn > 0 {
		n.Inspector.Capture(DirRecv, from, n.Core.LocalAddr(), p[:nn],
			fmt.Sprintf("node=%d", n.index))
	}
	return nn, from, err
}
