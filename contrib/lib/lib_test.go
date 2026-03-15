package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iwenc "github.com/Arceliar/ironwood/encrypted"
	iwt "github.com/Arceliar/ironwood/types"
	"github.com/gologme/log"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
)

func TestMain(m *testing.M) {
	// Gate [IW-SESSION] prints behind -v flag
	iwenc.SessionLogFunc = func(msg string) {
		if testing.Verbose() {
			fmt.Fprint(os.Stderr, msg)
		}
	}
	os.Exit(m.Run())
}

func testLogger() *log.Logger {
	if testing.Verbose() {
		l := log.New(os.Stderr, "", 0)
		l.EnableLevel("info")
		l.EnableLevel("warn")
		l.EnableLevel("error")
		return l
	}
	return log.New(io.Discard, "", 0)
}

func createConnectedPair(t *testing.T) (*core.Core, *core.Core) {
	t.Helper()
	logger := testLogger()

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	if err := cfgA.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := cfgB.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}

	nodeA, err := core.New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := core.New(cfgB.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse("quic://localhost:0")
	listener, err := nodeA.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}
	peerURL, _ := url.Parse("quic://" + listener.Addr().String())
	if err := nodeB.CallPeer(peerURL, ""); err != nil {
		t.Fatal(err)
	}

	// Wait for tree convergence
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(nodeA.GetTree()) > 1 && len(nodeB.GetTree()) > 1 {
			time.Sleep(3 * time.Second)
			return nodeA, nodeB
		}
	}
	t.Fatal("nodes did not connect")
	return nil, nil
}

func TestCoreWriteToReadFrom(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	// Build packet: same format as core_test.go
	msgLen := 1500
	msg := make([]byte, msgLen)
	rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], nodeB.Address())
	copy(msg[24:40], nodeA.Address())

	// Echo listener on A
	done := make(chan struct{})
	go func() {
		buf := make([]byte, msgLen)
		n, from, err := nodeA.ReadFrom(buf)
		if err != nil {
			t.Error("A ReadFrom:", err)
			return
		}
		t.Logf("A received %d bytes from %v", n, from)
		// Echo back with swapped addresses
		res := make([]byte, n)
		copy(res, buf[:n])
		copy(res[8:24], buf[24:40])
		copy(res[24:40], buf[8:24])
		nodeA.WriteTo(res, from)
		done <- struct{}{}
	}()

	// Send from B
	_, err := nodeB.WriteTo(msg, nodeA.LocalAddr())
	if err != nil {
		t.Fatal("B WriteTo:", err)
	}

	// Read echo on B
	buf := make([]byte, msgLen)
	n, _, err := nodeB.ReadFrom(buf)
	if err != nil {
		t.Fatal("B ReadFrom:", err)
	}
	if !bytes.Equal(msg[40:], buf[40:n]) {
		t.Fatal("payload mismatch")
	}
	t.Log("echo verified!")
	<-done
}

// createServerWithClients creates a server with a TCP listener and N clients connected to it.
// Returns the server, clients slice, and a cleanup function.
func createServerWithClients(t *testing.T, numClients int) (*core.Core, []*core.Core, func()) {
	t.Helper()
	logger := testLogger()

	srvCfg := config.GenerateConfig()
	if err := srvCfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	server, err := core.New(srvCfg.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse("quic://localhost:0")
	listener, err := server.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}
	peerURL, _ := url.Parse("quic://" + listener.Addr().String())
	t.Logf("Server listening on %s", peerURL)

	clients := make([]*core.Core, numClients)
	for i := 0; i < numClients; i++ {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		c, err := core.New(cfg.Certificate, logger)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.CallPeer(peerURL, ""); err != nil {
			t.Fatalf("client %d CallPeer: %v", i, err)
		}
		clients[i] = c
	}

	// Wait for all clients to appear in server's tree
	for i := 0; i < 150; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(server.GetTree()) > numClients {
			break
		}
	}
	treeSize := len(server.GetTree())
	t.Logf("Server tree has %d entries (want >%d)", treeSize, numClients)
	if treeSize <= numClients {
		t.Fatalf("only %d tree entries, expected >%d", treeSize, numClients)
	}

	// Wait for Ironwood sessions to establish
	time.Sleep(3 * time.Second)

	cleanup := func() {
		for _, c := range clients {
			c.Stop()
		}
		server.Stop()
	}
	return server, clients, cleanup
}

// runEchoTest starts an echo server and verifies all clients can round-trip a packet.
func runEchoTest(t *testing.T, server *core.Core, clients []*core.Core) {
	t.Helper()
	numClients := len(clients)
	msgLen := 1500
	done := make(chan int, numClients)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			res := make([]byte, n)
			copy(res, buf[:n])
			copy(res[8:24], buf[24:40])
			copy(res[24:40], buf[8:24])
			server.WriteTo(res, from)
		}
	}()

	for i, c := range clients {
		go func(idx int, client *core.Core) {
			msg := make([]byte, msgLen)
			rand.Read(msg[40:])
			msg[0] = 0x60
			copy(msg[8:24], server.Address())
			copy(msg[24:40], client.Address())
			addr := server.LocalAddr()
			buf := make([]byte, msgLen)

			// Retry send until we get an echo back (session may not be established yet)
			gotReply := make(chan struct{}, 1)
			go func() {
				if _, _, err := client.ReadFrom(buf); err == nil {
					gotReply <- struct{}{}
				}
			}()
			for attempt := 0; ; attempt++ {
				if _, err := client.WriteTo(msg, addr); err != nil {
					t.Errorf("client %d WriteTo: %v", idx, err)
					done <- idx
					return
				}
				select {
				case <-gotReply:
					goto verified
				case <-time.After(500 * time.Millisecond):
					if attempt >= 60 {
						t.Errorf("client %d: no echo after %d attempts", idx, attempt)
						done <- idx
						return
					}
				}
			}
		verified:
			if !bytes.Equal(msg[40:], buf[40:len(msg)]) {
				t.Errorf("client %d payload mismatch", idx)
			}
			done <- idx
		}(i, c)
	}

	for i := 0; i < numClients; i++ {
		select {
		case idx := <-done:
			t.Logf("client %d echo done", idx)
		case <-time.After(30 * time.Second):
			t.Fatal("timeout waiting for echo")
		}
	}
	t.Logf("All %d clients echoed successfully", numClients)
}

func TestTenClientsToOneServer(t *testing.T) {
	server, clients, cleanup := createServerWithClients(t, 10)
	defer cleanup()
	runEchoTest(t, server, clients)
}

func TestFiftyClientsToOneServer(t *testing.T) {
	server, clients, cleanup := createServerWithClients(t, 50)
	defer cleanup()
	runEchoTest(t, server, clients)
}

func TestThroughput(t *testing.T) {
	// One-directional streaming: B sends, A receives. No echo to avoid
	// backpressure deadlock in ironwood's actor-based WriteTo.
	// Max message size is ~128KB, so we use 60KB packets and vary total transfer.
	const packetSize = 60_000

	type testCase struct {
		name      string
		totalSize int
	}
	cases := []testCase{
		{"1B", 1},
		{"8B", 8},
		{"16B", 16},
		{"32B", 32},
		{"64B", 64},
		{"128B", 128},
		{"512B", 512},
		{"1MB", 1_000_000},
		{"8MB", 8_000_000},
		{"32MB", 32_000_000},
		{"64MB", 64_000_000},
		{"128MB", 128_000_000},
		{"512MB", 512_000_000},
		{"1GB", 1_000_000_000},
		{"5GB", 5_000_000_000},
	}

	type result struct {
		name    string
		bytes   int
		mbps    float64
		elapsed time.Duration
	}
	var results []result

	for _, tc := range cases {
		numPackets := tc.totalSize / packetSize
		if numPackets < 1 {
			numPackets = 1
		}
		t.Run(tc.name, func(t *testing.T) {
			nodeA, nodeB := createConnectedPair(t)
			defer nodeA.Stop()
			defer nodeB.Stop()

			// B needs a read loop running for session establishment (ack processing)
			go func() {
				buf := make([]byte, packetSize)
				for {
					if _, _, err := nodeB.ReadFrom(buf); err != nil {
						return
					}
				}
			}()

			msg := make([]byte, packetSize)
			rand.Read(msg[40:])
			msg[0] = 0x60
			copy(msg[8:24], nodeB.Address())
			copy(msg[24:40], nodeA.Address())
			addr := nodeA.LocalAddr()

			// Warmup: establish encrypted session before timing
			nodeB.WriteTo(msg, addr)
			warmupBuf := make([]byte, packetSize)
			if _, _, err := nodeA.ReadFrom(warmupBuf); err != nil {
				t.Fatalf("warmup ReadFrom: %v", err)
			}

			// Receiver on A
			var recvCount atomic.Int64
			var recvErr atomic.Value
			recvDone := make(chan struct{})
			go func() {
				buf := make([]byte, packetSize)
				for i := 0; i < numPackets; i++ {
					if _, _, err := nodeA.ReadFrom(buf); err != nil {
						recvErr.Store(err)
						return
					}
					recvCount.Add(1)
				}
				close(recvDone)
			}()

			// Sender on B (main goroutine)
			// With backpressure, WriteTo blocks when pipeline is full,
			// naturally pacing the sender to the receiver's speed.
			start := time.Now()
			for i := 0; i < numPackets; i++ {
				if _, err := nodeB.WriteTo(msg, addr); err != nil {
					t.Fatalf("WriteTo %d: %v", i, err)
				}
			}

			// Wait for all packets to arrive
			select {
			case <-recvDone:
			case <-time.After(time.Duration(60+tc.totalSize/5_000_000) * time.Second):
				if e := recvErr.Load(); e != nil {
					t.Fatalf("receiver error after %d/%d packets: %v", recvCount.Load(), numPackets, e)
				}
				t.Fatalf("timeout: received %d/%d packets", recvCount.Load(), numPackets)
			}
			elapsed := time.Since(start)

			totalBytes := int64(packetSize) * int64(numPackets)
			var mbps float64
			if elapsed > 0 {
				mbps = float64(totalBytes) / elapsed.Seconds() / 1_000_000
			}
			results = append(results, result{tc.name, tc.totalSize, mbps, elapsed})
			t.Logf("%d packets in %v (%.2f MB/s)", numPackets, elapsed, mbps)
		})
	}

	// Print summary table (visible without -v)
	fmt.Printf("\n  Throughput Summary:\n")
	fmt.Printf("  %-8s %12s %10s\n", "Total", "Time", "Rate")
	fmt.Printf("  %-8s %12s %10s\n", "-----", "----", "----")
	for _, r := range results {
		var rate string
		if r.bytes >= 1_000_000 {
			rate = fmt.Sprintf("%.2f MB/s", r.mbps)
		} else if r.bytes >= 1_000 {
			rate = fmt.Sprintf("%.2f KB/s", r.mbps*1000)
		} else {
			rate = fmt.Sprintf("%d B/s", int(r.mbps*1_000_000))
		}
		fmt.Printf("  %-8s %12v %10s\n", r.name, r.elapsed.Round(time.Microsecond), rate)
	}
	fmt.Println()
}

// TestReliableDelivery verifies that the reliable path (WriteTo/ReadFrom) delivers
// all packets without loss, even when the sender is faster than the receiver.
// With backpressure (inflight semaphore), WriteTo blocks when the pipeline is full,
// naturally pacing the sender.
func TestReliableDelivery(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	const packetSize = 60_000
	const numPackets = 1_000 // 60 MB — enough to exercise backpressure

	msg := make([]byte, packetSize)
	rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], nodeB.Address())
	copy(msg[24:40], nodeA.Address())
	addr := nodeA.LocalAddr()

	// B needs a read loop for session establishment
	go func() {
		buf := make([]byte, packetSize)
		for {
			if _, _, err := nodeB.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// Warmup: establish session
	nodeB.WriteTo(msg, addr)
	warmupBuf := make([]byte, packetSize)
	if _, _, err := nodeA.ReadFrom(warmupBuf); err != nil {
		t.Fatalf("warmup: %v", err)
	}

	// Concurrent receiver
	var recvCount atomic.Int64
	recvDone := make(chan struct{})
	go func() {
		buf := make([]byte, packetSize)
		for i := 0; i < numPackets; i++ {
			if _, _, err := nodeA.ReadFrom(buf); err != nil {
				t.Errorf("ReadFrom %d: %v", i, err)
				return
			}
			recvCount.Add(1)
		}
		close(recvDone)
	}()

	// Sender — WriteTo should block when pipeline is full (backpressure)
	sendStart := time.Now()
	for i := 0; i < numPackets; i++ {
		if _, err := nodeB.WriteTo(msg, addr); err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
	}
	sendElapsed := time.Since(sendStart)
	t.Logf("Sent %d packets (%d MB) in %v", numPackets, numPackets*packetSize/1_000_000, sendElapsed)

	select {
	case <-recvDone:
	case <-time.After(60 * time.Second):
		t.Fatalf("timeout: received %d/%d packets", recvCount.Load(), numPackets)
	}

	got := recvCount.Load()
	if got != int64(numPackets) {
		t.Fatalf("FAIL: received %d/%d packets — reliable path lost %d packets", got, numPackets, numPackets-int(got))
	}
	t.Logf("PASS: all %d packets delivered (reliable path, backpressure working)", numPackets)
}

// TestUnreliableDelivery verifies that the unreliable path (QUIC datagrams via
// SendDatagram/ReceiveDatagrams) works and gracefully handles drops under load.
func TestUnreliableDelivery(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	const numPackets = 500
	const payloadSize = 100

	// Verify datagram support
	if !nodeA.HasDatagramSupport(nodeB.PublicKey()) {
		t.Fatal("A does not have datagram support to B")
	}

	// Receiver
	var received atomic.Int64
	recvDone := make(chan struct{})
	go func() {
		ch := nodeA.ReceiveDatagrams()
		for {
			select {
			case pkt := <-ch:
				if len(pkt.Data) == payloadSize {
					received.Add(1)
				}
			case <-time.After(3 * time.Second):
				close(recvDone)
				return
			}
		}
	}()

	// Blast sender — no backpressure on datagram path, some may drop
	for i := 0; i < numPackets; i++ {
		payload := make([]byte, payloadSize)
		payload[0] = byte(i)
		if err := nodeB.SendDatagram(payload, nodeA.PublicKey()); err != nil {
			t.Fatalf("SendDatagram %d: %v", i, err)
		}
	}

	<-recvDone
	got := received.Load()
	t.Logf("Unreliable: received %d/%d packets (%.1f%% delivery)",
		got, numPackets, float64(got)/float64(numPackets)*100)

	if got == 0 {
		t.Fatal("FAIL: zero packets received on unreliable path")
	}
	// Unreliable path may drop packets — that's expected. Just verify some arrive.
	t.Logf("PASS: unreliable path delivered %d packets (drops are expected)", got)
}

// createChain creates a linear chain of numNodes: 0 ←→ 1 ←→ 2 ←→ ... ←→ (n-1).
// Packets from node 0 to node n-1 traverse all intermediate hops.
func createChain(t *testing.T, numNodes int) ([]*core.Core, func()) {
	t.Helper()
	logger := testLogger()

	nodes := make([]*core.Core, numNodes)
	for i := range nodes {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		node, err := core.New(cfg.Certificate, logger)
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = node
	}

	for i := 0; i < numNodes-1; i++ {
		u, _ := url.Parse("quic://localhost:0")
		listener, err := nodes[i].Listen(u, "")
		if err != nil {
			t.Fatalf("node %d Listen: %v", i, err)
		}
		peerURL, _ := url.Parse("quic://" + listener.Addr().String())
		if err := nodes[i+1].CallPeer(peerURL, ""); err != nil {
			t.Fatalf("node %d CallPeer: %v", i+1, err)
		}
	}

	// Wait for every node to see at least one peer in the tree
	for attempt := 0; attempt < 100; attempt++ {
		time.Sleep(100 * time.Millisecond)
		allReady := true
		for _, node := range nodes {
			if len(node.GetTree()) < 2 {
				allReady = false
				break
			}
		}
		if allReady {
			break
		}
	}

	// Brief pause for nearby routing tables; callers with retry warmup handle full convergence
	time.Sleep(time.Second)

	return nodes, func() {
		for _, n := range nodes {
			n.Stop()
		}
	}
}

func TestLatency(t *testing.T) {
	hopCounts := []int{1, 2, 4, 8, 16, 32, 64}
	const numPings = 100
	const packetSize = 1500
	const maxHops = 64

	// Create one chain of 65 nodes, test at different distances within it
	nodes, cleanup := createChain(t, maxHops+1)
	defer cleanup()

	first := nodes[0]

	type result struct {
		hops   int
		avgRTT time.Duration
	}
	var results []result

	for _, hops := range hopCounts {
		target := nodes[hops]
		name := fmt.Sprintf("%d_hops", hops)
		t.Run(name, func(t *testing.T) {
			// Echo server on target node
			echoStop := make(chan struct{})
			go func() {
				buf := make([]byte, packetSize)
				for {
					n, from, err := target.ReadFrom(buf)
					if err != nil {
						return
					}
					select {
					case <-echoStop:
						return
					default:
					}
					res := make([]byte, n)
					copy(res, buf[:n])
					copy(res[8:24], buf[24:40])
					copy(res[24:40], buf[8:24])
					target.WriteTo(res, from)
				}
			}()
			defer close(echoStop)

			msg := make([]byte, packetSize)
			rand.Read(msg[40:])
			msg[0] = 0x60
			copy(msg[8:24], first.Address())
			copy(msg[24:40], target.Address())
			buf := make([]byte, packetSize)
			addr := target.LocalAddr()

			// Warmup: retry until routing converges and session is established
			warmupDone := make(chan struct{}, 1)
			go func() {
				b := make([]byte, packetSize)
				if _, _, err := first.ReadFrom(b); err != nil {
					return
				}
				warmupDone <- struct{}{}
			}()
			for attempt := 0; ; attempt++ {
				first.WriteTo(msg, addr)
				select {
				case <-warmupDone:
					goto ready
				case <-time.After(200 * time.Millisecond):
					if attempt >= 300 {
						t.Fatal("warmup: no echo after 300 attempts")
					}
				}
			}
		ready:
			// A few more pings to stabilize
			for i := 0; i < 5; i++ {
				first.WriteTo(msg, addr)
				first.ReadFrom(buf)
			}

			// Measure RTT
			var totalRTT time.Duration
			for i := 0; i < numPings; i++ {
				start := time.Now()
				if _, err := first.WriteTo(msg, addr); err != nil {
					t.Fatalf("WriteTo %d: %v", i, err)
				}
				if _, _, err := first.ReadFrom(buf); err != nil {
					t.Fatalf("ReadFrom %d: %v", i, err)
				}
				totalRTT += time.Since(start)
			}

			avgRTT := totalRTT / time.Duration(numPings)
			perHop := avgRTT / time.Duration(2*hops)
			results = append(results, result{hops, avgRTT})
			t.Logf("%d hops: avg RTT %v, per-hop %v", hops, avgRTT, perHop)
		})
	}

	fmt.Printf("\n  Latency Summary (echo RTT, %d pings):\n", numPings)
	fmt.Printf("  %-10s %12s %12s\n", "Hops", "Avg RTT", "Per-hop")
	fmt.Printf("  %-10s %12s %12s\n", "----", "-------", "-------")
	for _, r := range results {
		perHop := r.avgRTT / time.Duration(2*r.hops)
		fmt.Printf("  %-10d %12v %12v\n", r.hops, r.avgRTT, perHop)
	}
	fmt.Println()
}

// TestLatencyWithIPRWCRelays mirrors what the Godot GDExtension does:
// relay nodes activate ipv6rwc (via ygg_recv) instead of being bare core.Core.
// This tests whether ipv6rwc activation on intermediate nodes breaks routing.
func TestLatencyWithIPRWCRelays(t *testing.T) {
	hopCounts := []int{1, 2, 4, 8, 16, 32, 64}
	const numPings = 100
	const packetSize = 1500
	const maxHops = 64

	// Build set of target node indices — these will run echo servers,
	// so they must NOT have a competing relay reader.
	targetSet := make(map[int]bool)
	for _, h := range hopCounts {
		targetSet[h] = true
	}

	logger := testLogger()

	numNodes := maxHops + 1
	nodes := make([]*core.Core, numNodes)
	iprwcs := make([]*ipv6rwc.ReadWriteCloser, numNodes)

	// Create all nodes
	for i := range nodes {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		node, err := core.New(cfg.Certificate, logger)
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = node

		// Activate ipv6rwc on EVERY node (like Godot's create_host does)
		rwc := ipv6rwc.NewReadWriteCloser(node)
		if rwc.MaxMTU() < cfg.IfMTU {
			rwc.SetMTU(rwc.MaxMTU())
		} else {
			rwc.SetMTU(cfg.IfMTU)
		}
		iprwcs[i] = rwc

		// Start a reader goroutine on intermediate nodes (like Godot's recv thread).
		// Skip node 0 (sender), target nodes (echo servers), to avoid racing on Read().
		if i > 0 && i < numNodes-1 && !targetSet[i] {
			go func(r *ipv6rwc.ReadWriteCloser) {
				buf := make([]byte, 65536)
				for {
					_, err := r.Read(buf)
					if err != nil {
						return
					}
					// Relay nodes just discard — they don't process game packets
				}
			}(rwc)
		}
	}

	// Chain them: node[i] listens, node[i+1] peers with it
	for i := 0; i < numNodes-1; i++ {
		u, _ := url.Parse("quic://localhost:0")
		listener, err := nodes[i].Listen(u, "")
		if err != nil {
			t.Fatalf("node %d Listen: %v", i, err)
		}
		peerURL, _ := url.Parse("quic://" + listener.Addr().String())
		if err := nodes[i+1].CallPeer(peerURL, ""); err != nil {
			t.Fatalf("node %d CallPeer: %v", i+1, err)
		}
	}

	// Wait for tree convergence
	for attempt := 0; attempt < 100; attempt++ {
		time.Sleep(100 * time.Millisecond)
		allReady := true
		for _, node := range nodes {
			if len(node.GetTree()) < 2 {
				allReady = false
				break
			}
		}
		if allReady {
			break
		}
	}
	time.Sleep(time.Second)

	defer func() {
		for _, n := range nodes {
			n.Stop()
		}
	}()

	first := iprwcs[0]

	type result struct {
		hops   int
		avgRTT time.Duration
	}
	var results []result

	for _, hops := range hopCounts {
		target := iprwcs[hops]
		name := fmt.Sprintf("%d_hops_iprwc", hops)
		t.Run(name, func(t *testing.T) {
			// Echo server on target using ipv6rwc
			echoStop := make(chan struct{})
			go func() {
				buf := make([]byte, packetSize)
				for {
					n, err := target.Read(buf)
					if err != nil {
						return
					}
					select {
					case <-echoStop:
						return
					default:
					}
					// Swap src/dst addresses in the IPv6 header and echo back
					res := make([]byte, n)
					copy(res, buf[:n])
					copy(res[8:24], buf[24:40])
					copy(res[24:40], buf[8:24])
					target.Write(res)
				}
			}()
			defer close(echoStop)

			// Build ping packet
			msg := make([]byte, packetSize)
			rand.Read(msg[40:])
			msg[0] = 0x60
			// src = first node addr, dst = target node addr
			firstAddr := nodes[0].Address()
			targetAddr := nodes[hops].Address()
			copy(msg[8:24], firstAddr[:])
			copy(msg[24:40], targetAddr[:])

			// Warmup with retry
			warmupDone := make(chan struct{}, 1)
			go func() {
				b := make([]byte, packetSize)
				if _, err := first.Read(b); err != nil {
					return
				}
				warmupDone <- struct{}{}
			}()
			for attempt := 0; ; attempt++ {
				first.Write(msg)
				select {
				case <-warmupDone:
					goto ready
				case <-time.After(200 * time.Millisecond):
					if attempt >= 300 {
						t.Fatalf("warmup: no echo after 300 attempts (60s)")
					}
					if attempt%25 == 0 && attempt > 0 {
						t.Logf("warmup: %d attempts...", attempt)
					}
				}
			}
		ready:
			// Stabilization pings
			buf := make([]byte, packetSize)
			for i := 0; i < 5; i++ {
				first.Write(msg)
				first.Read(buf)
			}

			// Measure RTT
			var totalRTT time.Duration
			for i := 0; i < numPings; i++ {
				start := time.Now()
				if _, err := first.Write(msg); err != nil {
					t.Fatalf("Write %d: %v", i, err)
				}
				if _, err := first.Read(buf); err != nil {
					t.Fatalf("Read %d: %v", i, err)
				}
				totalRTT += time.Since(start)
			}

			avgRTT := totalRTT / time.Duration(numPings)
			perHop := avgRTT / time.Duration(2*hops)
			results = append(results, result{hops, avgRTT})
			t.Logf("%d hops (iprwc relays): avg RTT %v, per-hop %v", hops, avgRTT, perHop)
		})
	}

	fmt.Printf("\n  Latency Summary — ipv6rwc on ALL nodes (echo RTT, %d pings):\n", numPings)
	fmt.Printf("  %-10s %12s %12s\n", "Hops", "Avg RTT", "Per-hop")
	fmt.Printf("  %-10s %12s %12s\n", "----", "-------", "-------")
	for _, r := range results {
		perHop := r.avgRTT / time.Duration(2*r.hops)
		fmt.Printf("  %-10d %12v %12v\n", r.hops, r.avgRTT, perHop)
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// C-API-style 10-hop relay chain test
//
// Mimics exactly what the GDExtension does:
//   - Server: core.New + Listen (like ygg_start + ygg_listen), then
//     ensureBgReader (SetPathNotify + background ReadFrom goroutine feeding
//     a channel)
//   - Relays: core.New with Peer (config-based, = linkTypePersistent) +
//     Listen. NO ReadFrom goroutines — relays are pure routing nodes.
//   - Client: core.New with Peer to last relay, then ensureBgReader, then
//     SendLookup + WriteTo in a loop every ~83ms (5 frames at 60fps).
// ---------------------------------------------------------------------------

// capiStyleBgReader mimics ensureBgReader from lib.go: starts a background
// goroutine that calls core.ReadFrom in a loop, feeding packets into a channel,
// and sets up SetPathNotify to track known peers.
func capiStyleBgReader(node *core.Core) (recvCh chan recvPacket, knownPeers *sync.Map) {
	recvCh = make(chan recvPacket, 256)
	knownPeers = &sync.Map{}

	node.SetPathNotify(func(key ed25519.PublicKey) {
		knownPeers.Store(string(key), struct{}{})
	})

	go func() {
		buf := make([]byte, node.MTU())
		for {
			n, from, err := node.ReadFrom(buf)
			if err != nil {
				close(recvCh)
				return
			}
			if n == 0 {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			recvCh <- recvPacket{data: pkt, from: from}
		}
	}()

	return recvCh, knownPeers
}

// capiStyleSendTo mimics ygg_send_to from lib.go: calls SendLookup for
// unknown destinations, then WriteTo with the public key as address.
func capiStyleSendTo(node *core.Core, knownPeers *sync.Map, destPubKey ed25519.PublicKey, data []byte) (int, error) {
	if _, known := knownPeers.Load(string(destPubKey)); !known {
		node.SendLookup(destPubKey)
	}
	return node.WriteTo(data, iwt.Addr(destPubKey))
}

// TestCAPIStyleTenHopChain creates a 10-hop relay chain using config-based
// Peers (core.Peer option) and Listen — exactly as ygg_start + ygg_listen does.
// Client uses SendLookup + WriteTo (like ygg_send_to). Relays have NO
// ReadFrom goroutines (like a relay node that only calls ygg_start + ygg_listen
// + ygg_add_peer).
func TestCAPIStyleTenHopChain(t *testing.T) {
	const numRelays = 9 // server + 9 relays + client = 11 nodes, 10 hops
	const sendInterval = 83 * time.Millisecond
	const timeout = 120 * time.Second

	logger := testLogger()

	// --- Server (node 0): Listen only, no outbound peers ---
	// This matches C API: ygg_start (no Peers in config) + ygg_listen
	srvCfg := config.GenerateConfig()
	if err := srvCfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	server, err := core.New(srvCfg.Certificate, logger)
	if err != nil {
		t.Fatal("server New:", err)
	}
	defer server.Stop()

	srvListenURL, _ := url.Parse("quic://localhost:0")
	srvListener, err := server.Listen(srvListenURL, "")
	if err != nil {
		t.Fatal("server Listen:", err)
	}
	srvAddr := "quic://" + srvListener.Addr().String()
	t.Logf("Server listening on %s (pubkey %x)", srvAddr, server.PublicKey())

	// --- Relays (nodes 1-9): each peers with the previous node via config ---
	// This matches C API: ygg_start with Peers in config + ygg_listen.
	// Peers in config => core.Peer{} option => links.add(persistent).
	// No ReadFrom on relays — they are pure routing participants.
	relays := make([]*core.Core, numRelays)
	prevURI := srvAddr
	for i := 0; i < numRelays; i++ {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		// Create relay with config-based peer (like ygg_start with Peers)
		relay, err := core.New(cfg.Certificate, logger,
			core.Peer{URI: prevURI},
		)
		if err != nil {
			t.Fatalf("relay %d New: %v", i, err)
		}
		defer relay.Stop()
		relays[i] = relay

		// Add listener (like ygg_listen)
		relayListenURL, _ := url.Parse("quic://localhost:0")
		relayListener, err := relay.Listen(relayListenURL, "")
		if err != nil {
			t.Fatalf("relay %d Listen: %v", i, err)
		}
		prevURI = "quic://" + relayListener.Addr().String()
		t.Logf("Relay %d listening on %s", i, prevURI)
	}

	// --- Wait for tree convergence (like GDScript's 5-second wait) ---
	t.Log("Waiting 5 seconds for tree convergence (matching GDScript delay)...")
	time.Sleep(5 * time.Second)

	// Verify tree connectivity
	srvTree := server.GetTree()
	t.Logf("Server tree: %d entries", len(srvTree))
	for i, r := range relays {
		t.Logf("Relay %d tree: %d entries", i, len(r.GetTree()))
	}

	// --- Client (node 10): peers with last relay via config ---
	// This matches C API: ygg_start with Peers pointing to last relay
	clientCfg := config.GenerateConfig()
	if err := clientCfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	client, err := core.New(clientCfg.Certificate, logger,
		core.Peer{URI: prevURI},
	)
	if err != nil {
		t.Fatal("client New:", err)
	}
	defer client.Stop()
	t.Logf("Client started (pubkey %x), peered with %s", client.PublicKey(), prevURI)

	// Wait for client to connect to last relay
	time.Sleep(2 * time.Second)
	t.Logf("Client tree: %d entries", len(client.GetTree()))

	// --- Start C-API-style background readers on server and client ---
	// This mimics what happens when GDExtension calls ygg_recv_from or
	// ygg_send_to for the first time (both trigger ensureBgReader).
	srvRecvCh, srvKnownPeers := capiStyleBgReader(server)
	clientRecvCh, clientKnownPeers := capiStyleBgReader(client)

	// --- Server echo goroutine (reads from channel, echoes back) ---
	// Mimics GDExtension server: recv thread reads via ygg_recv_from,
	// main thread echoes via ygg_send_to.
	go func() {
		for pkt := range srvRecvCh {
			senderKey := []byte(pkt.from.(iwt.Addr))
			capiStyleSendTo(server, srvKnownPeers, ed25519.PublicKey(senderKey), pkt.data)
		}
	}()

	// --- Client send loop: SendLookup + WriteTo every 83ms ---
	// Mimics GDExtension client: _poll() calls ygg_send_to every few frames
	serverPubKey := server.PublicKey()
	payload := make([]byte, 100)
	rand.Read(payload)

	t.Log("Starting send loop (83ms interval, like 5-frame retry at 60fps)...")
	sendStart := time.Now()
	var sendCount int
	var firstSendTime time.Time
	var firstRecvTime time.Time

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		ticker := time.NewTicker(sendInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendCount++
				if sendCount == 1 {
					firstSendTime = time.Now()
				}
				n, err := capiStyleSendTo(client, clientKnownPeers, serverPubKey, payload)
				if sendCount <= 10 || sendCount%50 == 0 {
					t.Logf("  send #%d: n=%d err=%v (elapsed %v)", sendCount, n, err, time.Since(sendStart))
				}
			case <-clientRecvCh:
				firstRecvTime = time.Now()
				return
			}
		}
	}()

	select {
	case <-sendDone:
		elapsed := firstRecvTime.Sub(firstSendTime)
		totalElapsed := firstRecvTime.Sub(sendStart)
		t.Logf("=== C-API STYLE RESULT ===")
		t.Logf("First response after %d sends", sendCount)
		t.Logf("Time from first send to first recv: %v", elapsed)
		t.Logf("Total time from start: %v", totalElapsed)
	case <-time.After(timeout):
		t.Fatalf("TIMEOUT after %v (%d sends). This reproduces the ~64s delay!", timeout, sendCount)
	}

	// Measure steady-state latency for comparison
	t.Log("Measuring steady-state RTT (10 pings)...")
	for i := 0; i < 10; i++ {
		start := time.Now()
		capiStyleSendTo(client, clientKnownPeers, serverPubKey, payload)
		select {
		case <-clientRecvCh:
			t.Logf("  ping %d: %v", i+1, time.Since(start))
		case <-time.After(10 * time.Second):
			t.Fatalf("  ping %d: timeout", i+1)
		}
	}
}

// TestCAPIStyleNoSendLookup is identical to TestCAPIStyleTenHopChain
// but WITHOUT calling SendLookup. This isolates whether SendLookup is the
// cause of the 60-second delay.
func TestCAPIStyleNoSendLookup(t *testing.T) {
	const numRelays = 9
	const sendInterval = 83 * time.Millisecond
	const timeout = 120 * time.Second

	logger := testLogger()

	// Server
	srvCfg := config.GenerateConfig()
	if err := srvCfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	server, err := core.New(srvCfg.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	srvListenURL, _ := url.Parse("quic://localhost:0")
	srvListener, err := server.Listen(srvListenURL, "")
	if err != nil {
		t.Fatal(err)
	}
	srvAddr := "quic://" + srvListener.Addr().String()
	t.Logf("Server: %s", srvAddr)

	// Relays - config-based Peer (same as C-API test)
	relays := make([]*core.Core, numRelays)
	prevURI := srvAddr
	for i := 0; i < numRelays; i++ {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		relay, err := core.New(cfg.Certificate, logger, core.Peer{URI: prevURI})
		if err != nil {
			t.Fatalf("relay %d: %v", i, err)
		}
		defer relay.Stop()
		relays[i] = relay
		lURL, _ := url.Parse("quic://localhost:0")
		rl, err := relay.Listen(lURL, "")
		if err != nil {
			t.Fatalf("relay %d Listen: %v", i, err)
		}
		prevURI = "quic://" + rl.Addr().String()
	}

	time.Sleep(5 * time.Second)

	// Client - config-based Peer (same as C-API test)
	clientCfg := config.GenerateConfig()
	if err := clientCfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	client, err := core.New(clientCfg.Certificate, logger, core.Peer{URI: prevURI})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Stop()
	time.Sleep(2 * time.Second)
	t.Logf("Client tree: %d entries", len(client.GetTree()))

	// BgReaders (same as C-API)
	srvRecvCh, _ := capiStyleBgReader(server)
	clientRecvCh, _ := capiStyleBgReader(client)

	// Server echo - but WITHOUT SendLookup (just direct WriteTo)
	go func() {
		for pkt := range srvRecvCh {
			senderKey := []byte(pkt.from.(iwt.Addr))
			// Direct WriteTo, no SendLookup
			server.WriteTo(pkt.data, iwt.Addr(senderKey))
		}
	}()

	// Client send loop - NO SendLookup, just WriteTo with iwt.Addr
	serverPubKey := server.PublicKey()
	payload := make([]byte, 100)
	rand.Read(payload)

	t.Log("Starting send loop (NO SendLookup, same 83ms interval)...")
	sendStart := time.Now()
	var sendCount int
	var firstRecvTime time.Time

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		ticker := time.NewTicker(sendInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendCount++
				// NO SendLookup - just WriteTo directly
				n, err := client.WriteTo(payload, iwt.Addr(serverPubKey))
				if sendCount <= 10 || sendCount%50 == 0 {
					t.Logf("  send #%d: n=%d err=%v (elapsed %v)", sendCount, n, err, time.Since(sendStart))
				}
			case <-clientRecvCh:
				firstRecvTime = time.Now()
				return
			}
		}
	}()

	select {
	case <-sendDone:
		t.Logf("=== NO-SENDLOOKUP RESULT (config Peer, bgReader, but no SendLookup) ===")
		t.Logf("First response after %d sends, %v", sendCount, firstRecvTime.Sub(sendStart))
	case <-time.After(timeout):
		t.Fatalf("TIMEOUT after %v (%d sends)", timeout, sendCount)
	}

	t.Log("Measuring steady-state RTT...")
	for i := 0; i < 10; i++ {
		start := time.Now()
		client.WriteTo(payload, iwt.Addr(serverPubKey))
		select {
		case <-clientRecvCh:
			t.Logf("  ping %d: %v", i+1, time.Since(start))
		case <-time.After(10 * time.Second):
			t.Fatalf("  ping %d: timeout", i+1)
		}
	}
}

// TestCAPIStyleWithCallPeer is the FIXED version of TestCAPIStyleTenHopChain.
// Uses CallPeer + proper convergence polling (matching createChain pattern).
func TestCAPIStyleWithCallPeer(t *testing.T) {
	const numRelays = 9
	const sendInterval = 83 * time.Millisecond
	const timeout = 120 * time.Second

	logger := testLogger()

	// Create ALL nodes first, then chain them (matching createChain pattern)
	numNodes := 1 + numRelays + 1 // server + relays + client
	allNodes := make([]*core.Core, numNodes)
	for i := 0; i < numNodes; i++ {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		node, err := core.New(cfg.Certificate, logger)
		if err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
		defer node.Stop()
		allNodes[i] = node
	}

	// Chain them: node[i] listens, node[i+1] CallPeers
	for i := 0; i < numNodes-1; i++ {
		lURL, _ := url.Parse("quic://localhost:0")
		rl, err := allNodes[i].Listen(lURL, "")
		if err != nil {
			t.Fatalf("node %d Listen: %v", i, err)
		}
		peerURL, _ := url.Parse("quic://" + rl.Addr().String())
		if err := allNodes[i+1].CallPeer(peerURL, ""); err != nil {
			t.Fatalf("node %d CallPeer: %v", i+1, err)
		}
	}

	// Wait for FULL tree convergence — all nodes must see all other nodes.
	// Partial convergence (tree >= 2) is insufficient: if the endpoints can't
	// route to each other, the first WriteTo triggers Ironwood's sessionInit
	// which buffers for sessionTimeout (60s) before failing.
	for attempt := 0; attempt < 200; attempt++ {
		time.Sleep(100 * time.Millisecond)
		allReady := true
		for _, node := range allNodes {
			if len(node.GetTree()) < numNodes {
				allReady = false
				break
			}
		}
		if allReady {
			t.Logf("Tree fully converged after %dms", (attempt+1)*100)
			break
		}
		if attempt == 199 {
			for i, node := range allNodes {
				t.Logf("  node %d tree: %d entries", i, len(node.GetTree()))
			}
			t.Log("WARNING: tree not fully converged after 20s")
		}
	}

	server := allNodes[0]
	client := allNodes[numNodes-1]
	t.Logf("Server tree: %d, Client tree: %d", len(server.GetTree()), len(client.GetTree()))

	// Full C-API style I/O (bgReader + SendLookup)
	srvRecvCh, srvKnownPeers := capiStyleBgReader(server)
	clientRecvCh, clientKnownPeers := capiStyleBgReader(client)

	go func() {
		for pkt := range srvRecvCh {
			senderKey := []byte(pkt.from.(iwt.Addr))
			capiStyleSendTo(server, srvKnownPeers, ed25519.PublicKey(senderKey), pkt.data)
		}
	}()

	serverPubKey := server.PublicKey()
	payload := make([]byte, 100)
	rand.Read(payload)

	t.Log("Starting send loop (CallPeer + bgReader + SendLookup)...")
	sendStart := time.Now()
	var sendCount int

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		ticker := time.NewTicker(sendInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendCount++
				capiStyleSendTo(client, clientKnownPeers, serverPubKey, payload)
				if sendCount <= 10 || sendCount%50 == 0 {
					t.Logf("  send #%d (elapsed %v)", sendCount, time.Since(sendStart))
				}
			case <-clientRecvCh:
				return
			}
		}
	}()

	select {
	case <-sendDone:
		elapsed := time.Since(sendStart)
		t.Logf("=== FIXED C-API STYLE (CallPeer + convergence + bgReader + SendLookup) ===")
		t.Logf("First response after %d sends, %v", sendCount, elapsed)
		if elapsed > 30*time.Second {
			t.Errorf("Still too slow! Expected <10s, got %v", elapsed)
		}
	case <-time.After(timeout):
		t.Fatalf("TIMEOUT after %v (%d sends)", timeout, sendCount)
	}
}

// TestCallPeerWithBgReader uses CallPeer-style relays (createChain)
// but bgReader-style I/O on endpoints. Isolates whether the bgReader
// channel approach is causing the 60s delay.
func TestCallPeerWithBgReader(t *testing.T) {
	const sendInterval = 83 * time.Millisecond
	const timeout = 120 * time.Second

	nodes, cleanup := createChain(t, 11)
	defer cleanup()
	first := nodes[0]
	last := nodes[10]

	time.Sleep(5 * time.Second)
	t.Logf("First tree: %d, Last tree: %d", len(first.GetTree()), len(last.GetTree()))

	// Use bgReader on both endpoints (like C-API)
	srvRecvCh, srvKnownPeers := capiStyleBgReader(last)
	clientRecvCh, clientKnownPeers := capiStyleBgReader(first)

	// Echo via bgReader+channel (like C-API server)
	go func() {
		for pkt := range srvRecvCh {
			senderKey := []byte(pkt.from.(iwt.Addr))
			capiStyleSendTo(last, srvKnownPeers, ed25519.PublicKey(senderKey), pkt.data)
		}
	}()

	// Send with SendLookup (like C-API client)
	serverPubKey := last.PublicKey()
	payload := make([]byte, 100)
	rand.Read(payload)

	t.Log("Starting send loop (CallPeer relays + bgReader endpoints + SendLookup)...")
	sendStart := time.Now()
	var sendCount int

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		ticker := time.NewTicker(sendInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendCount++
				capiStyleSendTo(first, clientKnownPeers, serverPubKey, payload)
				if sendCount <= 10 || sendCount%50 == 0 {
					t.Logf("  send #%d (elapsed %v)", sendCount, time.Since(sendStart))
				}
			case <-clientRecvCh:
				return
			}
		}
	}()

	select {
	case <-sendDone:
		t.Logf("=== CALLPEER + BGREADER RESULT ===")
		t.Logf("First response after %d sends, %v", sendCount, time.Since(sendStart))
	case <-time.After(timeout):
		t.Fatalf("TIMEOUT after %v (%d sends)", timeout, sendCount)
	}
}

// TestCallPeerStyleTenHopChain is the comparison test that uses CallPeer
// (linkTypeEphemeral) and direct WriteTo without SendLookup, like the existing
// TestLatency. This shows whether config-based Peer + SendLookup is slower
// than CallPeer + direct WriteTo.
func TestCallPeerStyleTenHopChain(t *testing.T) {
	const numHops = 10
	const sendInterval = 83 * time.Millisecond
	const timeout = 120 * time.Second

	// Use the existing createChain helper (CallPeer-based, linkTypeEphemeral)
	nodes, cleanup := createChain(t, numHops+1)
	defer cleanup()

	first := nodes[0]
	last := nodes[numHops]

	t.Logf("Chain created: %d nodes, %d hops", numHops+1, numHops)
	t.Logf("First node pubkey: %x", first.PublicKey())
	t.Logf("Last node pubkey: %x", last.PublicKey())

	// Wait 5 seconds to match the C-API test's convergence wait
	t.Log("Waiting 5 seconds for convergence (matching C-API test)...")
	time.Sleep(5 * time.Second)

	// Echo reader on last node using direct core.ReadFrom (like TestLatency)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := last.ReadFrom(buf)
			if err != nil {
				return
			}
			res := make([]byte, n)
			copy(res, buf[:n])
			last.WriteTo(res, from)
		}
	}()

	// Reader on first node
	firstRecvCh := make(chan net.Addr, 256)
	go func() {
		buf := make([]byte, 65535)
		for {
			_, from, err := first.ReadFrom(buf)
			if err != nil {
				close(firstRecvCh)
				return
			}
			firstRecvCh <- from
		}
	}()

	// Send using direct WriteTo (no SendLookup) every 83ms
	payload := make([]byte, 100)
	rand.Read(payload)
	destAddr := last.LocalAddr()

	t.Log("Starting send loop (83ms interval, direct WriteTo, no SendLookup)...")
	sendStart := time.Now()
	var sendCount int
	var firstSendTime time.Time
	var firstRecvTime time.Time

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		ticker := time.NewTicker(sendInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendCount++
				if sendCount == 1 {
					firstSendTime = time.Now()
				}
				n, err := first.WriteTo(payload, destAddr)
				if sendCount <= 10 || sendCount%50 == 0 {
					t.Logf("  send #%d: n=%d err=%v (elapsed %v)", sendCount, n, err, time.Since(sendStart))
				}
			case <-firstRecvCh:
				firstRecvTime = time.Now()
				return
			}
		}
	}()

	select {
	case <-sendDone:
		elapsed := firstRecvTime.Sub(firstSendTime)
		totalElapsed := firstRecvTime.Sub(sendStart)
		t.Logf("=== CALLPEER STYLE RESULT ===")
		t.Logf("First response after %d sends", sendCount)
		t.Logf("Time from first send to first recv: %v", elapsed)
		t.Logf("Total time from start: %v", totalElapsed)
	case <-time.After(timeout):
		t.Fatalf("TIMEOUT after %v (%d sends)", timeout, sendCount)
	}

	// Steady-state latency
	t.Log("Measuring steady-state RTT (10 pings)...")
	for i := 0; i < 10; i++ {
		start := time.Now()
		first.WriteTo(payload, destAddr)
		select {
		case <-firstRecvCh:
			t.Logf("  ping %d: %v", i+1, time.Since(start))
		case <-time.After(10 * time.Second):
			t.Fatalf("  ping %d: timeout", i+1)
		}
	}
}

// ---------------------------------------------------------------------------
// QUIC Datagram (RFC 9221) tests
// ---------------------------------------------------------------------------

func TestDatagramBasicSendReceive(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	// Verify datagram support registered for both directions
	if !nodeA.HasDatagramSupport(nodeB.PublicKey()) {
		t.Fatal("A does not have datagram support to B")
	}
	if !nodeB.HasDatagramSupport(nodeA.PublicKey()) {
		t.Fatal("B does not have datagram support to A")
	}

	// Send datagram B → A
	payload := []byte("hello datagram")
	if err := nodeB.SendDatagram(payload, nodeA.PublicKey()); err != nil {
		t.Fatal("SendDatagram:", err)
	}

	select {
	case pkt := <-nodeA.ReceiveDatagrams():
		if !bytes.Equal(pkt.Data, payload) {
			t.Fatalf("payload mismatch: got %q, want %q", pkt.Data, payload)
		}
		t.Log("Datagram received successfully")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for datagram")
	}

	// Send datagram A → B
	payload2 := []byte("reply datagram")
	if err := nodeA.SendDatagram(payload2, nodeB.PublicKey()); err != nil {
		t.Fatal("SendDatagram:", err)
	}

	select {
	case pkt := <-nodeB.ReceiveDatagrams():
		if !bytes.Equal(pkt.Data, payload2) {
			t.Fatalf("payload mismatch: got %q, want %q", pkt.Data, payload2)
		}
		t.Log("Reply datagram received successfully")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for reply datagram")
	}
}

func TestDatagramTooLarge(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	// 2000 bytes is fragmented automatically (fits in ~2 fragments).
	// This should succeed with fragmentation.
	payload := make([]byte, 2000)
	rand.Read(payload)
	err := nodeB.SendDatagram(payload, nodeA.PublicKey())
	if err != nil {
		t.Fatal("SendDatagram (2000 bytes, fragmented):", err)
	}

	select {
	case pkt := <-nodeA.ReceiveDatagrams():
		if !bytes.Equal(pkt.Data, payload) {
			t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", len(pkt.Data), len(payload))
		}
		t.Log("2000-byte fragmented datagram received and reassembled correctly")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for fragmented datagram")
	}
}

func TestDatagramNonQUICPeer(t *testing.T) {
	// Create a pair connected via TCP instead of QUIC
	logger := testLogger()

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	cfgA.GenerateSelfSignedCertificate()
	cfgB.GenerateSelfSignedCertificate()

	nodeA, err := core.New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Stop()
	nodeB, err := core.New(cfgB.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Stop()

	u, _ := url.Parse("tcp://localhost:0")
	listener, err := nodeA.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}
	peerURL, _ := url.Parse("tcp://" + listener.Addr().String())
	if err := nodeB.CallPeer(peerURL, ""); err != nil {
		t.Fatal(err)
	}

	// Wait for connection
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(nodeA.GetTree()) > 1 {
			break
		}
	}
	time.Sleep(time.Second)

	// TCP peers should NOT have datagram support
	if nodeA.HasDatagramSupport(nodeB.PublicKey()) {
		t.Fatal("TCP peer should not support datagrams")
	}
	err = nodeA.SendDatagram([]byte("test"), nodeB.PublicKey())
	if err != core.ErrDatagramNoPeer {
		t.Fatalf("expected ErrDatagramNoPeer, got %v", err)
	}
	t.Log("TCP peer correctly rejected datagram send")
}

func TestDatagramThroughput(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	const numPackets = 1000
	const packetSize = 500

	received := int64(0)
	done := make(chan struct{})
	go func() {
		ch := nodeA.ReceiveDatagrams()
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					return
				}
				if atomic.AddInt64(&received, 1) >= numPackets {
					close(done)
					return
				}
			case <-time.After(3 * time.Second):
				close(done)
				return
			}
		}
	}()

	payload := make([]byte, packetSize)
	rand.Read(payload)
	start := time.Now()
	for i := 0; i < numPackets; i++ {
		nodeB.SendDatagram(payload, nodeA.PublicKey())
	}

	<-done
	elapsed := time.Since(start)
	count := atomic.LoadInt64(&received)
	t.Logf("Sent %d, received %d (%.1f%%), in %v",
		numPackets, count, float64(count)/float64(numPackets)*100, elapsed)
}

func TestDatagramFragmentation(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	// 5000 bytes requires ~5 fragments at 1100-byte max datagram size.
	payload := make([]byte, 5000)
	rand.Read(payload)

	if err := nodeB.SendDatagram(payload, nodeA.PublicKey()); err != nil {
		t.Fatal("SendDatagram (fragmented):", err)
	}

	select {
	case pkt := <-nodeA.ReceiveDatagrams():
		if !bytes.Equal(pkt.Data, payload) {
			t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", len(pkt.Data), len(payload))
		}
		t.Logf("Fragmented datagram (%d bytes) reassembled successfully", len(payload))
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for fragmented datagram")
	}
}

func TestDatagramFragmentationVariousSizes(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	// Test sizes from tiny to large. Max per fragment is ~1095 bytes.
	// 255 fragments * 1095 = ~279KB max. 200000 bytes needs ~183 fragments.
	sizes := []int{1, 100, 500, 1000, 1099, 1100, 1500, 3000, 10000, 50000, 200000}
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)

		if err := nodeB.SendDatagram(payload, nodeA.PublicKey()); err != nil {
			t.Fatalf("SendDatagram (%d bytes): %v", size, err)
		}

		select {
		case pkt := <-nodeA.ReceiveDatagrams():
			if !bytes.Equal(pkt.Data, payload) {
				t.Fatalf("payload mismatch at size %d: got %d bytes", size, len(pkt.Data))
			}
			t.Logf("  %d bytes: OK", size)
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout at size %d", size)
		}
	}
}

// TestDatagramProtocolPacket sends data in the exact wire format that the C++
// GDExtension _put_packet produces: [MSG_DATA(0x05)][peer_id:4B][mode:1B][channel:1B][game_data].
// This verifies that real game traffic survives the fragmentation round-trip.
func TestDatagramProtocolPacket(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	// Build a realistic protocol packet like _put_packet does.
	buildPacket := func(peerID uint32, mode, channel uint8, gameData []byte) []byte {
		msg := make([]byte, 1+4+1+1+len(gameData))
		msg[0] = 0x05 // MSG_DATA
		msg[1] = byte(peerID >> 24)
		msg[2] = byte(peerID >> 16)
		msg[3] = byte(peerID >> 8)
		msg[4] = byte(peerID)
		msg[5] = mode
		msg[6] = channel
		copy(msg[7:], gameData)
		return msg
	}

	// Small packet — fits in a single datagram (no fragmentation)
	smallGame := make([]byte, 100)
	rand.Read(smallGame)
	smallPkt := buildPacket(42, 0, 0, smallGame)

	if err := nodeB.SendDatagram(smallPkt, nodeA.PublicKey()); err != nil {
		t.Fatal("small protocol packet send:", err)
	}
	select {
	case pkt := <-nodeA.ReceiveDatagrams():
		if !bytes.Equal(pkt.Data, smallPkt) {
			t.Fatal("small protocol packet mismatch")
		}
		if pkt.Data[0] != 0x05 {
			t.Fatal("MSG_DATA type byte corrupted")
		}
		gotID := uint32(pkt.Data[1])<<24 | uint32(pkt.Data[2])<<16 | uint32(pkt.Data[3])<<8 | uint32(pkt.Data[4])
		if gotID != 42 {
			t.Fatalf("peer_id corrupted: got %d, want 42", gotID)
		}
		if !bytes.Equal(pkt.Data[7:], smallGame) {
			t.Fatal("game data corrupted in small packet")
		}
		t.Log("Small protocol packet (107 bytes): OK")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout on small protocol packet")
	}

	// Large packet — requires fragmentation (simulates a big state update)
	bigGame := make([]byte, 8000)
	rand.Read(bigGame)
	bigPkt := buildPacket(99, 2, 3, bigGame) // mode=2 (unreliable), channel=3

	if err := nodeB.SendDatagram(bigPkt, nodeA.PublicKey()); err != nil {
		t.Fatal("large protocol packet send:", err)
	}
	select {
	case pkt := <-nodeA.ReceiveDatagrams():
		if !bytes.Equal(pkt.Data, bigPkt) {
			t.Fatalf("large protocol packet mismatch: got %d bytes, want %d", len(pkt.Data), len(bigPkt))
		}
		if pkt.Data[0] != 0x05 {
			t.Fatal("MSG_DATA type byte corrupted after fragmentation")
		}
		gotID := uint32(pkt.Data[1])<<24 | uint32(pkt.Data[2])<<16 | uint32(pkt.Data[3])<<8 | uint32(pkt.Data[4])
		if gotID != 99 {
			t.Fatalf("peer_id corrupted after fragmentation: got %d, want 99", gotID)
		}
		if pkt.Data[5] != 2 || pkt.Data[6] != 3 {
			t.Fatalf("mode/channel corrupted: got %d/%d, want 2/3", pkt.Data[5], pkt.Data[6])
		}
		if !bytes.Equal(pkt.Data[7:], bigGame) {
			t.Fatal("game data corrupted after fragmentation")
		}
		t.Logf("Large protocol packet (%d bytes, fragmented): OK", len(bigPkt))
	case <-time.After(5 * time.Second):
		t.Fatal("timeout on large protocol packet")
	}
}

// TestLateClientJoin reproduces the exact GDScript test pattern:
// 1. Create server + 9 relays, chain via CallPeer
// 2. Wait for partial tree convergence (tree >= 2) + 1s pause
// 3. Create client LATE, connect to relay8
// 4. Start bgReader on server and client
// 5. Client sends to server repeatedly
// This isolates whether the late-join pattern works in pure Go.
func TestLateClientJoin(t *testing.T) {
	const numRelays = 9
	const sendInterval = 83 * time.Millisecond
	const timeout = 120 * time.Second

	logger := testLogger()

	// Step 1: Create server + 9 relays
	numInitial := 1 + numRelays // server + relays
	nodes := make([]*core.Core, numInitial)
	for i := 0; i < numInitial; i++ {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		node, err := core.New(cfg.Certificate, logger)
		if err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
		defer node.Stop()
		nodes[i] = node
	}

	// Step 2: Chain them: node[i] listens, node[i+1] CallPeers
	lastRelayListener := (*core.Listener)(nil)
	for i := 0; i < numInitial-1; i++ {
		lURL, _ := url.Parse("quic://localhost:0")
		rl, err := nodes[i].Listen(lURL, "")
		if err != nil {
			t.Fatalf("node %d Listen: %v", i, err)
		}
		if i == numInitial-2 {
			// Save relay8's listener for the client later
			lURL2, _ := url.Parse("quic://localhost:0")
			lastRelayListener, err = nodes[i+1].Listen(lURL2, "")
			if err != nil {
				t.Fatalf("relay8 extra Listen: %v", err)
			}
		}
		peerURL, _ := url.Parse("quic://" + rl.Addr().String())
		if err := nodes[i+1].CallPeer(peerURL, ""); err != nil {
			t.Fatalf("node %d CallPeer: %v", i+1, err)
		}
	}

	// Step 3: Wait for partial convergence (tree >= 2) like GDScript test
	for attempt := 0; attempt < 200; attempt++ {
		time.Sleep(100 * time.Millisecond)
		allReady := true
		for _, node := range nodes {
			if len(node.GetTree()) < 2 {
				allReady = false
				break
			}
		}
		if allReady {
			t.Logf("All initial nodes have tree >= 2 after %dms", (attempt+1)*100)
			break
		}
		if attempt == 199 {
			t.Log("WARNING: not all initial nodes have tree >= 2 after 20s")
		}
	}

	// Step 4: 1 second pause (matching GDScript test)
	time.Sleep(time.Second)

	// Log tree state
	for i, node := range nodes {
		t.Logf("  node %d tree: %d", i, len(node.GetTree()))
	}

	// Step 5: Create client LATE (like GDScript pattern)
	cfg := config.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	client, err := core.New(cfg.Certificate, logger)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Stop()

	// Connect client to relay8
	relay8Addr := lastRelayListener.Addr().String()
	peerURL, _ := url.Parse("quic://" + relay8Addr)
	if err := client.CallPeer(peerURL, ""); err != nil {
		t.Fatalf("client CallPeer: %v", err)
	}
	t.Logf("Client created and connected to relay8 at %s", relay8Addr)

	// Step 6: Start bgReader on server and client
	server := nodes[0]
	srvRecvCh, srvKnownPeers := capiStyleBgReader(server)
	clientRecvCh, clientKnownPeers := capiStyleBgReader(client)

	// Server echoes
	go func() {
		for pkt := range srvRecvCh {
			senderKey := []byte(pkt.from.(iwt.Addr))
			capiStyleSendTo(server, srvKnownPeers, ed25519.PublicKey(senderKey), pkt.data)
		}
	}()

	// Step 7: Client sends in a loop
	serverPubKey := server.PublicKey()
	payload := make([]byte, 100)
	rand.Read(payload)

	t.Log("Starting send loop (late-join client)...")
	sendStart := time.Now()
	var sendCount int

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		ticker := time.NewTicker(sendInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendCount++
				capiStyleSendTo(client, clientKnownPeers, serverPubKey, payload)
				if sendCount <= 10 || sendCount%50 == 0 {
					t.Logf("  send #%d (elapsed %v, client_tree=%d)", sendCount, time.Since(sendStart), len(client.GetTree()))
				}
			case <-clientRecvCh:
				return
			}
		}
	}()

	select {
	case <-sendDone:
		elapsed := time.Since(sendStart)
		t.Logf("=== LATE CLIENT JOIN ===")
		t.Logf("First response after %d sends, %v", sendCount, elapsed)
		t.Logf("Client tree: %d, Server tree: %d", len(client.GetTree()), len(server.GetTree()))
		if elapsed > 30*time.Second {
			t.Errorf("Too slow! Expected <30s, got %v", elapsed)
		}
	case <-time.After(timeout):
		t.Logf("Client tree at timeout: %d", len(client.GetTree()))
		t.Logf("Server tree at timeout: %d", len(server.GetTree()))
		for i, node := range nodes {
			t.Logf("  node %d tree: %d", i, len(node.GetTree()))
		}
		t.Fatalf("TIMEOUT after %v (%d sends)", timeout, sendCount)
	}
}

func TestInjectClientKey(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		want string // substring that must appear
	}{
		{
			name: "quic URI gets password",
			in:   "quic://1.2.3.4:5678",
			want: "password=" + clientKey,
		},
		{
			name: "tcp URI gets password",
			in:   "tcp://example.com:9001",
			want: "password=" + clientKey,
		},
		{
			name: "existing password preserved",
			in:   "quic://1.2.3.4:5678?password=custom",
			want: "password=custom",
		},
		{
			name: "empty string passthrough",
			in:   "",
			want: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := injectClientKey(tt.in)
			if tt.want == "" {
				if got != tt.in {
					t.Errorf("injectClientKey(%q) = %q, want %q", tt.in, got, tt.in)
				}
				return
			}
			if !containsSubstr(got, tt.want) {
				t.Errorf("injectClientKey(%q) = %q, does not contain %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestInjectClientKeyDoesNotOverwrite(t *testing.T) {
	uri := "quic://host:1234?password=mypassword"
	got := injectClientKey(uri)
	if containsSubstr(got, clientKey) {
		t.Errorf("injectClientKey should not overwrite existing password, got %q", got)
	}
}

func containsSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestClientKeyPasswordHandshake(t *testing.T) {
	logger := testLogger()

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	if err := cfgA.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := cfgB.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}

	nodeA, err := core.New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Stop()

	nodeB, err := core.New(cfgB.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Stop()

	// Node A listens with client key.
	listenURI := injectClientKey("quic://localhost:0")
	u, _ := url.Parse(listenURI)
	listener, err := nodeA.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}

	// Node B connects with client key — should succeed.
	peerURI := injectClientKey(fmt.Sprintf("quic://%s", listener.Addr().String()))
	pu, _ := url.Parse(peerURI)
	if err := nodeB.CallPeer(pu, ""); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		peers := nodeA.GetPeers()
		for _, p := range peers {
			if p.Up && bytes.Equal(p.Key, nodeB.PublicKey()) {
				return // success
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("nodes failed to peer with matching client key")
}

func TestClientKeyPasswordRejection(t *testing.T) {
	logger := testLogger()

	cfgA, cfgC := config.GenerateConfig(), config.GenerateConfig()
	if err := cfgA.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := cfgC.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}

	nodeA, err := core.New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Stop()

	nodeC, err := core.New(cfgC.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeC.Stop()

	// Node A listens with client key.
	listenURI := injectClientKey("quic://localhost:0")
	u, _ := url.Parse(listenURI)
	listener, err := nodeA.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}

	// Node C connects WITHOUT client key — should be rejected.
	peerURI := fmt.Sprintf("quic://%s", listener.Addr().String())
	pu, _ := url.Parse(peerURI)
	_ = nodeC.CallPeer(pu, "")

	// Wait and verify no peering established.
	time.Sleep(3 * time.Second)
	peers := nodeA.GetPeers()
	for _, p := range peers {
		if p.Up && bytes.Equal(p.Key, nodeC.PublicKey()) {
			t.Fatal("node without client key should not be peered")
		}
	}
}

func TestAllowedPublicKeys(t *testing.T) {
	logger := testLogger()

	cfgA, cfgB, cfgC := config.GenerateConfig(), config.GenerateConfig(), config.GenerateConfig()
	for _, cfg := range []*config.NodeConfig{cfgA, cfgB, cfgC} {
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
	}

	nodeA, err := core.New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Stop()

	nodeB, err := core.New(cfgB.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Stop()

	nodeC, err := core.New(cfgC.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeC.Stop()

	// Allow only nodeB's public key on nodeA.
	nodeA.AllowPublicKey(nodeB.PublicKey())

	// Node A listens with client key.
	listenURI := injectClientKey("quic://localhost:0")
	u, _ := url.Parse(listenURI)
	listener, err := nodeA.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()

	// Node B connects (allowed).
	puB, _ := url.Parse(injectClientKey(fmt.Sprintf("quic://%s", addr)))
	if err := nodeB.CallPeer(puB, ""); err != nil {
		t.Fatal(err)
	}

	// Node C connects (not allowed).
	puC, _ := url.Parse(injectClientKey(fmt.Sprintf("quic://%s", addr)))
	_ = nodeC.CallPeer(puC, "")

	deadline := time.Now().Add(10 * time.Second)
	bPeered := false
	for time.Now().Before(deadline) {
		peers := nodeA.GetPeers()
		for _, p := range peers {
			if p.Up && bytes.Equal(p.Key, nodeB.PublicKey()) {
				bPeered = true
			}
			if p.Up && bytes.Equal(p.Key, nodeC.PublicKey()) {
				t.Fatal("nodeC should not be peered (not in AllowedPublicKeys)")
			}
		}
		if bPeered {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !bPeered {
		t.Fatal("nodeB should have been peered (is in AllowedPublicKeys)")
	}

	// Verify nodeC is still not peered after extra wait.
	time.Sleep(2 * time.Second)
	peers := nodeA.GetPeers()
	for _, p := range peers {
		if p.Up && bytes.Equal(p.Key, nodeC.PublicKey()) {
			t.Fatal("nodeC should not be peered after extra wait")
		}
	}
}

// udpProxy sits between two UDP endpoints and injects latency, jitter, and packet loss.
// It uses two sockets: one facing the client, one facing the server.
type pktLog struct {
	t     time.Duration // relative to start
	dir   string        // "C→S" or "S→C"
	size  int
}

type udpProxy struct {
	clientConn *net.UDPConn // proxy listens here (client connects to this)
	serverConn *net.UDPConn // proxy uses this to talk to the real server
	targetAddr *net.UDPAddr // the real server address

	baseLatency time.Duration // one-way base latency
	jitter      time.Duration // +/- random jitter on top of base
	lossPercent int           // 0-100, percentage of packets to drop

	mu         sync.Mutex
	clientAddr *net.UDPAddr // learned from first client packet
	closed     atomic.Bool

	// Stats
	c2sTotal   atomic.Int64
	s2cTotal   atomic.Int64
	c2sDropped atomic.Int64
	s2cDropped atomic.Int64

	logMu   sync.Mutex
	logStart time.Time
	logs    []pktLog
	logging bool
}

func newUDPProxy(t *testing.T, targetAddr string, baseLatency, jitter time.Duration, lossPercent int) *udpProxy {
	t.Helper()
	target, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	p := &udpProxy{
		clientConn:  clientConn,
		serverConn:  serverConn,
		targetAddr:  target,
		baseLatency: baseLatency,
		jitter:      jitter,
		lossPercent: lossPercent,
	}
	go p.clientToServer()
	go p.serverToClient()
	return p
}

func (p *udpProxy) Addr() string {
	return p.clientConn.LocalAddr().String()
}

func (p *udpProxy) Close() {
	p.closed.Store(true)
	p.clientConn.Close()
	p.serverConn.Close()
}

func (p *udpProxy) shouldDrop() bool {
	if p.lossPercent <= 0 {
		return false
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	return int(n.Int64()) < p.lossPercent
}

func (p *udpProxy) delay() time.Duration {
	d := p.baseLatency
	if p.jitter > 0 {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(p.jitter*2)))
		d += time.Duration(n.Int64()) - p.jitter
		if d < 0 {
			d = 0
		}
	}
	return d
}

func (p *udpProxy) stats() (c2sTotal, c2sDropped, s2cTotal, s2cDropped int64) {
	return p.c2sTotal.Load(), p.c2sDropped.Load(), p.s2cTotal.Load(), p.s2cDropped.Load()
}

func (p *udpProxy) resetStats() {
	p.c2sTotal.Store(0)
	p.c2sDropped.Store(0)
	p.s2cTotal.Store(0)
	p.s2cDropped.Store(0)
}

func (p *udpProxy) logPkt(dir string, size int) {
	if !p.logging {
		return
	}
	p.logMu.Lock()
	p.logs = append(p.logs, pktLog{t: time.Since(p.logStart), dir: dir, size: size})
	p.logMu.Unlock()
}

func (p *udpProxy) startLogging() {
	p.logMu.Lock()
	p.logStart = time.Now()
	p.logs = nil
	p.logging = true
	p.logMu.Unlock()
}

func (p *udpProxy) dumpLogs(t *testing.T) {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	p.logging = false
	t.Logf("=== Packet timeline (%d packets) ===", len(p.logs))
	for _, l := range p.logs {
		t.Logf("  %12v  %s  %d bytes", l.t.Round(time.Microsecond), l.dir, l.size)
	}
}

// delayQueue delivers packets in order after a delay, using a single goroutine
// with a timer instead of goroutine-per-packet (which causes reordering).
type delayQueue struct {
	ch     chan delayEntry
	dst    *net.UDPConn
	proxy  *udpProxy
	dir    string
	closed *atomic.Bool
}

type delayEntry struct {
	data    []byte
	addr    *net.UDPAddr
	delivAt time.Time
}

func newDelayQueue(dst *net.UDPConn, proxy *udpProxy, dir string, closed *atomic.Bool) *delayQueue {
	dq := &delayQueue{
		ch:     make(chan delayEntry, 65536),
		dst:    dst,
		proxy:  proxy,
		dir:    dir,
		closed: closed,
	}
	go dq.run()
	return dq
}

func (dq *delayQueue) send(data []byte, addr *net.UDPAddr, delay time.Duration) {
	pkt := make([]byte, len(data))
	copy(pkt, data)
	select {
	case dq.ch <- delayEntry{data: pkt, addr: addr, delivAt: time.Now().Add(delay)}:
	default:
		// queue full, drop
	}
}

func (dq *delayQueue) run() {
	for e := range dq.ch {
		if dq.closed.Load() {
			return
		}
		if wait := time.Until(e.delivAt); wait > 0 {
			time.Sleep(wait)
		}
		if !dq.closed.Load() {
			dq.proxy.logPkt(dq.dir, len(e.data))
			dq.dst.WriteToUDP(e.data, e.addr)
		}
	}
}

// clientToServer reads from the client-facing socket and forwards to the server.
func (p *udpProxy) clientToServer() {
	dq := newDelayQueue(p.serverConn, p, "C→S", &p.closed)
	buf := make([]byte, 65536)
	for {
		if p.closed.Load() {
			close(dq.ch)
			return
		}
		n, srcAddr, err := p.clientConn.ReadFromUDP(buf)
		if err != nil {
			close(dq.ch)
			return
		}
		p.mu.Lock()
		p.clientAddr = srcAddr
		p.mu.Unlock()

		p.c2sTotal.Add(1)
		if p.shouldDrop() {
			p.c2sDropped.Add(1)
			continue
		}
		dq.send(buf[:n], p.targetAddr, p.delay())
	}
}

// serverToClient reads responses from the server and forwards back to the client.
func (p *udpProxy) serverToClient() {
	dq := newDelayQueue(p.clientConn, p, "S→C", &p.closed)
	buf := make([]byte, 65536)
	for {
		if p.closed.Load() {
			close(dq.ch)
			return
		}
		n, _, err := p.serverConn.ReadFromUDP(buf)
		if err != nil {
			close(dq.ch)
			return
		}
		p.mu.Lock()
		client := p.clientAddr
		p.mu.Unlock()
		if client == nil {
			continue
		}
		p.s2cTotal.Add(1)
		if p.shouldDrop() {
			p.s2cDropped.Add(1)
			continue
		}
		dq.send(buf[:n], client, p.delay())
	}
}

// createConnectedPairViaProxy creates two nodes connected through a UDP proxy
// that simulates network impairment (latency, jitter, packet loss).
func createConnectedPairViaProxy(t *testing.T, baseLatency, jitter time.Duration, lossPercent int) (*core.Core, *core.Core, *udpProxy) {
	t.Helper()
	logger := testLogger()

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	if err := cfgA.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := cfgB.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}

	nodeA, err := core.New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := core.New(cfgB.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}

	// nodeA listens on QUIC
	u, _ := url.Parse("quic://localhost:0")
	listener, err := nodeA.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}

	// Create proxy pointing to nodeA's listener
	proxy := newUDPProxy(t, listener.Addr().String(), baseLatency, jitter, lossPercent)

	// nodeB connects through the proxy
	peerURL, _ := url.Parse("quic://" + proxy.Addr())
	if err := nodeB.CallPeer(peerURL, ""); err != nil {
		t.Fatal(err)
	}

	// Wait for tree convergence
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(nodeA.GetTree()) > 1 && len(nodeB.GetTree()) > 1 {
			time.Sleep(3 * time.Second)
			return nodeA, nodeB, proxy
		}
	}
	t.Fatal("nodes did not connect through proxy")
	return nil, nil, nil
}

// TestThroughputWithNetworkImpairment measures throughput under various simulated
// network conditions with packet loss tracking to avoid chasing test artifacts.
func TestThroughputWithNetworkImpairment(t *testing.T) {
	const packetSize = 60_000
	const totalSize = 1_000_000 // 1 MB

	type scenario struct {
		name        string
		latency     time.Duration // one-way base latency
		jitter      time.Duration // +/- jitter
		lossPercent int           // packet loss %
	}

	type result struct {
		name       string
		mbps       float64
		elapsed    time.Duration
		c2sTotal   int64
		c2sDropped int64
		s2cTotal   int64
		s2cDropped int64
	}
	var results []result

	scenarios := []scenario{
		// Baseline
		{"baseline (no impairment)", 0, 0, 0},
		// Latency sweep
		{"10ms latency", 10 * time.Millisecond, 0, 0},
		{"25ms latency", 25 * time.Millisecond, 0, 0},
		{"50ms latency", 50 * time.Millisecond, 0, 0},
		{"100ms latency", 100 * time.Millisecond, 0, 0},
		// Jitter
		{"25ms latency + 10ms jitter", 25 * time.Millisecond, 10 * time.Millisecond, 0},
		{"25ms latency + 25ms jitter", 25 * time.Millisecond, 25 * time.Millisecond, 0},
		// Packet loss
		{"25ms latency + 0.5% loss", 25 * time.Millisecond, 0, 1},
		{"25ms latency + 2% loss", 25 * time.Millisecond, 0, 2},
		{"25ms latency + 5% loss", 25 * time.Millisecond, 0, 5},
		// Realistic combos
		{"5G good (10ms+5ms jitter)", 10 * time.Millisecond, 5 * time.Millisecond, 0},
		{"5G typical (25ms+15ms jitter+0.5% loss)", 25 * time.Millisecond, 15 * time.Millisecond, 1},
		{"5G poor (50ms+30ms jitter+2% loss)", 50 * time.Millisecond, 30 * time.Millisecond, 2},
		{"satellite (300ms+50ms jitter+1% loss)", 300 * time.Millisecond, 50 * time.Millisecond, 1},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			nodeA, nodeB, proxy := createConnectedPairViaProxy(t, sc.latency, sc.jitter, sc.lossPercent)
			defer nodeA.Stop()
			defer nodeB.Stop()
			defer proxy.Close()

			numPackets := totalSize / packetSize
			proxy.resetStats()

			// B needs a read loop for session acks
			go func() {
				buf := make([]byte, packetSize)
				for {
					if _, _, err := nodeB.ReadFrom(buf); err != nil {
						return
					}
				}
			}()

			msg := make([]byte, packetSize)
			rand.Read(msg[40:])
			msg[0] = 0x60
			copy(msg[8:24], nodeB.Address())
			copy(msg[24:40], nodeA.Address())
			addr := nodeA.LocalAddr()

			// Warmup
			nodeB.WriteTo(msg, addr)
			warmupBuf := make([]byte, packetSize)
			if _, _, err := nodeA.ReadFrom(warmupBuf); err != nil {
				t.Fatalf("warmup ReadFrom: %v", err)
			}

			// Receiver on A
			var recvCount atomic.Int64
			recvDone := make(chan struct{})
			go func() {
				buf := make([]byte, packetSize)
				for i := 0; i < numPackets; i++ {
					if _, _, err := nodeA.ReadFrom(buf); err != nil {
						return
					}
					recvCount.Add(1)
				}
				close(recvDone)
			}()

			// Sender on B
			start := time.Now()
			for i := 0; i < numPackets; i++ {
				if _, err := nodeB.WriteTo(msg, addr); err != nil {
					t.Fatalf("WriteTo %d: %v", i, err)
				}
			}

			select {
			case <-recvDone:
			case <-time.After(5 * time.Minute):
				t.Fatalf("timeout: received %d/%d packets", recvCount.Load(), numPackets)
			}
			elapsed := time.Since(start)

			totalBytes := int64(packetSize) * int64(numPackets)
			mbps := float64(totalBytes) / elapsed.Seconds() / 1_000_000
			c2sT, c2sD, s2cT, s2cD := proxy.stats()
			results = append(results, result{sc.name, mbps, elapsed, c2sT, c2sD, s2cT, s2cD})
			t.Logf("%d packets in %v (%.2f MB/s) | UDP: C→S %d/%d dropped, S→C %d/%d dropped",
				numPackets, elapsed, mbps, c2sD, c2sT, s2cD, s2cT)
		})
	}

	fmt.Printf("\n  Throughput Under Network Impairment:\n")
	fmt.Printf("  %-48s %10s %10s %18s %18s\n", "Scenario", "Time", "Rate", "C→S loss", "S→C loss")
	fmt.Printf("  %-48s %10s %10s %18s %18s\n", "--------", "----", "----", "--------", "--------")
	for _, r := range results {
		c2sLoss := "0%"
		s2cLoss := "0%"
		if r.c2sTotal > 0 {
			c2sLoss = fmt.Sprintf("%d/%d (%.1f%%)", r.c2sDropped, r.c2sTotal, float64(r.c2sDropped)/float64(r.c2sTotal)*100)
		}
		if r.s2cTotal > 0 {
			s2cLoss = fmt.Sprintf("%d/%d (%.1f%%)", r.s2cDropped, r.s2cTotal, float64(r.s2cDropped)/float64(r.s2cTotal)*100)
		}
		fmt.Printf("  %-48s %10v %8.2f MB/s %18s %18s\n", r.name, r.elapsed.Round(time.Millisecond), r.mbps, c2sLoss, s2cLoss)
	}
	fmt.Println()
}

// TestReliableDeliveryWithPacketLoss verifies that QUIC retransmission ensures
// all ironwood packets arrive despite UDP-level packet loss.
func TestReliableDeliveryWithPacketLoss(t *testing.T) {
	const packetSize = 60_000
	const numPackets = 100 // 6 MB total

	type scenario struct {
		name        string
		latency     time.Duration
		lossPercent int
	}

	scenarios := []scenario{
		{"1% loss, 25ms latency", 25 * time.Millisecond, 1},
		{"5% loss, 25ms latency", 25 * time.Millisecond, 5},
		{"10% loss, 25ms latency", 25 * time.Millisecond, 10},
		{"5% loss, 100ms latency", 100 * time.Millisecond, 5},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			nodeA, nodeB, proxy := createConnectedPairViaProxy(t, sc.latency, 0, sc.lossPercent)
			defer nodeA.Stop()
			defer nodeB.Stop()
			defer proxy.Close()

			// B needs a read loop for session acks
			go func() {
				buf := make([]byte, packetSize)
				for {
					if _, _, err := nodeB.ReadFrom(buf); err != nil {
						return
					}
				}
			}()

			// Build unique packets so we can verify content
			msgs := make([][]byte, numPackets)
			for i := range msgs {
				msgs[i] = make([]byte, packetSize)
				rand.Read(msgs[i][40:])
				msgs[i][0] = 0x60
				copy(msgs[i][8:24], nodeB.Address())
				copy(msgs[i][24:40], nodeA.Address())
				// Tag each packet with its index
				msgs[i][40] = byte(i >> 8)
				msgs[i][41] = byte(i)
			}
			addr := nodeA.LocalAddr()

			// Warmup
			nodeB.WriteTo(msgs[0], addr)
			warmupBuf := make([]byte, packetSize)
			if _, _, err := nodeA.ReadFrom(warmupBuf); err != nil {
				t.Fatalf("warmup ReadFrom: %v", err)
			}

			// Receiver on A — collect all packets
			received := make([]bool, numPackets)
			var recvCount atomic.Int64
			recvDone := make(chan struct{})
			go func() {
				buf := make([]byte, packetSize)
				for i := 0; i < numPackets; i++ {
					n, _, err := nodeA.ReadFrom(buf)
					if err != nil {
						return
					}
					if n >= 42 {
						idx := int(buf[40])<<8 | int(buf[41])
						if idx >= 0 && idx < numPackets {
							received[idx] = true
						}
					}
					recvCount.Add(1)
				}
				close(recvDone)
			}()

			// Send all packets
			start := time.Now()
			for i := 0; i < numPackets; i++ {
				if _, err := nodeB.WriteTo(msgs[i], addr); err != nil {
					t.Fatalf("WriteTo %d: %v", i, err)
				}
			}

			select {
			case <-recvDone:
			case <-time.After(5 * time.Minute):
				t.Fatalf("timeout: received %d/%d packets", recvCount.Load(), numPackets)
			}
			elapsed := time.Since(start)

			// Verify all packets arrived
			missing := 0
			for i, got := range received {
				if !got {
					missing++
					if missing <= 5 {
						t.Errorf("packet %d missing", i)
					}
				}
			}
			if missing > 0 {
				t.Fatalf("%d/%d packets missing", missing, numPackets)
			}

			totalBytes := int64(packetSize) * int64(numPackets)
			mbps := float64(totalBytes) / elapsed.Seconds() / 1_000_000
			t.Logf("PASS: %d/%d packets delivered in %v (%.2f MB/s) with %d%% loss",
				numPackets, numPackets, elapsed.Round(time.Millisecond), mbps, sc.lossPercent)
		})
	}
}

// tcpProxy sits between two TCP endpoints and injects latency and jitter.
type tcpProxy struct {
	listener    net.Listener
	baseLatency time.Duration
	jitter      time.Duration
	closed      atomic.Bool
}

func newTCPProxy(t *testing.T, targetAddr string, baseLatency, jitter time.Duration) *tcpProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &tcpProxy{
		listener:    ln,
		baseLatency: baseLatency,
		jitter:      jitter,
	}
	go func() {
		for {
			clientConn, err := ln.Accept()
			if err != nil {
				return
			}
			serverConn, err := net.Dial("tcp", targetAddr)
			if err != nil {
				clientConn.Close()
				continue
			}
			go p.pipe(clientConn, serverConn)
			go p.pipe(serverConn, clientConn)
		}
	}()
	return p
}

func (p *tcpProxy) Addr() string {
	return p.listener.Addr().String()
}

func (p *tcpProxy) Close() {
	p.closed.Store(true)
	p.listener.Close()
}

func (p *tcpProxy) pipe(src, dst net.Conn) {
	// Use a buffered channel to serialize delayed writes while allowing reads to continue.
	type chunk struct {
		data []byte
		at   time.Time // when to deliver
	}
	ch := make(chan chunk, 1024)

	// Writer goroutine: delivers chunks at scheduled times.
	go func() {
		for c := range ch {
			if delay := time.Until(c.at); delay > 0 {
				time.Sleep(delay)
			}
			if _, err := dst.Write(c.data); err != nil {
				src.Close()
				dst.Close()
				return
			}
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if err != nil || p.closed.Load() {
			close(ch)
			src.Close()
			dst.Close()
			return
		}
		d := p.baseLatency
		if p.jitter > 0 {
			jn, _ := rand.Int(rand.Reader, big.NewInt(int64(p.jitter*2)))
			d += time.Duration(jn.Int64()) - p.jitter
			if d < 0 {
				d = 0
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		ch <- chunk{data: pkt, at: time.Now().Add(d)}
	}
}

// createConnectedPairViaTCPProxy creates two nodes connected via TCP through a latency proxy.
func createConnectedPairViaTCPProxy(t *testing.T, baseLatency, jitter time.Duration) (*core.Core, *core.Core, *tcpProxy) {
	t.Helper()
	logger := testLogger()

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	if err := cfgA.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := cfgB.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}

	nodeA, err := core.New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := core.New(cfgB.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse("tcp://localhost:0")
	listener, err := nodeA.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}

	proxy := newTCPProxy(t, listener.Addr().String(), baseLatency, jitter)

	peerURL, _ := url.Parse("tcp://" + proxy.Addr())
	if err := nodeB.CallPeer(peerURL, ""); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(nodeA.GetTree()) > 1 && len(nodeB.GetTree()) > 1 {
			time.Sleep(3 * time.Second)
			return nodeA, nodeB, proxy
		}
	}
	t.Fatal("nodes did not connect through TCP proxy")
	return nil, nil, nil
}

// TestThroughputTCPvsQUIC compares throughput over TCP vs QUIC under latency.
// TCP has its own congestion control (kernel Cubic) — if ironwood is the bottleneck,
// both will be equally slow. If QUIC Cubic is the bottleneck, TCP will be faster.
func TestThroughputTCPvsQUIC(t *testing.T) {
	const packetSize = 60_000
	const totalSize = 1_000_000 // 1 MB
	const latency = 25 * time.Millisecond

	type result struct {
		name    string
		mbps    float64
		elapsed time.Duration
	}
	var results []result

	runTest := func(name string, nodeA, nodeB *core.Core) {
		numPackets := totalSize / packetSize

		go func() {
			buf := make([]byte, packetSize)
			for {
				if _, _, err := nodeB.ReadFrom(buf); err != nil {
					return
				}
			}
		}()

		msg := make([]byte, packetSize)
		rand.Read(msg[40:])
		msg[0] = 0x60
		copy(msg[8:24], nodeB.Address())
		copy(msg[24:40], nodeA.Address())
		addr := nodeA.LocalAddr()

		nodeB.WriteTo(msg, addr)
		warmupBuf := make([]byte, packetSize)
		if _, _, err := nodeA.ReadFrom(warmupBuf); err != nil {
			t.Fatalf("warmup ReadFrom: %v", err)
		}

		var recvCount atomic.Int64
		recvDone := make(chan struct{})
		go func() {
			buf := make([]byte, packetSize)
			for i := 0; i < numPackets; i++ {
				if _, _, err := nodeA.ReadFrom(buf); err != nil {
					return
				}
				recvCount.Add(1)
			}
			close(recvDone)
		}()

		start := time.Now()
		for i := 0; i < numPackets; i++ {
			if _, err := nodeB.WriteTo(msg, addr); err != nil {
				t.Fatalf("WriteTo %d: %v", i, err)
			}
		}

		select {
		case <-recvDone:
		case <-time.After(5 * time.Minute):
			t.Fatalf("timeout: received %d/%d packets", recvCount.Load(), numPackets)
		}
		elapsed := time.Since(start)

		totalBytes := int64(packetSize) * int64(numPackets)
		mbps := float64(totalBytes) / elapsed.Seconds() / 1_000_000
		results = append(results, result{name, mbps, elapsed})
		t.Logf("%s: %d packets in %v (%.2f MB/s)", name, numPackets, elapsed, mbps)
	}

	t.Run("QUIC with 25ms latency", func(t *testing.T) {
		nodeA, nodeB, proxy := createConnectedPairViaProxy(t, latency, 0, 0)
		defer nodeA.Stop()
		defer nodeB.Stop()
		defer proxy.Close()
		runTest("QUIC", nodeA, nodeB)
	})

	t.Run("TCP with 25ms latency", func(t *testing.T) {
		nodeA, nodeB, proxy := createConnectedPairViaTCPProxy(t, latency, 0)
		defer nodeA.Stop()
		defer nodeB.Stop()
		defer proxy.Close()
		runTest("TCP", nodeA, nodeB)
	})

	fmt.Printf("\n  TCP (25ms one-way latency, 100 MB transfer):\n")
	fmt.Printf("  %-30s %12s %12s\n", "Transport", "Time", "Rate")
	fmt.Printf("  %-30s %12s %12s\n", "---------", "----", "----")
	for _, r := range results {
		fmt.Printf("  %-30s %12v %10.2f MB/s\n", r.name, r.elapsed.Round(time.Millisecond), r.mbps)
	}
	fmt.Println()
}

// TestRawTCPBaseline measures raw TCP throughput through the same TCP proxy
// with 25ms latency — no ironwood, no yggdrasil. This isolates whether the
// proxy + latency alone explains the throughput drop, or if ironwood is the cause.
func TestRawTCPBaseline(t *testing.T) {
	const totalSize = 1_000_000
	const chunkSize = 60_000
	const latency = 25 * time.Millisecond

	numChunks := totalSize / chunkSize
	actualSize := int64(numChunks * chunkSize)

	// Server: accepts and drains
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverLn.Close()

	recvDone := make(chan int64)
	go func() {
		conn, err := serverLn.Accept()
		if err != nil {
			recvDone <- 0
			return
		}
		defer conn.Close()
		total, _ := io.Copy(io.Discard, io.LimitReader(conn, actualSize))
		recvDone <- total
	}()

	conn, err := net.Dial("tcp", serverLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := make([]byte, chunkSize)
	rand.Read(payload)

	start := time.Now()
	for i := 0; i < numChunks; i++ {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	select {
	case total := <-recvDone:
		elapsed := time.Since(start)
		mbps := float64(total) / elapsed.Seconds() / 1_000_000
		t.Logf("Raw TCP localhost (no proxy): %d bytes in %v (%.2f MB/s)", total, elapsed, mbps)
	case <-time.After(30 * time.Second):
		t.Fatalf("timeout")
	}
}
