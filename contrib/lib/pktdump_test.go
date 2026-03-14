package main

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
)

// setupChain creates a chain of numNodes with ipv6rwc active, waits for
// convergence and path discovery, and returns the first/last rwc, nodes, plus cleanup.
func setupChain(tb testing.TB, numNodes int) (first, last *ipv6rwc.ReadWriteCloser, firstAddr, lastAddr []byte, nodes []*core.Core, cleanup func()) {
	tb.Helper()
	logger := testLogger()

	nodes = make([]*core.Core, numNodes)
	iprwcs := make([]*ipv6rwc.ReadWriteCloser, numNodes)

	for i := range nodes {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			tb.Fatal(err)
		}
		node, err := core.New(cfg.Certificate, logger)
		if err != nil {
			tb.Fatal(err)
		}
		nodes[i] = node
		rwc := ipv6rwc.NewReadWriteCloser(node)
		if rwc.MaxMTU() < cfg.IfMTU {
			rwc.SetMTU(rwc.MaxMTU())
		} else {
			rwc.SetMTU(cfg.IfMTU)
		}
		iprwcs[i] = rwc

		if i > 0 && i < numNodes-1 {
			go func(r *ipv6rwc.ReadWriteCloser) {
				buf := make([]byte, 65536)
				for {
					if _, err := r.Read(buf); err != nil {
						return
					}
				}
			}(rwc)
		}
	}

	// Chain
	for i := 0; i < numNodes-1; i++ {
		u, _ := url.Parse("quic://localhost:0")
		listener, err := nodes[i].Listen(u, "")
		if err != nil {
			tb.Fatalf("node %d Listen: %v", i, err)
		}
		peerURL, _ := url.Parse("quic://" + listener.Addr().String())
		if err := nodes[i+1].CallPeer(peerURL, ""); err != nil {
			tb.Fatalf("node %d CallPeer: %v", i+1, err)
		}
	}

	// Tree convergence
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
			break
		}
	}

	first = iprwcs[0]
	last = iprwcs[numNodes-1]
	fAddr := nodes[0].Address()
	lAddr := nodes[numNodes-1].Address()
	firstAddr = fAddr[:]
	lastAddr = lAddr[:]

	// Echo server on last node
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := last.Read(buf)
			if err != nil {
				return
			}
			res := make([]byte, n)
			copy(res, buf[:n])
			copy(res[8:24], buf[24:40])
			copy(res[24:40], buf[8:24])
			last.Write(res)
		}
	}()

	// Build warmup packet and wait for path discovery
	msg := make([]byte, 1500)
	rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], firstAddr)
	copy(msg[24:40], lastAddr)

	warmupDone := make(chan struct{}, 1)
	go func() {
		b := make([]byte, 1500)
		if _, err := first.Read(b); err != nil {
			return
		}
		warmupDone <- struct{}{}
	}()
	for attempt := 0; attempt < 1000; attempt++ {
		first.Write(msg)
		select {
		case <-warmupDone:
			goto ready
		case <-time.After(200 * time.Millisecond):
		}
	}
	tb.Fatal("path discovery timed out")

ready:
	// Stabilize
	buf := make([]byte, 1500)
	for i := 0; i < 10; i++ {
		first.Write(msg)
		first.Read(buf)
	}

	cleanup = func() {
		for _, n := range nodes {
			n.Stop()
		}
	}
	return
}

// chainStats holds aggregated peer-level stats across all nodes.
type chainStats struct {
	totalTXBytes uint64
	totalRXBytes uint64
	peerCount    int
}

// collectPeerStats snapshots TX/RX bytes from all peers on all nodes.
func collectPeerStats(nodes []*core.Core) chainStats {
	var s chainStats
	for _, node := range nodes {
		for _, p := range node.GetPeers() {
			if !p.Up {
				continue
			}
			s.totalTXBytes += p.TXBytes
			s.totalRXBytes += p.RXBytes
			s.peerCount++
		}
	}
	return s
}

// reportStats logs the delta between pre/post benchmark stats.
func reportStats(b *testing.B, pre, post chainStats, iterations int) {
	txDelta := post.totalTXBytes - pre.totalTXBytes
	rxDelta := post.totalRXBytes - pre.totalRXBytes
	totalBytes := txDelta + rxDelta

	// Expected: each iteration sends 1500 bytes through N-1 hops (each hop TX+RX)
	// plus the echo reply back through N-1 hops
	// So expected per iteration = 1500 * 2 * (N-1) hops * 2 (TX+RX per hop)
	// But QUIC adds framing overhead, so actual will be higher.
	expectedPayload := uint64(iterations) * 1500 * 2 // just the app-level payload (TX + RX)

	b.Logf("")
	b.Logf("=== NETWORK STATS (%d iterations) ===", iterations)
	b.Logf("  Peers:          %d", post.peerCount)
	b.Logf("  TX bytes:       %d (%.1f MB)", txDelta, float64(txDelta)/1e6)
	b.Logf("  RX bytes:       %d (%.1f MB)", rxDelta, float64(rxDelta)/1e6)
	b.Logf("  Total wire:     %d (%.1f MB)", totalBytes, float64(totalBytes)/1e6)
	b.Logf("  App payload:    %d (%.1f MB)", expectedPayload, float64(expectedPayload)/1e6)
	if expectedPayload > 0 {
		overhead := float64(totalBytes) / float64(expectedPayload)
		b.Logf("  Wire overhead:  %.1fx app payload", overhead)
		b.Logf("  Bytes/iter:     %d wire vs %d payload", totalBytes/uint64(iterations), expectedPayload/uint64(iterations))
	}
}

// BenchmarkRTT20 benchmarks ping-pong RTT across a 20-node (19-hop) chain.
func BenchmarkRTT20(b *testing.B) {
	first, _, firstAddr, lastAddr, nodes, cleanup := setupChain(b, 20)
	defer cleanup()

	// Snapshot stats before benchmark
	preStats := collectPeerStats(nodes)

	msg := make([]byte, 1500)
	rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], firstAddr)
	copy(msg[24:40], lastAddr)
	buf := make([]byte, 1500)

	b.ResetTimer()
	b.SetBytes(1500 * 2) // TX + RX
	for i := 0; i < b.N; i++ {
		first.Write(msg)
		first.Read(buf)
	}
	b.StopTimer()

	// Dump stats delta
	postStats := collectPeerStats(nodes)
	reportStats(b, preStats, postStats, b.N)
}

// BenchmarkThroughput33 benchmarks one-way throughput across a 33-node chain.
func BenchmarkThroughput33(b *testing.B) {
	first, _, firstAddr, lastAddr, _, cleanup := setupChain(b, 33)
	defer cleanup()

	msg := make([]byte, 1500)
	rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], firstAddr)
	copy(msg[24:40], lastAddr)

	b.ResetTimer()
	b.SetBytes(1500)
	for i := 0; i < b.N; i++ {
		first.Write(msg)
	}
}

// BenchmarkRTTParallel33 benchmarks concurrent ping-pong RTT.
func BenchmarkRTTParallel33(b *testing.B) {
	first, _, firstAddr, lastAddr, _, cleanup := setupChain(b, 33)
	defer cleanup()

	b.ResetTimer()
	b.SetBytes(1500 * 2)

	var mu sync.Mutex
	b.RunParallel(func(pb *testing.PB) {
		msg := make([]byte, 1500)
		rand.Read(msg[40:])
		msg[0] = 0x60
		copy(msg[8:24], firstAddr)
		copy(msg[24:40], lastAddr)
		buf := make([]byte, 1500)

		for pb.Next() {
			mu.Lock()
			first.Write(msg)
			first.Read(buf)
			mu.Unlock()
		}
	})
}

// TestPacketInspectorChain creates a multi-hop chain with full packet inspection
// to diagnose where packets get lost at high hop counts.
//
// Run with:
//
//	go test -v -run TestPacketInspectorChain -timeout 120s ./...
//
// Pcap files are written to /tmp/ygg-pktdump/ — open in Wireshark.
// Text logs go to stderr (visible with -v).
func TestPacketInspectorChain(t *testing.T) {
	// Test at progressively larger chains to find where it breaks
	for _, numNodes := range []int{3, 5, 9, 17, 33, 65} {
		name := fmt.Sprintf("chain_%d_nodes", numNodes)
		t.Run(name, func(t *testing.T) {
			testChainWithInspection(t, numNodes)
		})
	}
}

// TestPathConvergenceBenchmark measures how long ironwood path discovery takes
// at various chain lengths. This isolates the path discovery time from
// session establishment and warmup overhead.
//
// Run with:
//
//	go test -v -run TestPathConvergenceBenchmark -timeout 600s ./...
func TestPathConvergenceBenchmark(t *testing.T) {
	for _, numNodes := range []int{3, 5, 9, 17, 20, 33, 49, 65} {
		name := fmt.Sprintf("%d_nodes_%d_hops", numNodes, numNodes-1)
		t.Run(name, func(t *testing.T) {
			benchmarkPathConvergence(t, numNodes)
		})
	}
}

func benchmarkPathConvergence(t *testing.T, numNodes int) {
	t.Helper()
	logger := testLogger()

	// --- Phase 1: Create nodes ---
	phaseStart := time.Now()
	nodes := make([]*core.Core, numNodes)
	iprwcs := make([]*ipv6rwc.ReadWriteCloser, numNodes)

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

		rwc := ipv6rwc.NewReadWriteCloser(node)
		if rwc.MaxMTU() < cfg.IfMTU {
			rwc.SetMTU(rwc.MaxMTU())
		} else {
			rwc.SetMTU(cfg.IfMTU)
		}
		iprwcs[i] = rwc

		// Relay readers on middle nodes (matches real usage)
		if i > 0 && i < numNodes-1 {
			go func(r *ipv6rwc.ReadWriteCloser) {
				buf := make([]byte, 65536)
				for {
					if _, err := r.Read(buf); err != nil {
						return
					}
				}
			}(rwc)
		}
	}
	createTime := time.Since(phaseStart)
	t.Logf("Phase 1 - Create %d nodes: %v", numNodes, createTime)

	defer func() {
		for _, n := range nodes {
			n.Stop()
		}
	}()

	// --- Phase 2: Chain them ---
	phaseStart = time.Now()
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
	chainTime := time.Since(phaseStart)
	t.Logf("Phase 2 - Chain %d links: %v", numNodes-1, chainTime)

	// --- Phase 3: Tree convergence ---
	phaseStart = time.Now()
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
			break
		}
	}
	treeTime := time.Since(phaseStart)
	t.Logf("Phase 3 - Tree convergence: %v", treeTime)

	// Verify convergence
	for i, node := range nodes {
		if len(node.GetTree()) < 2 {
			t.Fatalf("node %d failed to converge", i)
		}
	}

	// --- Phase 4: First packet delivery (path discovery + session establishment) ---
	first := iprwcs[0]
	target := iprwcs[numNodes-1]
	firstAddr := nodes[0].Address()
	targetAddr := nodes[numNodes-1].Address()

	// Echo server
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := target.Read(buf)
			if err != nil {
				return
			}
			res := make([]byte, n)
			copy(res, buf[:n])
			copy(res[8:24], buf[24:40])
			copy(res[24:40], buf[8:24])
			target.Write(res)
		}
	}()

	// Build ping
	msg := make([]byte, 1500)
	rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], firstAddr[:])
	copy(msg[24:40], targetAddr[:])

	phaseStart = time.Now()
	warmupDone := make(chan struct{}, 1)
	go func() {
		b := make([]byte, 1500)
		if _, err := first.Read(b); err != nil {
			return
		}
		warmupDone <- struct{}{}
	}()

	var warmupAttempts int
	var pathDiscovered bool
	for warmupAttempts = 0; warmupAttempts < 1000; warmupAttempts++ {
		first.Write(msg)
		select {
		case <-warmupDone:
			pathDiscovered = true
		case <-time.After(200 * time.Millisecond):
		}
		if pathDiscovered {
			break
		}
	}
	pathTime := time.Since(phaseStart)
	if !pathDiscovered {
		t.Fatalf("Path discovery FAILED after %d attempts (%v)", warmupAttempts, pathTime)
	}
	t.Logf("Phase 4 - Path discovery + session: %v (%d warmup attempts)", pathTime, warmupAttempts)

	// --- Phase 5: Steady-state RTT ---
	// Stabilize
	buf := make([]byte, 1500)
	for i := 0; i < 5; i++ {
		first.Write(msg)
		first.Read(buf)
	}

	phaseStart = time.Now()
	const numPings = 50
	for i := 0; i < numPings; i++ {
		first.Write(msg)
		first.Read(buf)
	}
	pingTime := time.Since(phaseStart)
	avgRTT := pingTime / numPings
	perHop := avgRTT / time.Duration(2*(numNodes-1))
	t.Logf("Phase 5 - Steady RTT: avg=%v per-hop=%v (%d pings)", avgRTT, perHop, numPings)

	// --- Summary ---
	t.Logf("")
	t.Logf("=== BENCHMARK SUMMARY: %d nodes, %d hops ===", numNodes, numNodes-1)
	t.Logf("  Node creation:    %v", createTime)
	t.Logf("  QUIC chain:       %v", chainTime)
	t.Logf("  Tree convergence: %v", treeTime)
	t.Logf("  Path discovery:   %v (%d attempts)", pathTime, warmupAttempts)
	t.Logf("  Steady-state RTT: %v (per-hop: %v)", avgRTT, perHop)
	t.Logf("  Total to first packet: %v", createTime+chainTime+treeTime+pathTime)
}

func testChainWithInspection(t *testing.T, numNodes int) {
	t.Helper()

	pcapDir := fmt.Sprintf("/tmp/ygg-pktdump/%d-nodes", numNodes)
	logger := testLogger()

	// Create nodes with inspectors
	nodes := make([]*core.Core, numNodes)
	iprwcs := make([]*ipv6rwc.ReadWriteCloser, numNodes)
	inspectors := make([]*PacketInspector, numNodes)

	for i := 0; i < numNodes; i++ {
		name := fmt.Sprintf("n%d", i)
		var opts []InspectorOption
		// Only write pcap for first, last, and a few middle nodes to avoid too many files
		if i == 0 || i == numNodes-1 || i == numNodes/2 {
			os.MkdirAll(pcapDir, 0755)
			opts = append(opts, WithPcap(fmt.Sprintf("%s/%s.pcap", pcapDir, name)))
		}
		opts = append(opts, WithTextLog(os.Stderr))
		inspectors[i] = NewPacketInspector(name, opts...)

		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		node, err := core.New(cfg.Certificate, logger)
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = node

		rwc := ipv6rwc.NewReadWriteCloser(node)
		if rwc.MaxMTU() < cfg.IfMTU {
			rwc.SetMTU(rwc.MaxMTU())
		} else {
			rwc.SetMTU(cfg.IfMTU)
		}
		iprwcs[i] = rwc

		inspectors[i].CaptureEvent("node_created",
			fmt.Sprintf("addr=%s", node.Address()))

		// Start relay reader on middle nodes
		if i > 0 && i < numNodes-1 {
			go func(idx int, r *ipv6rwc.ReadWriteCloser, insp *PacketInspector) {
				buf := make([]byte, 65536)
				for {
					n, err := r.Read(buf)
					if err != nil {
						return
					}
					insp.Capture(DirRecv, nil, nil, buf[:n], "relay-discard")
				}
			}(i, rwc, inspectors[i])
		}
	}

	defer func() {
		for i, n := range nodes {
			inspectors[i].CaptureEvent("node_stopping")
			n.Stop()
			inspectors[i].Close()
		}
	}()

	// Chain them
	for i := 0; i < numNodes-1; i++ {
		u, _ := url.Parse("quic://localhost:0")
		listener, err := nodes[i].Listen(u, "")
		if err != nil {
			t.Fatalf("node %d Listen: %v", i, err)
		}
		inspectors[i].CaptureEvent("listening", fmt.Sprintf("addr=%s", listener.Addr()))

		peerURL, _ := url.Parse("quic://" + listener.Addr().String())
		if err := nodes[i+1].CallPeer(peerURL, ""); err != nil {
			t.Fatalf("node %d CallPeer: %v", i+1, err)
		}
		inspectors[i+1].CaptureEvent("peered",
			fmt.Sprintf("to=node%d", i),
			fmt.Sprintf("via=%s", peerURL))
	}

	// Wait for tree convergence with diagnostic logging
	t.Log("Waiting for tree convergence...")
	for attempt := 0; attempt < 100; attempt++ {
		time.Sleep(100 * time.Millisecond)
		allReady := true
		readyCount := 0
		for i, node := range nodes {
			treeSize := len(node.GetTree())
			if treeSize < 2 {
				allReady = false
			} else {
				readyCount++
			}
			if attempt%10 == 0 && attempt > 0 {
				peers := node.GetPeers()
				inspectors[i].CaptureEvent("convergence_check",
					fmt.Sprintf("tree=%d", treeSize),
					fmt.Sprintf("peers=%d", len(peers)),
					fmt.Sprintf("attempt=%d", attempt))
			}
		}
		if attempt%10 == 0 {
			t.Logf("  attempt %d: %d/%d nodes converged", attempt, readyCount, numNodes)
		}
		if allReady {
			t.Logf("  converged after %d attempts", attempt)
			break
		}
	}
	time.Sleep(time.Second)

	// Verify all nodes converged
	for i, node := range nodes {
		if len(node.GetTree()) < 2 {
			t.Fatalf("node %d failed to converge (tree size: %d)", i, len(node.GetTree()))
		}
	}

	// Now try to send a ping from node 0 to node N-1
	first := iprwcs[0]
	target := iprwcs[numNodes-1]

	firstAddr := nodes[0].Address()
	targetAddr := nodes[numNodes-1].Address()

	t.Logf("Sending ping from node0 (%s) to node%d (%s)",
		firstAddr, numNodes-1, targetAddr)

	// Build ping packet
	msg := make([]byte, 1500)
	rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], firstAddr[:])
	copy(msg[24:40], targetAddr[:])

	inspectors[0].Capture(DirSend, nil, nil, msg, "ping")

	// Echo server on target
	echoStop := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
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
			inspectors[numNodes-1].Capture(DirRecv, nil, nil, buf[:n], "echo-recv")

			res := make([]byte, n)
			copy(res, buf[:n])
			copy(res[8:24], buf[24:40])
			copy(res[24:40], buf[8:24])

			inspectors[numNodes-1].Capture(DirSend, nil, nil, res, "echo-send")
			target.Write(res)
		}
	}()
	defer close(echoStop)

	// Try warmup with timeout and progress logging
	warmupDone := make(chan struct{}, 1)
	go func() {
		b := make([]byte, 1500)
		if _, err := first.Read(b); err != nil {
			return
		}
		inspectors[0].Capture(DirRecv, nil, nil, b, "warmup-reply")
		warmupDone <- struct{}{}
	}()

	for attempt := 0; attempt < 500; attempt++ {
		first.Write(msg)
		if attempt%10 == 0 {
			inspectors[0].CaptureEvent("warmup_attempt",
				fmt.Sprintf("attempt=%d", attempt))
			t.Logf("  warmup attempt %d...", attempt)
		}
		// Every 50 attempts, dump node state to find the bottleneck
		if attempt%50 == 0 && attempt > 0 {
			t.Logf("  --- Node state at attempt %d ---", attempt)
			for i, node := range nodes {
				peers := node.GetPeers()
				tree := node.GetTree()
				paths := node.GetPaths()
				sessions := node.GetSessions()
				t.Logf("    node%d: peers=%d tree=%d paths=%d sessions=%d",
					i, len(peers), len(tree), len(paths), len(sessions))
			}
		}
		select {
		case <-warmupDone:
			t.Logf("  warmup succeeded after %d attempts!", attempt)
			goto done
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatalf("warmup: no echo after 500 attempts (100s) — packets lost in chain")

done:
	// If warmup succeeded, do a few measured pings
	buf := make([]byte, 1500)
	for i := 0; i < 5; i++ {
		start := time.Now()
		first.Write(msg)
		first.Read(buf)
		rtt := time.Since(start)
		t.Logf("  ping %d: RTT %v", i, rtt)
		inspectors[0].CaptureEvent("ping_rtt", fmt.Sprintf("rtt=%v", rtt))
	}

	// Log final stats
	for i, node := range nodes {
		peers := node.GetPeers()
		tree := node.GetTree()
		inspectors[i].CaptureEvent("final_state",
			fmt.Sprintf("peers=%d", len(peers)),
			fmt.Sprintf("tree=%d", len(tree)))
	}
}
