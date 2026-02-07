package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

func createConnectedPair(t *testing.T) (*core.Core, *core.Core) {
	t.Helper()
	logger := log.New(os.Stderr, "", 0)
	logger.EnableLevel("info")
	logger.EnableLevel("warn")
	logger.EnableLevel("error")

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
	peerURL, _ := url.Parse("tcp://" + listener.Addr().String())
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
	logger := log.New(os.Stderr, "", 0)
	logger.EnableLevel("info")
	logger.EnableLevel("warn")
	logger.EnableLevel("error")

	srvCfg := config.GenerateConfig()
	if err := srvCfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	server, err := core.New(srvCfg.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse("tcp://localhost:0")
	listener, err := server.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}
	peerURL, _ := url.Parse("tcp://" + listener.Addr().String())
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

			if _, err := client.WriteTo(msg, server.LocalAddr()); err != nil {
				t.Errorf("client %d WriteTo: %v", idx, err)
				done <- idx
				return
			}
			buf := make([]byte, msgLen)
			n, _, err := client.ReadFrom(buf)
			if err != nil {
				t.Errorf("client %d ReadFrom: %v", idx, err)
				done <- idx
				return
			}
			if !bytes.Equal(msg[40:], buf[40:n]) {
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
		{"1MB", 1_000_000},
		{"8MB", 8_000_000},
		{"32MB", 32_000_000},
		{"64MB", 64_000_000},
		{"128MB", 128_000_000},
		{"512MB", 512_000_000},
		{"1GB", 1_000_000_000},
	}

	type result struct {
		name string
		mbps float64
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
				recvDone <- struct{}{}
			}()

			// Sender on B (main goroutine)
			start := time.Now()
			for i := 0; i < numPackets; i++ {
				if _, err := nodeB.WriteTo(msg, addr); err != nil {
					t.Fatalf("WriteTo %d: %v", i, err)
				}
			}

			// Wait for all packets to arrive
			select {
			case <-recvDone:
			case <-time.After(120 * time.Second):
				t.Fatalf("timeout: received %d/%d packets", recvCount.Load(), numPackets)
			}
			elapsed := time.Since(start)

			totalBytes := int64(packetSize) * int64(numPackets)
			mbps := float64(totalBytes) / elapsed.Seconds() / 1_000_000
			results = append(results, result{tc.name, mbps})
			t.Logf("%d packets x 60KB in %v (%.2f MB/s)", numPackets, elapsed, mbps)
		})
	}

	// Print summary table (visible without -v)
	fmt.Printf("\n  Throughput Summary (60KB packets):\n")
	fmt.Printf("  %-8s %10s\n", "Total", "MB/s")
	fmt.Printf("  %-8s %10s\n", "-----", "----")
	for _, r := range results {
		fmt.Printf("  %-8s %10.2f\n", r.name, r.mbps)
	}
	fmt.Println()
}

// createChain creates a linear chain of numNodes: 0 ←→ 1 ←→ 2 ←→ ... ←→ (n-1).
// Packets from node 0 to node n-1 traverse all intermediate hops.
func createChain(t *testing.T, numNodes int) ([]*core.Core, func()) {
	t.Helper()
	logger := log.New(os.Stderr, "", 0)

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
		u, _ := url.Parse("tcp://localhost:0")
		listener, err := nodes[i].Listen(u, "")
		if err != nil {
			t.Fatalf("node %d Listen: %v", i, err)
		}
		peerURL, _ := url.Parse("tcp://" + listener.Addr().String())
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

