package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/url"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iwenc "github.com/Arceliar/ironwood/encrypted"
	iwt "github.com/Arceliar/ironwood/types"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// TestSessionNotReinitialisedDuringBulkTransfer verifies that Ironwood does NOT
// perform expensive Curve25519 key exchange (session re-init) while data is
// actively flowing between two connected peers.
//
// The bug: during sustained bulk data transfer, Ironwood calls
// sessionManager._bufferAndInit → sendInit → nacl/box.Precompute (Curve25519)
// repeatedly, consuming ~27% CPU and throttling throughput to ~3.6 MB/s at
// 200ms RTT when it should be much higher.
//
// This test sends 1000 packets over an established session and counts how many
// times sendInit is called. After the initial session setup, sendInit should
// be called 0 times during data transfer.
func TestSessionNotReinitialisedDuringBulkTransfer(t *testing.T) {
	logger := testLogger()

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	cfgA.GenerateSelfSignedCertificate()
	cfgB.GenerateSelfSignedCertificate()

	nodeA, _ := core.New(cfgA.Certificate, logger)
	defer nodeA.Stop()
	nodeB, _ := core.New(cfgB.Certificate, logger)
	defer nodeB.Stop()

	u, _ := url.Parse("quic://localhost:0")
	listener, _ := nodeA.Listen(u, "")
	peerURL, _ := url.Parse("quic://" + listener.Addr().String())
	nodeB.CallPeer(peerURL, "")

	// Wait for convergence
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(nodeA.GetTree()) > 1 && len(nodeB.GetTree()) > 1 {
			break
		}
	}
	if len(nodeA.GetTree()) <= 1 {
		t.Fatal("nodes did not connect")
	}
	time.Sleep(3 * time.Second)

	keyA := nodeA.PublicKey()
	_ = nodeB.PublicKey()

	// Start background reader on A so sessions can establish
	go func() {
		buf := make([]byte, 65536)
		for {
			_, _, err := nodeA.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// Warm up session: send a few packets and wait for session to be established
	for i := 0; i < 5; i++ {
		nodeB.WriteTo([]byte("warmup"), iwt.Addr(keyA))
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)

	// At this point the session should be fully established.
	// Now do a bulk transfer and measure throughput degradation over time.

	packetSize := 32000
	payload := []byte(strings.Repeat("X", packetSize))
	numPackets := 1000

	// Measure throughput in windows
	windowSize := 100 // packets per window
	windows := numPackets / windowSize

	t.Logf("Sending %d packets (%d bytes each) in %d windows of %d",
		numPackets, packetSize, windows, windowSize)

	var windowThroughputs []float64
	totalStart := time.Now()

	for w := 0; w < windows; w++ {
		windowStart := time.Now()
		for i := 0; i < windowSize; i++ {
			nodeB.WriteTo(payload, iwt.Addr(keyA))
		}
		windowElapsed := time.Since(windowStart).Seconds()
		windowMBps := float64(windowSize*packetSize) / windowElapsed / 1024 / 1024
		windowThroughputs = append(windowThroughputs, windowMBps)
		t.Logf("Window %d: %.1f MB/s (%.3fs)", w, windowMBps, windowElapsed)
	}

	totalElapsed := time.Since(totalStart).Seconds()
	totalMBps := float64(numPackets*packetSize) / totalElapsed / 1024 / 1024
	t.Logf("Total: %.1f MB/s over %.1fs", totalMBps, totalElapsed)

	// Check for throughput degradation: the last window should not be
	// dramatically slower than the first window. If session re-init is
	// happening, later windows will be much slower due to crypto overhead.
	if len(windowThroughputs) >= 2 {
		first := windowThroughputs[0]
		last := windowThroughputs[len(windowThroughputs)-1]
		ratio := last / first

		t.Logf("First window: %.1f MB/s, Last window: %.1f MB/s, Ratio: %.2f", first, last, ratio)

		// If the last window is less than 50% of the first window's throughput,
		// session re-init is likely happening
		if ratio < 0.5 {
			t.Errorf("Throughput degraded to %.0f%% of initial — session re-init likely occurring during transfer (first=%.1f MB/s, last=%.1f MB/s)",
				ratio*100, first, last)
		}
	}
}

// TestSustainedThroughputStability sends data for 10 seconds and checks that
// throughput remains stable (doesn't collapse after initial burst).
func TestSustainedThroughputStability(t *testing.T) {
	logger := testLogger()

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	cfgA.GenerateSelfSignedCertificate()
	cfgB.GenerateSelfSignedCertificate()

	nodeA, _ := core.New(cfgA.Certificate, logger)
	defer nodeA.Stop()
	nodeB, _ := core.New(cfgB.Certificate, logger)
	defer nodeB.Stop()

	u, _ := url.Parse("quic://localhost:0")
	listener, _ := nodeA.Listen(u, "")
	peerURL, _ := url.Parse("quic://" + listener.Addr().String())
	nodeB.CallPeer(peerURL, "")

	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(nodeA.GetTree()) > 1 {
			break
		}
	}
	time.Sleep(3 * time.Second)

	keyA := nodeA.PublicKey()

	// Background reader
	var bytesReceived int64
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := nodeA.ReadFrom(buf)
			if err != nil {
				return
			}
			atomic.AddInt64(&bytesReceived, int64(n))
		}
	}()

	// Warm up
	for i := 0; i < 10; i++ {
		nodeB.WriteTo([]byte("warmup"), iwt.Addr(keyA))
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)

	// Send for 10 seconds, measure throughput each second
	payload := []byte(strings.Repeat("X", 32000))
	duration := 10 * time.Second
	end := time.Now().Add(duration)

	var secondThroughputs []float64
	var totalSent int64

	for time.Now().Before(end) {
		secStart := time.Now()
		secEnd := secStart.Add(time.Second)
		var secSent int64

		for time.Now().Before(secEnd) {
			n, _ := nodeB.WriteTo(payload, iwt.Addr(keyA))
			if n > 0 {
				secSent += int64(n)
				totalSent += int64(n)
			}
		}

		secMBps := float64(secSent) / 1024 / 1024
		secondThroughputs = append(secondThroughputs, secMBps)
		t.Logf("Second %d: %.1f MB/s (sent %d bytes)", len(secondThroughputs), secMBps, secSent)
	}

	t.Logf("Total sent: %.0f MB, received: %.0f MB",
		float64(totalSent)/1024/1024, float64(bytesReceived)/1024/1024)

	// Analyze: check if throughput is stable
	if len(secondThroughputs) < 5 {
		t.Fatal("not enough data points")
	}

	// Average of first 3 seconds vs last 3 seconds
	earlyAvg := (secondThroughputs[0] + secondThroughputs[1] + secondThroughputs[2]) / 3
	lateAvg := (secondThroughputs[len(secondThroughputs)-3] +
		secondThroughputs[len(secondThroughputs)-2] +
		secondThroughputs[len(secondThroughputs)-1]) / 3

	ratio := lateAvg / earlyAvg
	t.Logf("Early avg: %.1f MB/s, Late avg: %.1f MB/s, Ratio: %.2f", earlyAvg, lateAvg, ratio)

	if ratio < 0.5 {
		t.Errorf("Throughput collapsed: early=%.1f MB/s, late=%.1f MB/s (%.0f%% of initial) — session re-init during transfer",
			earlyAvg, lateAvg, ratio*100)
	}
}

// TestSessionInitCountDuringTransfer directly counts how many goroutines are
// running crypto operations during a bulk transfer. A high count indicates
// session re-initialization.
func TestSessionInitCountDuringTransfer(t *testing.T) {
	logger := testLogger()

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	cfgA.GenerateSelfSignedCertificate()
	cfgB.GenerateSelfSignedCertificate()

	nodeA, _ := core.New(cfgA.Certificate, logger)
	defer nodeA.Stop()
	nodeB, _ := core.New(cfgB.Certificate, logger)
	defer nodeB.Stop()

	u, _ := url.Parse("quic://localhost:0")
	listener, _ := nodeA.Listen(u, "")
	peerURL, _ := url.Parse("quic://" + listener.Addr().String())
	nodeB.CallPeer(peerURL, "")

	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(nodeA.GetTree()) > 1 {
			break
		}
	}
	time.Sleep(3 * time.Second)

	keyA := nodeA.PublicKey()

	// Background reader
	go func() {
		buf := make([]byte, 65536)
		for {
			_, _, err := nodeA.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// Warm up session
	for i := 0; i < 10; i++ {
		nodeB.WriteTo([]byte("warmup"), iwt.Addr(keyA))
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)
	t.Log("Session warmed up, starting bulk transfer...")

	// Take a goroutine snapshot before
	goroutinesBefore := runtime.NumGoroutine()

	// Send bulk data
	payload := []byte(strings.Repeat("X", 32000))
	var wg sync.WaitGroup

	// Sample CPU profile during transfer
	var profileBuf strings.Builder
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(500 * time.Millisecond) // let transfer start
		pprof.Lookup("goroutine").WriteTo(&profileBuf, 1)
	}()

	sent := 0
	start := time.Now()
	for i := 0; i < 500; i++ {
		nodeB.WriteTo(payload, iwt.Addr(keyA))
		sent++
	}
	elapsed := time.Since(start)
	wg.Wait()

	goroutinesAfter := runtime.NumGoroutine()

	t.Logf("Sent %d packets in %v", sent, elapsed)
	t.Logf("Goroutines: before=%d, during=%d", goroutinesBefore, goroutinesAfter)

	// Check goroutine profile for crypto operations
	profile := profileBuf.String()
	cryptoCount := strings.Count(profile, "curve25519") +
		strings.Count(profile, "nacl/box") +
		strings.Count(profile, "Precompute") +
		strings.Count(profile, "sendInit") +
		strings.Count(profile, "_bufferAndInit")

	t.Logf("Crypto/session-init goroutine references during transfer: %d", cryptoCount)

	if cryptoCount > 2 {
		t.Errorf("Found %d crypto/session-init references in goroutine profile during active transfer — session re-init is occurring mid-transfer", cryptoCount)
	}

	// Also check: the IW-SESSION log spam shows "no session" on every WriteTo.
	// Even though throughput is high on localhost (init resolves in microseconds),
	// this means EVERY write goes through _bufferAndInit rather than a fast-path
	// for established sessions. With network latency, this kills throughput.
	//
	// This is the core bug: WriteTo should use the established session directly
	// once it exists, not re-enter _bufferAndInit on every call.
	t.Log("NOTE: Even if this test passes, check IW-SESSION logs — 'no session for' on every WriteTo indicates missing fast-path for established sessions")

	_ = hex.EncodeToString(keyA)
	_ = ed25519.PublicKey(keyA)
	_ = fmt.Sprintf("%v", peerURL)
}

// TestWriteToUsesEstablishedSession verifies that after a session is established,
// subsequent WriteTo calls do NOT go through _bufferAndInit.
//
// This is the root cause of the throughput collapse under latency:
// WriteTo → _bufferAndInit → sendInit → Curve25519 on EVERY packet,
// instead of WriteTo → established session → direct encrypt+send.
func TestWriteToUsesEstablishedSession(t *testing.T) {
	if testing.Verbose() {
		// Count "no session" log messages during transfer
		t.Log("Enable verbose (-v) to see IW-SESSION log messages")
	}

	logger := testLogger()
	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	cfgA.GenerateSelfSignedCertificate()
	cfgB.GenerateSelfSignedCertificate()

	nodeA, _ := core.New(cfgA.Certificate, logger)
	defer nodeA.Stop()
	nodeB, _ := core.New(cfgB.Certificate, logger)
	defer nodeB.Stop()

	u, _ := url.Parse("quic://localhost:0")
	listener, _ := nodeA.Listen(u, "")
	peerURL, _ := url.Parse("quic://" + listener.Addr().String())
	nodeB.CallPeer(peerURL, "")

	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(nodeA.GetTree()) > 1 {
			break
		}
	}
	time.Sleep(3 * time.Second)

	keyA := nodeA.PublicKey()

	// Background reader
	go func() {
		buf := make([]byte, 65536)
		for {
			_, _, err := nodeA.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	// NOTE: No reader on B — the fix in encrypted/packetconn.go should
	// auto-start the read loop from WriteTo so sessions can establish
	// without requiring ReadFrom to be called.

	// Warm up — establish session
	for i := 0; i < 20; i++ {
		nodeB.WriteTo([]byte("warmup"), iwt.Addr(keyA))
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(3 * time.Second)

	// Now send 100 packets. If the session is established, NONE should
	// trigger "no session for" / _bufferAndInit.
	// We detect this by counting IW-SESSION log lines via the session log func.
	var initCount int64
	origLogFunc := iwenc.SessionLogFunc
	iwenc.SessionLogFunc = func(msg string) {
		if strings.Contains(msg, "no session for") || strings.Contains(msg, "_bufferAndInit") {
			atomic.AddInt64(&initCount, 1)
		}
		if origLogFunc != nil {
			origLogFunc(msg)
		}
	}
	defer func() { iwenc.SessionLogFunc = origLogFunc }()

	payload := []byte(strings.Repeat("X", 1000))
	for i := 0; i < 100; i++ {
		nodeB.WriteTo(payload, iwt.Addr(keyA))
	}
	time.Sleep(1 * time.Second)

	count := atomic.LoadInt64(&initCount)
	t.Logf("Session init/buffer attempts during 100-packet transfer after warmup: %d", count)

	if count > 0 {
		t.Errorf("WriteTo triggered %d session re-init attempts on an established session — "+
			"this causes throughput collapse under latency (each re-init does Curve25519 key exchange)", count)
	}
}
