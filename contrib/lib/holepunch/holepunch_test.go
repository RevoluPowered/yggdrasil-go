package holepunch

import (
	"testing"
)

func TestHolePunchGetCandidatesNoSTUN(t *testing.T) {
	// Without calling RefreshSTUN, GetCandidates should only return local candidates.
	hp := &HolePunch{
		listenPort: 55555,
	}
	candidates := hp.GetCandidates()
	for _, c := range candidates {
		if c.Type == CandidateSTUN {
			t.Error("should not have STUN candidate without RefreshSTUN")
		}
	}
}

func TestHolePunchGetCandidatesWithSTUN(t *testing.T) {
	hp := &HolePunch{
		listenPort: 55555,
		publicAddr: &STUNResult{IP: []byte{85, 1, 2, 3}, Port: 40000},
	}
	candidates := hp.GetCandidates()
	found := false
	for _, c := range candidates {
		if c.Type == CandidateSTUN {
			found = true
			// STUN candidate uses listenPort (Yggdrasil's port), not STUN port
			if c.Addr != "85.1.2.3:55555" {
				t.Errorf("STUN candidate addr = %q, want %q", c.Addr, "85.1.2.3:55555")
			}
		}
	}
	if !found {
		t.Error("expected STUN candidate")
	}
}

func TestHolePunchClosedRefreshSTUN(t *testing.T) {
	hp := &HolePunch{} // no localConn
	_, err := hp.RefreshSTUN()
	if err == nil {
		t.Fatal("expected error when closed")
	}
}

func TestHolePunchClose(t *testing.T) {
	conn, err := listenTestUDP()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	hp := &HolePunch{localConn: conn}
	if err := hp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Double close should be safe.
	hp.localConn = nil
	if err := hp.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestHolePunchRefreshSTUNLocalServer(t *testing.T) {
	// Set up a fake STUN server and verify RefreshSTUN updates publicAddr.
	serverConn, err := listenTestUDP()
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	wantIP := []byte{203, 0, 113, 42}
	wantPort := 54321

	go func() {
		buf := make([]byte, 1024)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil || n < stunHeaderSize {
			return
		}
		var txID [12]byte
		copy(txID[:], buf[8:20])
		resp := buildSTUNResponse(txID, wantIP, wantPort, true)
		serverConn.WriteToUDP(resp, clientAddr) //nolint:errcheck
	}()

	clientConn, err := listenTestUDP()
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}

	hp := &HolePunch{
		localConn:   clientConn,
		stunServers: []string{serverAddr},
	}
	defer hp.Close()

	result, err := hp.RefreshSTUN()
	if err != nil {
		t.Fatalf("RefreshSTUN: %v", err)
	}
	if result.Port != wantPort {
		t.Errorf("Port = %d, want %d", result.Port, wantPort)
	}

	// Verify publicAddr was stored.
	hp.mu.RLock()
	stored := hp.publicAddr
	hp.mu.RUnlock()
	if stored == nil {
		t.Fatal("publicAddr not stored after RefreshSTUN")
	}
	if stored.Port != wantPort {
		t.Errorf("stored port = %d, want %d", stored.Port, wantPort)
	}
}
