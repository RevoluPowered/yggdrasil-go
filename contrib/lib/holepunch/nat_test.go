package holepunch

import (
	"net"
	"os"
	"testing"

	"github.com/gologme/log"
)

func TestNATMapperNilWhenNoGateway(t *testing.T) {
	// NewNATMapper should return nil, nil when no UPnP/NAT-PMP gateway
	// is discoverable (which is the case in most CI/test environments).
	mapper, err := NewNATMapper(NATMapperConfig{
		LocalPort: 12345,
	})
	if err != nil {
		// An error means a gateway was found but mapping failed — that's
		// also acceptable in test environments.
		t.Logf("NewNATMapper returned error (expected in some environments): %v", err)
		return
	}
	if mapper == nil {
		t.Log("No UPnP/NAT-PMP gateway found (expected in test environments)")
		return
	}
	// If we got a mapper, clean up.
	t.Log("UPnP/NAT-PMP gateway found, cleaning up mapping")
	mapper.Stop()
}

func TestNATMapperExternalAddrEmpty(t *testing.T) {
	m := &NATMapper{
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
	close(m.stopCh)
	close(m.done)

	ip, port := m.ExternalAddr()
	if ip != nil || port != 0 {
		t.Errorf("expected empty, got %v:%d", ip, port)
	}
}

func TestNATMapperExternalURIEmpty(t *testing.T) {
	m := &NATMapper{
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
	close(m.stopCh)
	close(m.done)

	if uri := m.ExternalURI(); uri != "" {
		t.Errorf("expected empty URI, got %q", uri)
	}
}

func TestNATMapperExternalURI(t *testing.T) {
	m := &NATMapper{
		externalIP: net.IPv4(85, 1, 2, 3),
		mappedPort: 5678,
		stopCh:     make(chan struct{}),
		done:       make(chan struct{}),
	}
	close(m.stopCh)
	close(m.done)

	want := "quic://85.1.2.3:5678"
	if got := m.ExternalURI(); got != want {
		t.Errorf("ExternalURI() = %q, want %q", got, want)
	}
}

func TestNATMapperStopIdempotent(t *testing.T) {
	m := &NATMapper{
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
	close(m.stopCh)
	close(m.done)

	// Second Stop should not panic.
	m.Stop()
	m.Stop()
}

func testLogger() *log.Logger {
	l := log.New(os.Stderr, "[test] ", 0)
	l.EnableLevel("error")
	l.EnableLevel("warn")
	l.EnableLevel("info")
	return l
}

func TestHolePunchUPnPToggle(t *testing.T) {
	hp := &HolePunch{
		listenPort: 12345,
		logger:     testLogger(),
	}
	// UPnP should be disabled by default.
	if hp.UPnPEnabled() {
		t.Error("UPnP should be disabled by default")
	}
	if uri := hp.ExternalURI(); uri != "" {
		t.Errorf("ExternalURI should be empty, got %q", uri)
	}

	// EnableUPnP will likely find no gateway in test env, which is fine.
	_ = hp.EnableUPnP()

	// DisableUPnP should be safe regardless.
	hp.DisableUPnP()
	if hp.UPnPEnabled() {
		t.Error("UPnP should be disabled after DisableUPnP")
	}
}

func TestGetCandidatesIncludesUPnP(t *testing.T) {
	mapper := &NATMapper{
		externalIP: net.IPv4(85, 1, 2, 3),
		mappedPort: 5678,
		stopCh:     make(chan struct{}),
		done:       make(chan struct{}),
	}
	close(mapper.stopCh)
	close(mapper.done)

	hp := &HolePunch{
		listenPort: 55555,
		natMapper:  mapper,
	}
	candidates := hp.GetCandidates()
	found := false
	for _, c := range candidates {
		if c.Type == CandidateUPnP {
			found = true
			if c.Addr != "85.1.2.3:5678" {
				t.Errorf("UPnP candidate addr = %q, want %q", c.Addr, "85.1.2.3:5678")
			}
		}
	}
	if !found {
		t.Error("expected UPnP candidate in GetCandidates")
	}
}
