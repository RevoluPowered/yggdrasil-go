package holepunch

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gologme/log"
)

// HolePunch manages STUN discovery and UPnP port mapping. Incoming
// connections are handled by Yggdrasil's built-in QUIC listener —
// this module just discovers the public address and maps ports.
type HolePunch struct {
	stunServers []string
	listenPort  int // Yggdrasil's QUIC listener port (for UPnP mapping + candidates)

	mu         sync.RWMutex
	localConn  *net.UDPConn // UDP socket for STUN queries only
	publicAddr *STUNResult  // last known STUN result

	natMapper *NATMapper // UPnP/NAT-PMP mapper (nil if unavailable or disabled)
	logger    *log.Logger
}

// New creates a new HolePunch instance. listenPort is the port
// Yggdrasil's QUIC listener is bound to — UPnP will map this port
// and candidates will advertise it.
func New(logger *log.Logger, listenPort int, stunServers ...string) (*HolePunch, error) {
	if len(stunServers) == 0 {
		stunServers = DefaultSTUNServers
	}

	// Bind a UDP socket for STUN queries. This is separate from
	// Yggdrasil's listener to avoid packet contention.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("bind STUN socket: %w", err)
	}

	return &HolePunch{
		stunServers: stunServers,
		listenPort:  listenPort,
		localConn:   conn,
		logger:      logger,
	}, nil
}

// EnableUPnP starts UPnP/NAT-PMP port mapping for the Yggdrasil
// listener port. Returns nil if no gateway is found (not an error).
// Call DisableUPnP to release the mapping.
func (hp *HolePunch) EnableUPnP() error {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if hp.natMapper != nil {
		return nil // already enabled
	}

	mapper, err := NewNATMapper(NATMapperConfig{
		LocalPort:   hp.listenPort,
		Description: "something.chat P2P",
	})
	if err != nil {
		return err
	}
	hp.natMapper = mapper // may be nil if no gateway found
	return nil
}

// DisableUPnP releases any active UPnP/NAT-PMP port mapping.
func (hp *HolePunch) DisableUPnP() {
	hp.mu.Lock()
	mapper := hp.natMapper
	hp.natMapper = nil
	hp.mu.Unlock()
	if mapper != nil {
		mapper.Stop()
	}
}

// DetectNAT probes STUN servers to determine the NAT type.
func (hp *HolePunch) DetectNAT() *NATInfo {
	hp.mu.RLock()
	conn := hp.localConn
	hp.mu.RUnlock()
	if conn == nil {
		return &NATInfo{Type: NATUnknown, Details: "holepunch closed"}
	}
	return DetectNATType(conn, hp.stunServers, 5*time.Second)
}

// UPnPEnabled returns true if a UPnP/NAT-PMP mapping is active.
func (hp *HolePunch) UPnPEnabled() bool {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.natMapper != nil
}

// ExternalURI returns the UPnP-mapped QUIC URI, or "" if unavailable.
func (hp *HolePunch) ExternalURI() string {
	hp.mu.RLock()
	mapper := hp.natMapper
	hp.mu.RUnlock()
	if mapper == nil {
		return ""
	}
	return mapper.ExternalURI()
}

// ExternalTLSURI returns the UPnP-mapped TLS (TCP) URI, or "" if unavailable.
func (hp *HolePunch) ExternalTLSURI() string {
	hp.mu.RLock()
	mapper := hp.natMapper
	hp.mu.RUnlock()
	if mapper == nil {
		return ""
	}
	return mapper.ExternalTLSURI()
}

// Close releases the STUN UDP socket and any UPnP mappings.
func (hp *HolePunch) Close() error {
	hp.DisableUPnP()
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if hp.localConn != nil {
		return hp.localConn.Close()
	}
	return nil
}

// RefreshSTUN queries STUN servers to update the public address.
func (hp *HolePunch) RefreshSTUN() (*STUNResult, error) {
	hp.mu.RLock()
	conn := hp.localConn
	hp.mu.RUnlock()
	if conn == nil {
		return nil, fmt.Errorf("holepunch closed")
	}

	result, err := DiscoverPublicAddr(conn, hp.stunServers, 5*time.Second)
	if err != nil {
		return nil, err
	}

	hp.mu.Lock()
	hp.publicAddr = result
	hp.mu.Unlock()
	return result, nil
}

// GetCandidates gathers all connection candidates: STUN-discovered
// public address (with Yggdrasil listener port), UPnP-mapped address,
// and local network addresses.
func (hp *HolePunch) GetCandidates() []Candidate {
	var candidates []Candidate

	hp.mu.RLock()
	pub := hp.publicAddr
	port := hp.listenPort
	mapper := hp.natMapper
	hp.mu.RUnlock()

	// STUN candidate: public IP from STUN, but use Yggdrasil's listener port
	if pub != nil {
		candidates = append(candidates, Candidate{
			Addr: net.JoinHostPort(pub.IP.String(), fmt.Sprintf("%d", port)),
			Type: CandidateSTUN,
		})
	}
	// UPnP candidate: externally mapped address
	if mapper != nil {
		if ip, mport := mapper.ExternalAddr(); ip != nil && mport > 0 {
			candidates = append(candidates, Candidate{
				Addr: net.JoinHostPort(ip.String(), fmt.Sprintf("%d", mport)),
				Type: CandidateUPnP,
			})
		}
	}
	// Local candidates: LAN addresses with Yggdrasil's listener port
	candidates = append(candidates, GatherLocalCandidates(port)...)
	return candidates
}
