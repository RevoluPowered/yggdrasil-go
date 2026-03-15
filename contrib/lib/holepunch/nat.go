package holepunch

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
	natpmp "github.com/jackpal/go-nat-pmp"
)

// NATMapper manages UPnP/NAT-PMP port mappings. It discovers the gateway,
// maps a UDP port, and refreshes the mapping periodically. The mapping is
// released on Stop().
type NATMapper struct {
	mu          sync.RWMutex
	localPort   int
	mappedPort  int
	externalIP  net.IP
	description string
	leaseSecs   int

	// UPnP client (nil if using NAT-PMP or not discovered).
	upnpClient upnpClient
	// NAT-PMP client (nil if using UPnP or not discovered).
	pmpClient *natpmp.Client
	pmpGW     net.IP

	stopCh chan struct{}
	done   chan struct{}
}

// upnpClient is the subset of WANIPConnection we need, satisfied by both
// WANIPConnection1 and WANIPConnection2.
type upnpClient interface {
	AddPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16,
		protocol string, internalPort uint16, internalClient string,
		enabled bool, description string, leaseDuration uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16,
		protocol string) error
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
}

// NATMapperConfig holds configuration for the NAT mapper.
type NATMapperConfig struct {
	LocalPort   int           // local UDP port to map
	Description string        // description for the port mapping
	LeaseSecs   int           // lease duration in seconds (default 1800 = 30m)
	Refresh     time.Duration // refresh interval (default 15m)
}

// NewNATMapper discovers a UPnP or NAT-PMP gateway and creates a port
// mapping. Returns nil, nil if no gateway is found (not an error — just
// means UPnP/NAT-PMP is unavailable).
func NewNATMapper(cfg NATMapperConfig) (*NATMapper, error) {
	if cfg.LeaseSecs <= 0 {
		cfg.LeaseSecs = 1800 // 30 minutes
	}
	if cfg.Refresh <= 0 {
		cfg.Refresh = 15 * time.Minute
	}
	if cfg.Description == "" {
		cfg.Description = "something.chat"
	}

	m := &NATMapper{
		localPort:   cfg.LocalPort,
		description: cfg.Description,
		leaseSecs:   cfg.LeaseSecs,
		stopCh:      make(chan struct{}),
		done:        make(chan struct{}),
	}

	// Try UPnP first, then NAT-PMP.
	if err := m.discoverUPnP(); err == nil {
		// Map the port.
		if err := m.mapPort(); err != nil {
			return nil, fmt.Errorf("UPnP port mapping: %w", err)
		}
		go m.refreshLoop(cfg.Refresh)
		return m, nil
	}

	if err := m.discoverNATPMP(); err == nil {
		if err := m.mapPort(); err != nil {
			return nil, fmt.Errorf("NAT-PMP port mapping: %w", err)
		}
		go m.refreshLoop(cfg.Refresh)
		return m, nil
	}

	// No gateway found — not an error.
	return nil, nil
}

func (m *NATMapper) discoverUPnP() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try IGD2 first (WANIPConnection2), then IGD1 (WANIPConnection1).
	clients2, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	if err == nil && len(clients2) > 0 {
		m.upnpClient = clients2[0]
		return nil
	}

	clients1, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	if err == nil && len(clients1) > 0 {
		m.upnpClient = clients1[0]
		return nil
	}

	return fmt.Errorf("no UPnP gateway found")
}

func (m *NATMapper) discoverNATPMP() error {
	gw, err := defaultGateway()
	if err != nil {
		return err
	}

	client := natpmp.NewClientWithTimeout(gw, 3*time.Second)
	// Test connectivity by requesting external address.
	_, err = client.GetExternalAddress()
	if err != nil {
		return fmt.Errorf("NAT-PMP not available: %w", err)
	}
	m.pmpClient = client
	m.pmpGW = gw
	return nil
}

func (m *NATMapper) mapPort() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.upnpClient != nil {
		return m.mapPortUPnP()
	}
	if m.pmpClient != nil {
		return m.mapPortPMP()
	}
	return fmt.Errorf("no NAT client")
}

func (m *NATMapper) mapPortUPnP() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get external IP.
	extIP, err := m.upnpClient.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return fmt.Errorf("get external IP: %w", err)
	}
	m.externalIP = net.ParseIP(extIP)

	// Get local IP for the mapping.
	localIP, err := localIPForGateway()
	if err != nil {
		return fmt.Errorf("get local IP: %w", err)
	}

	port := uint16(m.localPort)
	// Map UDP (QUIC)
	err = m.upnpClient.AddPortMappingCtx(ctx,
		"",          // remote host (any)
		port,        // external port
		"UDP",       // protocol
		port,        // internal port
		localIP,     // internal client
		true,        // enabled
		m.description+" UDP",
		uint32(m.leaseSecs),
	)
	if err != nil {
		return fmt.Errorf("add UDP port mapping: %w", err)
	}
	// Map TCP (TLS) on the same port
	err = m.upnpClient.AddPortMappingCtx(ctx,
		"",
		port,
		"TCP",
		port,
		localIP,
		true,
		m.description+" TCP",
		uint32(m.leaseSecs),
	)
	if err != nil {
		// TCP mapping failure is non-fatal — UDP still works
		fmt.Printf("UPnP TCP mapping failed (non-fatal): %v\n", err)
	}
	m.mappedPort = int(port)
	return nil
}

func (m *NATMapper) mapPortPMP() error {
	result, err := m.pmpClient.AddPortMapping("udp", m.localPort, m.localPort, m.leaseSecs)
	if err != nil {
		return fmt.Errorf("NAT-PMP add UDP mapping: %w", err)
	}
	m.mappedPort = int(result.MappedExternalPort)

	// Also map TCP on the same port (non-fatal if it fails)
	_, _ = m.pmpClient.AddPortMapping("tcp", m.localPort, m.localPort, m.leaseSecs)

	// Get external IP.
	extResult, err := m.pmpClient.GetExternalAddress()
	if err == nil {
		m.externalIP = net.IP(extResult.ExternalIPAddress[:])
	}
	return nil
}

func (m *NATMapper) refreshLoop(interval time.Duration) {
	defer close(m.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			_ = m.mapPort() // silently refresh
		}
	}
}

// ExternalAddr returns the external IP:port if a mapping exists.
func (m *NATMapper) ExternalAddr() (net.IP, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.externalIP, m.mappedPort
}

// ExternalURI returns a QUIC URI for the mapped port, or "" if unmapped.
func (m *NATMapper) ExternalURI() string {
	ip, port := m.ExternalAddr()
	if ip == nil || port == 0 {
		return ""
	}
	return fmt.Sprintf("quic://%s", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
}

// ExternalTLSURI returns a TLS (TCP) URI for the mapped port, or "" if unmapped.
func (m *NATMapper) ExternalTLSURI() string {
	ip, port := m.ExternalAddr()
	if ip == nil || port == 0 {
		return ""
	}
	return fmt.Sprintf("tls://%s", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
}

// Stop releases the port mapping and stops the refresh goroutine.
func (m *NATMapper) Stop() {
	select {
	case <-m.stopCh:
		return // already stopped
	default:
		close(m.stopCh)
	}
	<-m.done

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.upnpClient != nil && m.mappedPort > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.upnpClient.DeletePortMappingCtx(ctx, "", uint16(m.mappedPort), "UDP")
		_ = m.upnpClient.DeletePortMappingCtx(ctx, "", uint16(m.mappedPort), "TCP")
	}
	if m.pmpClient != nil && m.mappedPort > 0 {
		// Mapping with lifetime 0 = delete.
		_, _ = m.pmpClient.AddPortMapping("udp", m.localPort, 0, 0)
		_, _ = m.pmpClient.AddPortMapping("tcp", m.localPort, 0, 0)
	}
	m.mappedPort = 0
}

// defaultGateway returns the default gateway IP for NAT-PMP.
func defaultGateway() (net.IP, error) {
	// NAT-PMP assumes the gateway is the first hop. Use a UDP dial
	// to a public address to find which interface routes externally,
	// then infer the gateway as x.x.x.1 (common for home routers).
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("determine default gateway: %w", err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("non-IPv4 default route")
	}
	// Guess gateway as x.x.x.1.
	gw := make(net.IP, 4)
	copy(gw, ip)
	gw[3] = 1
	return gw, nil
}

// localIPForGateway returns the local IP address that routes to the internet.
func localIPForGateway() (string, error) {
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
