package holepunch

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// STUN constants (RFC 5389).
const (
	stunMagicCookie    = 0x2112A442
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	stunAttrXORMapped  = 0x0020
	stunAttrMapped     = 0x0001
	stunHeaderSize     = 20
)

// STUNResult holds the reflexive (public) address discovered via STUN.
type STUNResult struct {
	IP   net.IP
	Port int
}

// String returns the address as "ip:port".
func (r STUNResult) String() string {
	return net.JoinHostPort(r.IP.String(), fmt.Sprintf("%d", r.Port))
}

// QuerySTUN sends a STUN Binding Request from conn to serverAddr and
// returns the XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS) from the response.
// The conn should be a *net.UDPConn so the response comes back on the
// same port that will be used for hole punching.
func QuerySTUN(conn *net.UDPConn, serverAddr string, timeout time.Duration) (*STUNResult, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve STUN server %s: %w", serverAddr, err)
	}

	// Build Binding Request.
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, fmt.Errorf("generate transaction ID: %w", err)
	}
	req := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0) // message length
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], txID[:])

	if _, err := conn.WriteToUDP(req, addr); err != nil {
		return nil, fmt.Errorf("send STUN request: %w", err)
	}

	// Read response.
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("read STUN response: %w", err)
	}
	if n < stunHeaderSize {
		return nil, fmt.Errorf("STUN response too short: %d bytes", n)
	}

	// Validate response.
	msgType := binary.BigEndian.Uint16(buf[0:2])
	if msgType != stunBindingSuccess {
		return nil, fmt.Errorf("unexpected STUN response type: 0x%04x", msgType)
	}
	cookie := binary.BigEndian.Uint32(buf[4:8])
	if cookie != stunMagicCookie {
		return nil, fmt.Errorf("invalid magic cookie: 0x%08x", cookie)
	}
	// Verify transaction ID matches.
	for i := 0; i < 12; i++ {
		if buf[8+i] != txID[i] {
			return nil, fmt.Errorf("transaction ID mismatch")
		}
	}

	// Parse attributes to find XOR-MAPPED-ADDRESS or MAPPED-ADDRESS.
	msgLen := int(binary.BigEndian.Uint16(buf[2:4]))
	attrs := buf[stunHeaderSize:]
	if len(attrs) > msgLen {
		attrs = attrs[:msgLen]
	}
	return parseSTUNAttributes(attrs, txID)
}

func parseSTUNAttributes(attrs []byte, txID [12]byte) (*STUNResult, error) {
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		attrs = attrs[4:]
		if len(attrs) < attrLen {
			break
		}
		value := attrs[:attrLen]
		attrs = attrs[attrLen:]
		// Pad to 4-byte boundary.
		if pad := attrLen % 4; pad != 0 {
			skip := 4 - pad
			if len(attrs) >= skip {
				attrs = attrs[skip:]
			}
		}

		switch attrType {
		case stunAttrXORMapped:
			return parseXORMappedAddress(value, txID)
		case stunAttrMapped:
			return parseMappedAddress(value)
		}
	}
	return nil, fmt.Errorf("no MAPPED-ADDRESS in STUN response")
}

func parseXORMappedAddress(value []byte, txID [12]byte) (*STUNResult, error) {
	if len(value) < 8 {
		return nil, fmt.Errorf("XOR-MAPPED-ADDRESS too short")
	}
	family := value[1]
	xport := binary.BigEndian.Uint16(value[2:4])
	port := int(xport ^ uint16(stunMagicCookie>>16))

	switch family {
	case 0x01: // IPv4
		if len(value) < 8 {
			return nil, fmt.Errorf("XOR-MAPPED-ADDRESS IPv4 too short")
		}
		ip := make(net.IP, 4)
		xip := binary.BigEndian.Uint32(value[4:8])
		binary.BigEndian.PutUint32(ip, xip^stunMagicCookie)
		return &STUNResult{IP: ip, Port: port}, nil

	case 0x02: // IPv6
		if len(value) < 20 {
			return nil, fmt.Errorf("XOR-MAPPED-ADDRESS IPv6 too short")
		}
		ip := make(net.IP, 16)
		// XOR with magic cookie + transaction ID
		var xorKey [16]byte
		binary.BigEndian.PutUint32(xorKey[0:4], stunMagicCookie)
		copy(xorKey[4:16], txID[:])
		for i := 0; i < 16; i++ {
			ip[i] = value[4+i] ^ xorKey[i]
		}
		return &STUNResult{IP: ip, Port: port}, nil

	default:
		return nil, fmt.Errorf("unknown address family: %d", family)
	}
}

func parseMappedAddress(value []byte) (*STUNResult, error) {
	if len(value) < 8 {
		return nil, fmt.Errorf("MAPPED-ADDRESS too short")
	}
	family := value[1]
	port := int(binary.BigEndian.Uint16(value[2:4]))

	switch family {
	case 0x01: // IPv4
		ip := net.IP(make([]byte, 4))
		copy(ip, value[4:8])
		return &STUNResult{IP: ip, Port: port}, nil

	case 0x02: // IPv6
		if len(value) < 20 {
			return nil, fmt.Errorf("MAPPED-ADDRESS IPv6 too short")
		}
		ip := net.IP(make([]byte, 16))
		copy(ip, value[4:20])
		return &STUNResult{IP: ip, Port: port}, nil

	default:
		return nil, fmt.Errorf("unknown address family: %d", family)
	}
}

// DefaultSTUNServers is the hardcoded list of public STUN servers.
// Cloudflare on port 3478 first (standard STUN port, better carrier compat),
// then Google's 5 servers on 19302 as fallback.
var DefaultSTUNServers = []string{
	"stun.cloudflare.com:3478",
	"turn.cloudflare.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun2.l.google.com:19302",
	"stun3.l.google.com:19302",
	"stun4.l.google.com:19302",
}

// NATType describes the NAT behavior as determined by STUN probing.
type NATType string

const (
	NATNone      NATType = "none"      // no NAT, public IP
	NATCone      NATType = "cone"      // full/restricted/port-restricted cone — hole punch works
	NATSymmetric NATType = "symmetric" // different mapping per destination — hole punch usually fails
	NATUnknown   NATType = "unknown"   // couldn't determine
)

// NATInfo holds the result of NAT type detection.
type NATInfo struct {
	Type       NATType
	PublicAddr *STUNResult
	Details    string // human-readable explanation
}

// DetectNATType queries two different STUN servers from the same UDP socket
// and compares the reflexive addresses. If the mapped port differs, the NAT
// is symmetric. If it's the same, the NAT is cone-type.
//
// It tries all available servers to find two that respond, so it tolerates
// individual server failures (e.g. carrier blocking specific UDP ports).
func DetectNATType(conn *net.UDPConn, servers []string, timeout time.Duration) *NATInfo {
	if len(servers) < 2 {
		servers = DefaultSTUNServers
	}

	// Try each server until we get two successful results.
	type stunHit struct {
		server string
		result *STUNResult
	}
	var hits []stunHit
	var errors []string

	for _, srv := range servers {
		result, err := QuerySTUN(conn, srv, timeout)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", srv, err))
			continue
		}
		hits = append(hits, stunHit{server: srv, result: result})
		if len(hits) >= 2 {
			break
		}
	}

	if len(hits) == 0 {
		return &NATInfo{Type: NATUnknown, Details: fmt.Sprintf("all STUN servers failed: %v", errors)}
	}
	if len(hits) == 1 {
		return &NATInfo{Type: NATUnknown, PublicAddr: hits[0].result,
			Details: fmt.Sprintf("only 1 STUN server responded (%s → %s), cannot determine NAT type. failures: %v",
				hits[0].server, hits[0].result, errors)}
	}

	result1, srv1 := hits[0].result, hits[0].server
	result2, srv2 := hits[1].result, hits[1].server

	// Check if the local port matches the mapped port (no NAT).
	localPort := conn.LocalAddr().(*net.UDPAddr).Port
	if result1.Port == localPort && result2.Port == localPort {
		return &NATInfo{Type: NATNone, PublicAddr: result1, Details: fmt.Sprintf("public IP, no NAT (mapped port %d matches local port)", localPort)}
	}

	// Compare the two mapped addresses.
	if result1.Port == result2.Port && result1.IP.Equal(result2.IP) {
		return &NATInfo{
			Type:       NATCone,
			PublicAddr: result1,
			Details: fmt.Sprintf("cone NAT — same mapping %s via %s and %s (hole punch will work)",
				result1, srv1, srv2),
		}
	}

	return &NATInfo{
		Type:       NATSymmetric,
		PublicAddr: result1,
		Details: fmt.Sprintf("symmetric NAT — %s via %s but %s via %s (hole punch unreliable, need UPnP or relay)",
			result1, srv1, result2, srv2),
	}
}

// DiscoverPublicAddr tries each STUN server in order and returns the
// first successful reflexive address. The provided conn is used so that
// the discovered address maps to the same local port.
func DiscoverPublicAddr(conn *net.UDPConn, servers []string, timeout time.Duration) (*STUNResult, error) {
	if len(servers) == 0 {
		servers = DefaultSTUNServers
	}
	var lastErr error
	for _, srv := range servers {
		result, err := QuerySTUN(conn, srv, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		return result, nil
	}
	return nil, fmt.Errorf("all STUN servers failed, last error: %w", lastErr)
}
