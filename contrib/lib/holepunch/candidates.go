package holepunch

import (
	"encoding/json"
	"fmt"
	"net"
)

// CandidateType identifies how a candidate address was discovered.
type CandidateType string

const (
	CandidateSTUN  CandidateType = "stun"
	CandidateLocal CandidateType = "local"
	CandidateUPnP  CandidateType = "upnp"
)

// Candidate represents a network address where this node might be reachable.
type Candidate struct {
	Addr string        `json:"addr"`
	Type CandidateType `json:"type"`
}

// GatherLocalCandidates returns candidates for all non-loopback unicast
// addresses on the machine, using the provided port.
func GatherLocalCandidates(port int) []Candidate {
	var candidates []Candidate
	ifaces, err := net.Interfaces()
	if err != nil {
		return candidates
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			candidates = append(candidates, Candidate{
				Addr: net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)),
				Type: CandidateLocal,
			})
		}
	}
	return candidates
}

// MarshalCandidates returns the JSON encoding of a candidate list.
func MarshalCandidates(candidates []Candidate) (string, error) {
	b, err := json.Marshal(candidates)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UnmarshalCandidates parses a JSON candidate list.
func UnmarshalCandidates(data string) ([]Candidate, error) {
	var candidates []Candidate
	if err := json.Unmarshal([]byte(data), &candidates); err != nil {
		return nil, err
	}
	return candidates, nil
}
