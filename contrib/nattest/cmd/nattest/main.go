package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gologme/log"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

type PeerInfo struct {
	Role      string `json:"role"`
	QUICURI   string `json:"quic_uri"`
	TLSURI    string `json:"tls_uri"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}

type TestResult struct {
	Role     string            `json:"role"`
	Peers    map[string]string `json:"peers"`
	Protocol map[string]string `json:"protocol"`
	Pass     bool              `json:"pass"`
}

type echoReply struct {
	nonce [16]byte
	ch    chan struct{}
}

var (
	pendingMu sync.Mutex
	pending   []*echoReply
)

func main() {
	role := os.Getenv("NODE_ROLE")
	listenPort := os.Getenv("LISTEN_PORT")
	mySubnet := os.Getenv("MY_SUBNET")
	gwSubnet := os.Getenv("GATEWAY_SUBNET")
	expectedNodesStr := os.Getenv("EXPECTED_NODES")
	expectedNodes := 4
	if n, err := strconv.Atoi(expectedNodesStr); err == nil {
		expectedNodes = n
	}

	logger := log.New(os.Stderr, fmt.Sprintf("[%s] ", role), log.Ltime)
	logger.EnableLevel("info")
	logger.EnableLevel("warn")
	logger.EnableLevel("error")

	// Discover our IP
	myIP := findIPOnSubnet(mySubnet)
	if myIP == "" {
		logger.Fatalf("Could not find IP on subnet %s", mySubnet)
	}
	logger.Infof("My IP: %s", myIP)

	// Set default gateway for NATted nodes
	if gwSubnet != "" {
		gateway := findGateway(gwSubnet)
		if gateway != "" {
			logger.Infof("Setting default gateway to %s", gateway)
			exec.Command("ip", "route", "del", "default").Run()
			if err := exec.Command("ip", "route", "add", "default", "via", gateway).Run(); err != nil {
				logger.Warnf("Failed to set gateway: %v", err)
			}
			// Verify route
			out, _ := exec.Command("ip", "route").Output()
			logger.Infof("Routes: %s", strings.TrimSpace(string(out)))
		}
	}

	// Generate identity
	cfg := config.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		logger.Fatalf("Failed to generate certificate: %v", err)
	}

	node, err := core.New(cfg.Certificate, logger)
	if err != nil {
		logger.Fatalf("Failed to create node: %v", err)
	}
	defer node.Stop()

	port := listenPort
	if port == "" {
		port = "27500"
	}

	// Start listeners
	quicURL, _ := url.Parse(fmt.Sprintf("quic://[::]:%s", port))
	if l, err := node.Listen(quicURL, ""); err != nil {
		logger.Warnf("QUIC listener failed: %v", err)
	} else {
		logger.Infof("QUIC listener on %s", l.Addr())
	}

	tlsURL, _ := url.Parse(fmt.Sprintf("tls://[::]:%s", port))
	if l, err := node.Listen(tlsURL, ""); err != nil {
		logger.Warnf("TLS listener failed: %v", err)
	} else {
		logger.Infof("TLS listener on %s", l.Addr())
	}

	// Write peer info
	info := PeerInfo{
		Role:      role,
		QUICURI:   fmt.Sprintf("quic://%s:%s", myIP, port),
		TLSURI:    fmt.Sprintf("tls://%s:%s", myIP, port),
		PublicKey: fmt.Sprintf("%x", node.PublicKey()),
		Address:   node.Address().String(),
	}
	infoJSON, _ := json.MarshalIndent(info, "", "  ")
	infoPath := filepath.Join("/peerinfo", role+".json")
	os.WriteFile(infoPath, infoJSON, 0644)
	logger.Infof("Identity: addr=%s", info.Address)

	// Wait for peers
	logger.Infof("Waiting for %d peers...", expectedNodes)
	peers := waitForPeers(expectedNodes, 60*time.Second)
	if len(peers) < expectedNodes {
		logger.Fatalf("Only found %d/%d peers", len(peers), expectedNodes)
	}
	logger.Infof("All %d peers discovered", len(peers))

	// Start packet handler
	go packetHandler(node, logger)

	result := TestResult{
		Role:     role,
		Peers:    make(map[string]string),
		Protocol: make(map[string]string),
		Pass:     true,
	}

	if role != "public" {
		// Find public node
		var publicPeer *PeerInfo
		for i := range peers {
			if peers[i].Role == "public" {
				publicPeer = &peers[i]
				break
			}
		}
		if publicPeer == nil {
			logger.Fatalf("Could not find public node peer info")
		}

		// Test raw TCP connectivity to public node
		tlsHost := strings.TrimPrefix(publicPeer.TLSURI, "tls://")
		logger.Infof("Testing raw TCP connectivity to %s ...", tlsHost)
		conn, err := net.DialTimeout("tcp", tlsHost, 5*time.Second)
		if err != nil {
			logger.Warnf("Raw TCP to public node FAILED: %v", err)
		} else {
			logger.Infof("Raw TCP to public node OK")
			conn.Close()
		}

		// Test raw UDP connectivity
		quicHost := strings.TrimPrefix(publicPeer.QUICURI, "quic://")
		logger.Infof("Testing raw UDP connectivity to %s ...", quicHost)
		udpAddr, _ := net.ResolveUDPAddr("udp", quicHost)
		if udpAddr != nil {
			udpConn, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				logger.Warnf("Raw UDP dial FAILED: %v", err)
			} else {
				udpConn.Write([]byte("ping"))
				logger.Infof("Raw UDP dial OK (sent ping)")
				udpConn.Close()
			}
		}

		// Connect via yggdrasil
		proto, err := connectToPublic(node, publicPeer, logger)
		if err != nil {
			logger.Errorf("Failed to connect to public node: %v", err)
			result.Pass = false
			result.Peers["public"] = err.Error()
		} else {
			result.Protocol["public"] = proto
		}
	}

	// Wait for tree convergence
	logger.Infof("Waiting for tree convergence...")
	if !waitForConvergence(node, 30*time.Second, logger) {
		logger.Errorf("Tree did not converge (entries: %d)", len(node.GetTree()))
	} else {
		logger.Infof("Tree converged (%d entries)", len(node.GetTree()))
	}

	// Extra settle time
	time.Sleep(3 * time.Second)

	// Echo tests
	logger.Infof("Running echo tests...")
	for _, peer := range peers {
		if peer.Role == role {
			continue
		}
		peerIP := net.ParseIP(peer.Address)
		if peerIP == nil {
			result.Peers[peer.Role] = "invalid address"
			result.Pass = false
			continue
		}
		err := sendEcho(node, peerIP, 10*time.Second)
		if err != nil {
			logger.Errorf("Echo %s -> %s FAIL: %v", role, peer.Role, err)
			result.Peers[peer.Role] = err.Error()
			result.Pass = false
		} else {
			logger.Infof("Echo %s -> %s OK", role, peer.Role)
			result.Peers[peer.Role] = "ok"
			if _, exists := result.Protocol[peer.Role]; !exists {
				result.Protocol[peer.Role] = "overlay"
			}
		}
	}

	// Results
	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	resultPath := filepath.Join("/peerinfo", role+".result.json")
	os.WriteFile(resultPath, resultJSON, 0644)

	if result.Pass {
		logger.Infof("ALL TESTS PASSED")
		fmt.Printf("\n=== %s: PASS ===\n%s\n", strings.ToUpper(role), string(resultJSON))
	} else {
		logger.Errorf("TESTS FAILED")
		fmt.Printf("\n=== %s: FAIL ===\n%s\n", strings.ToUpper(role), string(resultJSON))
		os.Exit(1)
	}
}

func findIPOnSubnet(prefix string) string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipnet.IP.To4(); ip4 != nil && strings.HasPrefix(ip4.String(), prefix) {
			return ip4.String()
		}
	}
	return ""
}

func findGateway(subnetPrefix string) string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipnet.IP.To4(); ip4 != nil && strings.HasPrefix(ip4.String(), subnetPrefix) {
			gw := make(net.IP, 4)
			copy(gw, ipnet.IP.Mask(ipnet.Mask))
			gw[3] = 1
			return gw.String()
		}
	}
	return ""
}

func connectToPublic(node *core.Core, pub *PeerInfo, logger *log.Logger) (string, error) {
	// Try QUIC first (non-blocking, just starts the attempt)
	logger.Infof("Starting QUIC peer: %s", pub.QUICURI)
	quicU, _ := url.Parse(pub.QUICURI)
	if err := node.CallPeer(quicU, ""); err != nil {
		logger.Warnf("QUIC CallPeer failed: %v", err)
	}

	// Also start TLS in parallel (for UDP-blocked scenarios)
	logger.Infof("Starting TLS peer: %s", pub.TLSURI)
	tlsU, _ := url.Parse(pub.TLSURI)
	if err := node.CallPeer(tlsU, ""); err != nil {
		logger.Warnf("TLS CallPeer failed: %v", err)
	}

	// Whichever connects first wins — convergence check will tell us
	// Check which protocol actually connected by looking at peers after convergence
	return "quic+tls", nil
}

func waitForConvergence(node *core.Core, timeout time.Duration, logger *log.Logger) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		tree := node.GetTree()
		if len(tree) >= 2 {
			return true
		}
		if time.Now().After(deadline.Add(-timeout / 2)) {
			// Log progress in the second half of the timeout
			logger.Infof("  tree entries: %d, peers: %d", len(tree), len(node.GetPeers()))
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func waitForPeers(expected int, timeout time.Duration) []PeerInfo {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries, _ := os.ReadDir("/peerinfo")
		var peers []PeerInfo
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".json") || strings.HasSuffix(e.Name(), ".result.json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join("/peerinfo", e.Name()))
			if err != nil {
				continue
			}
			var p PeerInfo
			if json.Unmarshal(data, &p) == nil && p.Role != "" {
				peers = append(peers, p)
			}
		}
		if len(peers) >= expected {
			return peers
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

func packetHandler(node *core.Core, logger *log.Logger) {
	buf := make([]byte, 65535)
	for {
		n, from, err := node.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 44 {
			continue
		}
		magic := string(buf[40:44])
		if magic == "ECHO" {
			reply := make([]byte, n)
			copy(reply, buf[:n])
			copy(reply[8:24], buf[24:40])
			copy(reply[24:40], buf[8:24])
			copy(reply[40:44], []byte("RPLY"))
			node.WriteTo(reply, from)
		} else if magic == "RPLY" && n >= 60 {
			var nonce [16]byte
			copy(nonce[:], buf[44:60])
			pendingMu.Lock()
			for i, p := range pending {
				if p.nonce == nonce {
					close(p.ch)
					pending = append(pending[:i], pending[i+1:]...)
					break
				}
			}
			pendingMu.Unlock()
		}
	}
}

func sendEcho(node *core.Core, destIP net.IP, timeout time.Duration) error {
	msg := make([]byte, 200)
	msg[0] = 0x60
	copy(msg[8:24], destIP.To16())
	copy(msg[24:40], node.Address().To16())
	copy(msg[40:44], []byte("ECHO"))
	var nonce [16]byte
	rand.Read(nonce[:])
	copy(msg[44:60], nonce[:])

	reply := &echoReply{nonce: nonce, ch: make(chan struct{})}
	pendingMu.Lock()
	pending = append(pending, reply)
	pendingMu.Unlock()

	defer func() {
		pendingMu.Lock()
		for i, p := range pending {
			if p == reply {
				pending = append(pending[:i], pending[i+1:]...)
				break
			}
		}
		pendingMu.Unlock()
	}()

	_, err := node.WriteTo(msg, &net.IPAddr{IP: destIP})
	if err != nil {
		return fmt.Errorf("WriteTo: %w", err)
	}

	select {
	case <-reply.ch:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout")
	}
}
