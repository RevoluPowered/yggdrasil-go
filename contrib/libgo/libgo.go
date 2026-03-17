package libgo

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	iwenc "github.com/Arceliar/ironwood/encrypted"
	iwt "github.com/Arceliar/ironwood/types"
	"github.com/gologme/log"

	"github.com/yggdrasil-network/yggdrasil-go/contrib/lib/holepunch"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"
	"github.com/yggdrasil-network/yggdrasil-go/src/version"
)

// ClientKey is the network segmentation password. Tests override this
// to isolate test nodes from the production network.
var ClientKey = "somethingchat-v1-k8x2mQ9pLwR7nTfY3hBvJ6dA"

type RecvPacket struct {
	Data []byte
	From net.Addr
}

type Node struct {
	Core        *core.Core
	Iprwc       *ipv6rwc.ReadWriteCloser
	iprwcOnce   sync.Once
	bgOnce      sync.Once
	dgBgOnce    sync.Once
	Config      *config.NodeConfig
	Multicast   *multicast.Multicast
	Holepunch   *holepunch.HolePunch
	Listener    *core.Listener
	TLSListener *core.Listener
	ListenPort  int
	Logger      *log.Logger
	RecvCh      chan RecvPacket
	dgRecvCh    chan RecvPacket
	recvBuf     []byte
	ioModeLock  sync.Mutex
	ioMode      int
	KnownPeers  sync.Map
}

type LogCallback func(msg string, level int)

// Handle map
var (
	handleMu  sync.RWMutex
	handleMap = make(map[int32]*Node)
	nextID    int32
)

func newHandle(n *Node) int32 {
	h := atomic.AddInt32(&nextID, 1)
	handleMu.Lock()
	handleMap[h] = n
	handleMu.Unlock()
	return h
}

func GetNode(h int32) *Node {
	handleMu.RLock()
	n := handleMap[h]
	handleMu.RUnlock()
	return n
}

func removeHandle(h int32) {
	handleMu.Lock()
	delete(handleMap, h)
	handleMu.Unlock()
}

// Error state
var (
	lastErrMu sync.Mutex
	lastErr   error
)

func setLastError(err error) {
	lastErrMu.Lock()
	lastErr = err
	lastErrMu.Unlock()
}

func LastError() error {
	lastErrMu.Lock()
	e := lastErr
	lastErrMu.Unlock()
	return e
}

// Logger adapter
type callbackWriter struct {
	cb    LogCallback
	level int
}

func (w *callbackWriter) Write(p []byte) (int, error) {
	if w.cb != nil {
		w.cb(string(p), w.level)
	}
	return len(p), nil
}

// Client key injection
func InjectClientKey(rawURI string) string {
	if rawURI == "" {
		return rawURI
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return rawURI
	}
	q := u.Query()
	if q.Get("password") == "" {
		q.Set("password", ClientKey)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// Crash log
var crashLogFile *os.File

func SetCrashLog(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	crashLogFile = f
	debug.SetTraceback("system")
	return nil
}

// --- Lifecycle ---

func Start(configJSON string, logCb LogCallback) (int32, error) {
	node := &Node{}

	var logger *log.Logger
	if logCb != nil {
		logger = log.New(&callbackWriter{cb: logCb, level: 2}, "", 0)
	} else {
		logger = log.New(&callbackWriter{}, "", 0)
	}
	logger.EnableLevel("error")
	logger.EnableLevel("warn")
	logger.EnableLevel("info")
	node.Logger = logger

	if logCb != nil {
		iwenc.SessionLogFunc = func(msg string) {
			logCb(msg, 0)
		}
	}

	node.Config = config.GenerateConfig()
	if err := node.Config.UnmarshalHJSON([]byte(configJSON)); err != nil {
		return -1, err
	}
	node.Config.IfName = "none"

	for i, peer := range node.Config.Peers {
		node.Config.Peers[i] = InjectClientKey(peer)
	}
	for intf, peers := range node.Config.InterfacePeers {
		for i, peer := range peers {
			node.Config.InterfacePeers[intf][i] = InjectClientKey(peer)
		}
	}
	for i, listen := range node.Config.Listen {
		node.Config.Listen[i] = InjectClientKey(listen)
	}
	for i := range node.Config.MulticastInterfaces {
		if node.Config.MulticastInterfaces[i].Password == "" {
			node.Config.MulticastInterfaces[i].Password = ClientKey
		}
	}

	iprange := net.IPNet{
		IP:   net.ParseIP("200::"),
		Mask: net.CIDRMask(7, 128),
	}
	options := []core.SetupOption{
		core.PeerFilter(func(ip net.IP) bool {
			return !iprange.Contains(ip)
		}),
	}
	for _, allowed := range node.Config.AllowedPublicKeys {
		k, err := hex.DecodeString(allowed)
		if err != nil {
			continue
		}
		options = append(options, core.AllowedPublicKey(k))
	}
	for _, lAddr := range node.Config.Listen {
		options = append(options, core.ListenAddress(lAddr))
	}

	var err error
	node.Core, err = core.New(node.Config.Certificate, logger, options...)
	if err != nil {
		return -1, err
	}

	for _, peer := range node.Config.Peers {
		u, err := url.Parse(peer)
		if err != nil {
			continue
		}
		if err := node.Core.CallPeer(u, ""); err != nil {
			logger.Warnln("Failed to call peer", peer, err)
		}
	}
	for intf, peers := range node.Config.InterfacePeers {
		for _, peer := range peers {
			u, err := url.Parse(peer)
			if err != nil {
				continue
			}
			if err := node.Core.CallPeer(u, intf); err != nil {
				logger.Warnln("Failed to call peer", peer, err)
			}
		}
	}

	if len(node.Config.MulticastInterfaces) > 0 {
		var mcastOpts []multicast.SetupOption
		for _, intf := range node.Config.MulticastInterfaces {
			mcastOpts = append(mcastOpts, multicast.MulticastInterface{
				Regex:    regexp.MustCompile(intf.Regex),
				Beacon:   intf.Beacon,
				Listen:   intf.Listen,
				Port:     intf.Port,
				Priority: uint8(intf.Priority),
				Password: intf.Password,
			})
		}
		node.Multicast, _ = multicast.New(node.Core, node.Logger, mcastOpts...)
	}

	// QUIC listener — try 27000-28000 range
	var listener *core.Listener
	for port := 27000; port <= 28000; port++ {
		uri, _ := url.Parse(InjectClientKey(fmt.Sprintf("quic://[::]:%d", port)))
		l, err := node.Core.Listen(uri, "")
		if err == nil {
			listener = l
			break
		}
	}
	if listener == nil {
		fallbackURI, _ := url.Parse(InjectClientKey("quic://[::]:0"))
		listener, err = node.Core.Listen(fallbackURI, "")
		if err != nil {
			logger.Warnln("Failed to start QUIC listener:", err)
		}
	}
	if listener != nil {
		node.Listener = listener
		_, portStr, _ := net.SplitHostPort(listener.Addr().String())
		node.ListenPort, _ = strconv.Atoi(portStr)
		logger.Infof("QUIC listener on %s", listener.Addr())
	}

	// TLS listener on same port
	if node.ListenPort > 0 {
		tlsURI, _ := url.Parse(InjectClientKey(fmt.Sprintf("tls://[::]:%d", node.ListenPort)))
		tlsListener, err := node.Core.Listen(tlsURI, "")
		if err != nil {
			logger.Warnln("Failed to start TLS listener:", err)
		} else {
			node.TLSListener = tlsListener
			logger.Infof("TLS listener on %s", tlsListener.Addr())
		}
	}

	// Hole punching
	hp, err := holepunch.New(logger, node.ListenPort)
	if err != nil {
		logger.Warnln("Failed to initialize hole punching:", err)
	} else {
		node.Holepunch = hp
		go func() {
			if result, err := hp.RefreshSTUN(); err != nil {
				logger.Warnln("STUN discovery failed:", err)
			} else {
				logger.Infof("STUN discovered public address: %s", result)
			}
		}()
	}

	node.RecvCh = make(chan RecvPacket, 256)

	setLastError(nil)
	return newHandle(node), nil
}

func Stop(handle int32) error {
	node := GetNode(handle)
	if node == nil {
		return fmt.Errorf("invalid handle")
	}
	if node.Holepunch != nil {
		_ = node.Holepunch.Close()
	}
	if node.Multicast != nil {
		_ = node.Multicast.Stop()
	}
	node.Core.Stop()
	removeHandle(handle)
	setLastError(nil)
	return nil
}

func GenerateConfig() (string, error) {
	nc := config.GenerateConfig()
	nc.IfName = "none"
	j, err := json.Marshal(nc)
	if err != nil {
		return "", err
	}
	return string(j), nil
}

// --- I/O mode helpers ---

func ensureIPRWC(node *Node) {
	node.iprwcOnce.Do(func() {
		node.ioModeLock.Lock()
		defer node.ioModeLock.Unlock()
		if node.ioMode == 2 {
			panic("libgo: cannot use Send/Recv after RecvFrom")
		}
		node.ioMode = 1
		mtu := node.Config.IfMTU
		node.Iprwc = ipv6rwc.NewReadWriteCloser(node.Core)
		if node.Iprwc.MaxMTU() < mtu {
			mtu = node.Iprwc.MaxMTU()
		}
		node.Iprwc.SetMTU(mtu)
	})
}

func ensureBgReader(node *Node) {
	node.bgOnce.Do(func() {
		node.ioModeLock.Lock()
		defer node.ioModeLock.Unlock()
		if node.ioMode == 1 {
			panic("libgo: cannot use RecvFrom after Send/Recv")
		}
		node.ioMode = 2
		node.Core.SetPathNotify(func(key ed25519.PublicKey) {
			node.KnownPeers.Store(string(key), struct{}{})
		})
		go func() {
			buf := make([]byte, node.Core.MTU())
			for {
				n, from, err := node.Core.ReadFrom(buf)
				if err != nil {
					close(node.RecvCh)
					return
				}
				if n == 0 {
					continue
				}
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				node.RecvCh <- RecvPacket{Data: pkt, From: from}
			}
		}()
	})
}

func ensureDgBgReader(node *Node) {
	node.dgBgOnce.Do(func() {
		node.dgRecvCh = make(chan RecvPacket, 256)
		go func() {
			ch := node.Core.ReceiveDatagrams()
			for pkt := range ch {
				rp := RecvPacket{
					Data: pkt.Data,
					From: iwt.Addr(pkt.From[:]),
				}
				select {
				case node.dgRecvCh <- rp:
				default:
				}
			}
			close(node.dgRecvCh)
		}()
	})
}

// --- Packet I/O (IPv6-address-based) ---

func Send(handle int32, data []byte) (int, error) {
	node := GetNode(handle)
	if node == nil {
		return -1, fmt.Errorf("invalid handle")
	}
	ensureIPRWC(node)
	n, err := node.Iprwc.Write(data)
	if err != nil {
		setLastError(err)
		return -1, err
	}
	return n, nil
}

func Recv(handle int32, bufLen int) ([]byte, error) {
	node := GetNode(handle)
	if node == nil {
		return nil, fmt.Errorf("invalid handle")
	}
	ensureIPRWC(node)
	if len(node.recvBuf) < bufLen {
		node.recvBuf = make([]byte, bufLen)
	}
	n, err := node.Iprwc.Read(node.recvBuf[:bufLen])
	if err != nil {
		setLastError(err)
		return nil, err
	}
	result := make([]byte, n)
	copy(result, node.recvBuf[:n])
	return result, nil
}

// --- Packet I/O (key-based) ---

func SendTo(handle int32, peerKeyHex string, data []byte) (int, error) {
	node := GetNode(handle)
	if node == nil {
		return -1, fmt.Errorf("invalid handle")
	}
	ensureBgReader(node)
	keyBytes, err := hex.DecodeString(peerKeyHex)
	if err != nil {
		setLastError(err)
		return -1, err
	}
	if _, known := node.KnownPeers.Load(string(keyBytes)); !known {
		node.Core.SendLookup(keyBytes)
	}
	n, err := node.Core.WriteTo(data, iwt.Addr(keyBytes))
	if err != nil {
		setLastError(err)
		return -1, err
	}
	return n, nil
}

func RecvFrom(handle int32) ([]byte, string, error) {
	node := GetNode(handle)
	if node == nil {
		return nil, "", fmt.Errorf("invalid handle")
	}
	ensureBgReader(node)
	pkt, ok := <-node.RecvCh
	if !ok {
		return nil, "", fmt.Errorf("node stopped")
	}
	keyHex := hex.EncodeToString([]byte(pkt.From.(iwt.Addr)))
	return pkt.Data, keyHex, nil
}

func RecvFromTimeout(handle int32, timeoutMs int) ([]byte, string, error) {
	node := GetNode(handle)
	if node == nil {
		return nil, "", fmt.Errorf("invalid handle")
	}
	ensureBgReader(node)
	var pkt RecvPacket
	var ok bool
	if timeoutMs < 0 {
		pkt, ok = <-node.RecvCh
	} else {
		select {
		case pkt, ok = <-node.RecvCh:
		case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
			return nil, "", fmt.Errorf("recv timeout")
		}
	}
	if !ok {
		return nil, "", fmt.Errorf("node stopped")
	}
	keyHex := hex.EncodeToString([]byte(pkt.From.(iwt.Addr)))
	return pkt.Data, keyHex, nil
}

// --- Unreliable datagram I/O ---

func SendToUnreliable(handle int32, peerKeyHex string, data []byte) (int, error) {
	node := GetNode(handle)
	if node == nil {
		return -1, fmt.Errorf("invalid handle")
	}
	keyBytes, err := hex.DecodeString(peerKeyHex)
	if err != nil {
		return -1, err
	}
	if err := node.Core.SendDatagram(data, keyBytes); err != nil {
		setLastError(err)
		return -1, err
	}
	return len(data), nil
}

func RecvFromUnreliable(handle int32, timeoutMs int) ([]byte, string, error) {
	node := GetNode(handle)
	if node == nil {
		return nil, "", fmt.Errorf("invalid handle")
	}
	ensureDgBgReader(node)
	var pkt RecvPacket
	var ok bool
	if timeoutMs < 0 {
		pkt, ok = <-node.dgRecvCh
	} else if timeoutMs == 0 {
		select {
		case pkt, ok = <-node.dgRecvCh:
		default:
			return nil, "", nil // no data (poll)
		}
	} else {
		select {
		case pkt, ok = <-node.dgRecvCh:
		case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
			return nil, "", nil // timeout
		}
	}
	if !ok {
		return nil, "", fmt.Errorf("node stopped")
	}
	keyHex := hex.EncodeToString([]byte(pkt.From.(iwt.Addr)))
	return pkt.Data, keyHex, nil
}

func HasDatagramSupport(handle int32, peerKeyHex string) bool {
	node := GetNode(handle)
	if node == nil {
		return false
	}
	keyBytes, err := hex.DecodeString(peerKeyHex)
	if err != nil {
		return false
	}
	return node.Core.HasDatagramSupport(keyBytes)
}

// --- Peer management ---

func AddPeer(handle int32, uri string, sintf string) error {
	node := GetNode(handle)
	if node == nil {
		return fmt.Errorf("invalid handle")
	}
	u, err := url.Parse(InjectClientKey(uri))
	if err != nil {
		return err
	}
	if err := node.Core.CallPeer(u, sintf); err != nil {
		setLastError(err)
		return err
	}
	setLastError(nil)
	return nil
}

func RemovePeer(handle int32, uri string, sintf string) error {
	node := GetNode(handle)
	if node == nil {
		return fmt.Errorf("invalid handle")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}
	if err := node.Core.RemovePeer(u, sintf); err != nil {
		setLastError(err)
		return err
	}
	setLastError(nil)
	return nil
}

func RetryPeersNow(handle int32) error {
	node := GetNode(handle)
	if node == nil {
		return fmt.Errorf("invalid handle")
	}
	node.Core.RetryPeersNow()
	return nil
}

// --- Listener management ---

func Listen(handle int32, uri string) (string, error) {
	node := GetNode(handle)
	if node == nil {
		return "", fmt.Errorf("invalid handle")
	}
	u, err := url.Parse(InjectClientKey(uri))
	if err != nil {
		return "", err
	}
	listener, err := node.Core.Listen(u, "")
	if err != nil {
		return "", err
	}
	actualURI := u.Scheme + "://" + listener.Addr().String()
	setLastError(nil)
	return actualURI, nil
}

func GetListenURI(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	if node.Listener == nil {
		return ""
	}
	return "quic://" + node.Listener.Addr().String()
}

func StopListen(handle int32) error {
	node := GetNode(handle)
	if node == nil {
		return fmt.Errorf("invalid handle")
	}
	if node.Listener != nil {
		node.Listener.Cancel()
		node.Listener = nil
		node.ListenPort = 0
	}
	if node.Holepunch != nil {
		node.Holepunch.DisableUPnP()
	}
	setLastError(nil)
	return nil
}

// --- Node information ---

func GetAddress(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	return node.Core.Address().String()
}

func GetSubnet(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	sn := node.Core.Subnet()
	return sn.String()
}

func GetPublicKey(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	return hex.EncodeToString(node.Core.PublicKey())
}

func ResolveAddress(handle int32, ipv6Addr string) (string, error) {
	node := GetNode(handle)
	if node == nil {
		return "", fmt.Errorf("invalid handle")
	}
	target := net.ParseIP(ipv6Addr)
	if target == nil {
		return "", fmt.Errorf("invalid IPv6 address")
	}
	for _, t := range node.Core.GetTree() {
		if t.Key != nil {
			a := address.AddrForKey(t.Key)
			if net.IP(a[:]).Equal(target) {
				return hex.EncodeToString(t.Key), nil
			}
		}
	}
	for _, p := range node.Core.GetPeers() {
		if p.Key != nil {
			a := address.AddrForKey(p.Key)
			if net.IP(a[:]).Equal(target) {
				return hex.EncodeToString(p.Key), nil
			}
		}
	}
	return "", fmt.Errorf("address not found in routing table")
}

func GetMTU(handle int32) int {
	node := GetNode(handle)
	if node == nil {
		return 0
	}
	return int(node.Core.MTU())
}

func GetRoutingEntries(handle int32) int {
	node := GetNode(handle)
	if node == nil {
		return 0
	}
	return int(node.Core.GetSelf().RoutingEntries)
}

func GetTreeEntries(handle int32) int {
	node := GetNode(handle)
	if node == nil {
		return 0
	}
	return len(node.Core.GetTree())
}

func HasRoute(handle int32, peerKeyHex string) bool {
	node := GetNode(handle)
	if node == nil {
		return false
	}
	keyBytes, err := hex.DecodeString(peerKeyHex)
	if err != nil {
		return false
	}
	_, known := node.KnownPeers.Load(string(keyBytes))
	return known
}

func GetVersion() string {
	return version.BuildVersion()
}

// --- Network state (JSON) ---

func GetSelfJSON(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	self := node.Core.GetSelf()
	res := struct {
		Key            string `json:"key"`
		RoutingEntries uint64 `json:"routing_entries"`
	}{
		Key:            hex.EncodeToString(self.Key),
		RoutingEntries: self.RoutingEntries,
	}
	j, _ := json.Marshal(res)
	return string(j)
}

func GetPeersJSON(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	type peerEntry struct {
		core.PeerInfo
		IP        string `json:"IP"`
		KeyHex    string `json:"KeyHex"`
		Transport string `json:"Transport"` // "quic", "tls", or "tcp"
	}
	var peers []peerEntry
	for _, v := range node.Core.GetPeers() {
		var ip, keyHex, transport string
		if v.Key != nil {
			a := address.AddrForKey(v.Key)
			ip = net.IP(a[:]).String()
			keyHex = hex.EncodeToString(v.Key)
		}
		if strings.HasPrefix(v.URI, "quic://") {
			transport = "quic"
		} else if strings.HasPrefix(v.URI, "tls://") {
			transport = "tls"
		} else if strings.HasPrefix(v.URI, "tcp://") {
			transport = "tcp"
		}
		peers = append(peers, peerEntry{PeerInfo: v, IP: ip, KeyHex: keyHex, Transport: transport})
	}
	j, _ := json.Marshal(peers)
	return string(j)
}

func GetPathsJSON(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	j, _ := json.Marshal(node.Core.GetPaths())
	return string(j)
}

func GetTreeJSON(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	j, _ := json.Marshal(node.Core.GetTree())
	return string(j)
}

func GetSessionsJSON(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	j, _ := json.Marshal(node.Core.GetSessions())
	return string(j)
}

// --- Configuration utilities ---

func ConfigSummary(configJSON string) (string, error) {
	cfg := config.GenerateConfig()
	if err := cfg.UnmarshalHJSON([]byte(configJSON)); err != nil {
		return "", err
	}
	pub := ed25519.PrivateKey(cfg.PrivateKey).Public().(ed25519.PublicKey)
	addr := net.IP(address.AddrForKey(pub)[:])
	snet := net.IPNet{
		IP:   append(address.SubnetForKey(pub)[:], 0, 0, 0, 0, 0, 0, 0, 0),
		Mask: net.CIDRMask(64, 128),
	}
	res := struct {
		PublicKey   string `json:"public_key"`
		IPv6Address string `json:"ipv6_address"`
		IPv6Subnet  string `json:"ipv6_subnet"`
	}{
		PublicKey:   hex.EncodeToString(pub),
		IPv6Address: addr.String(),
		IPv6Subnet:  snet.String(),
	}
	j, _ := json.Marshal(res)
	return string(j), nil
}

// --- AllowedPublicKeys ---

func AllowPublicKey(handle int32, keyHex string) error {
	node := GetNode(handle)
	if node == nil {
		return fmt.Errorf("invalid handle")
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return err
	}
	node.Core.AllowPublicKey(keyBytes)
	setLastError(nil)
	return nil
}

func DisallowPublicKey(handle int32, keyHex string) error {
	node := GetNode(handle)
	if node == nil {
		return fmt.Errorf("invalid handle")
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return err
	}
	node.Core.DisallowPublicKey(keyBytes)
	setLastError(nil)
	return nil
}

// --- Hole punching ---

func RefreshSTUN(handle int32) (string, error) {
	node := GetNode(handle)
	if node == nil {
		return "", fmt.Errorf("invalid handle")
	}
	if node.Holepunch == nil {
		return "", fmt.Errorf("holepunch not initialized")
	}
	result, err := node.Holepunch.RefreshSTUN()
	if err != nil {
		return "", err
	}
	setLastError(nil)
	return result.String(), nil
}

func GetCandidatesJSON(handle int32) (string, error) {
	node := GetNode(handle)
	if node == nil {
		return "", fmt.Errorf("invalid handle")
	}
	if node.Holepunch == nil {
		return "", fmt.Errorf("holepunch not initialized")
	}
	candidates := node.Holepunch.GetCandidates()
	data, err := holepunch.MarshalCandidates(candidates)
	if err != nil {
		return "", err
	}
	setLastError(nil)
	return data, nil
}

func EnableUPnP(handle int32) (int, error) {
	node := GetNode(handle)
	if node == nil {
		return -1, fmt.Errorf("invalid handle")
	}
	if node.Holepunch == nil {
		return -1, fmt.Errorf("holepunch not initialized")
	}
	if err := node.Holepunch.EnableUPnP(); err != nil {
		return -1, err
	}
	setLastError(nil)
	if node.Holepunch.UPnPEnabled() {
		return 1, nil
	}
	return 0, nil
}

func DisableUPnP(handle int32) error {
	node := GetNode(handle)
	if node == nil {
		return fmt.Errorf("invalid handle")
	}
	if node.Holepunch == nil {
		return fmt.Errorf("holepunch not initialized")
	}
	node.Holepunch.DisableUPnP()
	setLastError(nil)
	return nil
}

func GetExternalURI(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	if node.Holepunch == nil {
		return ""
	}
	return node.Holepunch.ExternalURI()
}

func GetExternalTLSURI(handle int32) string {
	node := GetNode(handle)
	if node == nil {
		return ""
	}
	if node.Holepunch == nil {
		return ""
	}
	return node.Holepunch.ExternalTLSURI()
}

func DetectNAT(handle int32) (string, error) {
	node := GetNode(handle)
	if node == nil {
		return "", fmt.Errorf("invalid handle")
	}
	if node.Holepunch == nil {
		return "", fmt.Errorf("holepunch not initialized")
	}
	info := node.Holepunch.DetectNAT()
	result := map[string]interface{}{
		"type":    string(info.Type),
		"details": info.Details,
	}
	if info.PublicAddr != nil {
		result["publicAddr"] = info.PublicAddr.String()
	}
	j, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	setLastError(nil)
	return string(j), nil
}

// --- Noop (benchmark helpers) ---

func Noop() {}

func NoopWithData(data []byte) {
	_ = data
}
