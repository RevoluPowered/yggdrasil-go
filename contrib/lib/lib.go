package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Log callback. level: 0=trace, 1=debug, 2=info, 3=warn, 4=error
typedef void (*ygg_log_callback)(const char* msg, int level);

static void call_log_cb(ygg_log_callback cb, const char* msg, int level) {
	if (cb) cb(msg, level);
}
*/
import "C"

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

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

// ---------------------------------------------------------------------------
// Handle map
// ---------------------------------------------------------------------------

type recvPacket struct {
	data []byte
	from net.Addr
}

type yggNode struct {
	core       *core.Core
	iprwc      *ipv6rwc.ReadWriteCloser
	iprwcOnce  sync.Once
	bgOnce     sync.Once
	dgBgOnce   sync.Once
	config     *config.NodeConfig
	multicast  *multicast.Multicast
	holepunch  *holepunch.HolePunch
	listener   *core.Listener // QUIC listener for incoming peer connections
	listenPort int            // actual bound port of the QUIC listener
	logger     *log.Logger
	recvCh     chan recvPacket // background reader feeds this (lazy, started by ygg_recv_from)
	dgRecvCh   chan recvPacket // datagram background reader feeds this
	recvBuf    []byte         // reusable buffer for ygg_recv (single caller: recv thread)
	ioModeLock sync.Mutex     // protects first-use choice between ipv6rwc vs core I/O
	ioMode     int            // 0=undecided, 1=ipv6rwc (ygg_send/ygg_recv), 2=core (ygg_send_to/ygg_recv_from)
	knownPeers sync.Map       // tracks keys we've received pathNotify for (core I/O mode)
}

var (
	handleMu  sync.RWMutex
	handleMap = make(map[C.int]*yggNode)
	nextID    int32
)

func newHandle(n *yggNode) C.int {
	h := C.int(atomic.AddInt32(&nextID, 1))
	handleMu.Lock()
	handleMap[h] = n
	handleMu.Unlock()
	return h
}

func getNode(h C.int) *yggNode {
	handleMu.RLock()
	n := handleMap[h]
	handleMu.RUnlock()
	return n
}

func removeHandle(h C.int) {
	handleMu.Lock()
	delete(handleMap, h)
	handleMu.Unlock()
}

// ---------------------------------------------------------------------------
// Error state
// ---------------------------------------------------------------------------

var (
	lastErrMu  sync.Mutex
	lastErrStr *C.char
)

func setLastError(err error) {
	lastErrMu.Lock()
	if lastErrStr != nil {
		C.free(unsafe.Pointer(lastErrStr))
		lastErrStr = nil
	}
	if err != nil {
		lastErrStr = C.CString(err.Error())
	}
	lastErrMu.Unlock()
}

//export ygg_last_error
func ygg_last_error() *C.char {
	lastErrMu.Lock()
	s := lastErrStr
	lastErrMu.Unlock()
	return s
}

// ---------------------------------------------------------------------------
// Logger adapter
// ---------------------------------------------------------------------------

type callbackWriter struct {
	cb    C.ygg_log_callback
	level C.int
}

func (w *callbackWriter) Write(p []byte) (int, error) {
	if w.cb == nil {
		return len(p), nil
	}
	cstr := C.CString(string(p))
	C.call_log_cb(w.cb, cstr, w.level)
	C.free(unsafe.Pointer(cstr))
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Client key injection
// ---------------------------------------------------------------------------

// injectClientKey appends the something.chat client key password to a peer URI.
// This ensures only something.chat nodes can complete the Yggdrasil handshake.
func injectClientKey(rawURI string) string {
	if rawURI == "" {
		return rawURI
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return rawURI
	}
	q := u.Query()
	if q.Get("password") == "" {
		q.Set("password", clientKey)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

//export ygg_start
func ygg_start(configJSON *C.char, logCb C.ygg_log_callback) C.int {
	node := &yggNode{}

	// Logger
	var logger *log.Logger
	if logCb != nil {
		logger = log.New(&callbackWriter{cb: logCb, level: 2}, "", 0)
	} else {
		logger = log.New(&callbackWriter{}, "", 0)
	}
	logger.EnableLevel("error")
	logger.EnableLevel("warn")
	logger.EnableLevel("info")
	node.logger = logger

	// Route Ironwood session trace logs through the same callback
	if logCb != nil {
		iwenc.SessionLogFunc = func(msg string) {
			cstr := C.CString(msg)
			C.call_log_cb(logCb, cstr, 0) // level 0 = trace
			C.free(unsafe.Pointer(cstr))
		}
	}

	// Config
	node.config = config.GenerateConfig()
	if err := node.config.UnmarshalHJSON([]byte(C.GoString(configJSON))); err != nil {
		setLastError(err)
		return -1
	}
	node.config.IfName = "none"

	// Inject client key into all configured peers, listeners, and multicast interfaces
	for i, peer := range node.config.Peers {
		node.config.Peers[i] = injectClientKey(peer)
	}
	for intf, peers := range node.config.InterfacePeers {
		for i, peer := range peers {
			node.config.InterfacePeers[intf][i] = injectClientKey(peer)
		}
	}
	for i, listen := range node.config.Listen {
		node.config.Listen[i] = injectClientKey(listen)
	}
	for i := range node.config.MulticastInterfaces {
		if node.config.MulticastInterfaces[i].Password == "" {
			node.config.MulticastInterfaces[i].Password = clientKey
		}
	}

	// Core options — mirrors contrib/mobile/mobile.go
	iprange := net.IPNet{
		IP:   net.ParseIP("200::"),
		Mask: net.CIDRMask(7, 128),
	}
	options := []core.SetupOption{
		core.PeerFilter(func(ip net.IP) bool {
			return !iprange.Contains(ip)
		}),
	}
	// Note: Peers are NOT added as core.Peer{} setup options because that
	// creates persistent links (linkTypePersistent) with exponential backoff.
	// Ironwood's encrypted session init through persistent links triggers a
	// 60-second sessionTimeout delay before data can flow. Instead, we use
	// CallPeer after core.New, which creates ephemeral links that establish
	// encrypted sessions immediately (~3 seconds for multi-hop chains).
	for _, allowed := range node.config.AllowedPublicKeys {
		k, err := hex.DecodeString(allowed)
		if err != nil {
			continue
		}
		options = append(options, core.AllowedPublicKey(k))
	}
	for _, lAddr := range node.config.Listen {
		options = append(options, core.ListenAddress(lAddr))
	}

	var err error
	node.core, err = core.New(node.config.Certificate, logger, options...)
	if err != nil {
		setLastError(err)
		return -1
	}

	// Connect to configured peers using CallPeer (ephemeral links).
	for _, peer := range node.config.Peers {
		u, err := url.Parse(peer)
		if err != nil {
			continue
		}
		if err := node.core.CallPeer(u, ""); err != nil {
			logger.Warnln("Failed to call peer", peer, err)
		}
	}
	for intf, peers := range node.config.InterfacePeers {
		for _, peer := range peers {
			u, err := url.Parse(peer)
			if err != nil {
				continue
			}
			if err := node.core.CallPeer(u, intf); err != nil {
				logger.Warnln("Failed to call peer", peer, err)
			}
		}
	}

	// Multicast
	if len(node.config.MulticastInterfaces) > 0 {
		var mcastOpts []multicast.SetupOption
		for _, intf := range node.config.MulticastInterfaces {
			mcastOpts = append(mcastOpts, multicast.MulticastInterface{
				Regex:    regexp.MustCompile(intf.Regex),
				Beacon:   intf.Beacon,
				Listen:   intf.Listen,
				Port:     intf.Port,
				Priority: uint8(intf.Priority),
				Password: intf.Password,
			})
		}
		node.multicast, _ = multicast.New(node.core, node.logger, mcastOpts...)
	}

	// Start QUIC listener for incoming peer connections
	listenURI, _ := url.Parse(injectClientKey("quic://[::]:0"))
	listener, err := node.core.Listen(listenURI, "")
	if err != nil {
		logger.Warnln("Failed to start QUIC listener:", err)
	} else {
		node.listener = listener
		_, portStr, _ := net.SplitHostPort(listener.Addr().String())
		node.listenPort, _ = strconv.Atoi(portStr)
		logger.Infof("QUIC listener on %s", listener.Addr())
	}

	// Hole punching (STUN + UPnP, uses Yggdrasil's listener port)
	hp, err := holepunch.New(logger, node.listenPort)
	if err != nil {
		logger.Warnln("Failed to initialize hole punching:", err)
	} else {
		node.holepunch = hp
		// Do an initial STUN discovery in the background.
		go func() {
			if result, err := hp.RefreshSTUN(); err != nil {
				logger.Warnln("STUN discovery failed:", err)
			} else {
				logger.Infof("STUN discovered public address: %s", result)
			}
		}()
	}

	// I/O mode is chosen lazily on first use:
	//   - ygg_send/ygg_recv use ipv6rwc (address-based, initialized by ensureIPRWC)
	//   - ygg_send_to/ygg_recv_from use core directly (key-based, bg reader started by ensureBgReader)
	// The two modes are mutually exclusive: ipv6rwc and the background reader
	// both call core.ReadFrom, so running both causes packets to be randomly
	// consumed by the wrong reader.
	node.recvCh = make(chan recvPacket, 256)

	setLastError(nil)
	return newHandle(node)
}

//export ygg_stop
func ygg_stop(handle C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	if node.holepunch != nil {
		_ = node.holepunch.Close()
	}
	if node.multicast != nil {
		_ = node.multicast.Stop()
	}
	node.core.Stop()
	removeHandle(handle)
	setLastError(nil)
	return 0
}

//export ygg_generate_config
func ygg_generate_config() *C.char {
	nc := config.GenerateConfig()
	nc.IfName = "none"
	j, err := json.Marshal(nc)
	if err != nil {
		setLastError(err)
		return nil
	}
	return C.CString(string(j))
}

// ---------------------------------------------------------------------------
// Packet I/O (IPv6-address-based, uses ipv6rwc layer)
// ---------------------------------------------------------------------------

// ensureIPRWC lazily initializes the ipv6rwc layer for ygg_send/ygg_recv.
// Must not be used after ensureBgReader has been called (the two modes are
// mutually exclusive because both call core.ReadFrom).
func ensureIPRWC(node *yggNode) {
	node.iprwcOnce.Do(func() {
		node.ioModeLock.Lock()
		defer node.ioModeLock.Unlock()
		if node.ioMode == 2 {
			panic("libyggdrasil: cannot use ygg_send/ygg_recv after ygg_recv_from")
		}
		node.ioMode = 1

		mtu := node.config.IfMTU
		node.iprwc = ipv6rwc.NewReadWriteCloser(node.core)
		if node.iprwc.MaxMTU() < mtu {
			mtu = node.iprwc.MaxMTU()
		}
		node.iprwc.SetMTU(mtu)
	})
}

// ensureBgReader lazily starts the background reader goroutine for
// ygg_recv_from / ygg_recv_from_timeout (key-based I/O).
// Must not be used after ensureIPRWC has been called.
func ensureBgReader(node *yggNode) {
	node.bgOnce.Do(func() {
		node.ioModeLock.Lock()
		defer node.ioModeLock.Unlock()
		if node.ioMode == 1 {
			panic("libyggdrasil: cannot use ygg_recv_from after ygg_send/ygg_recv")
		}
		node.ioMode = 2

		// Register path notification so we know when Ironwood discovers
		// a route. Keys in knownPeers skip the SendLookup in ygg_send_to.
		node.core.SetPathNotify(func(key ed25519.PublicKey) {
			node.knownPeers.Store(string(key), struct{}{})
		})

		go func() {
			buf := make([]byte, node.core.MTU())
			for {
				n, from, err := node.core.ReadFrom(buf)
				if err != nil {
					close(node.recvCh)
					return
				}
				if n == 0 {
					continue
				}
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				node.recvCh <- recvPacket{data: pkt, from: from}
			}
		}()
	})
}

//export ygg_send
func ygg_send(handle C.int, data unsafe.Pointer, length C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	ensureIPRWC(node)
	n, err := node.iprwc.Write(C.GoBytes(data, length))
	if err != nil {
		setLastError(err)
		return -1
	}
	return C.int(n)
}

//export ygg_recv
func ygg_recv(handle C.int, buf unsafe.Pointer, bufLen C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	ensureIPRWC(node)
	needed := int(bufLen)
	if len(node.recvBuf) < needed {
		node.recvBuf = make([]byte, needed)
	}
	n, err := node.iprwc.Read(node.recvBuf[:needed])
	if err != nil {
		setLastError(err)
		return -1
	}
	C.memcpy(buf, unsafe.Pointer(&node.recvBuf[0]), C.size_t(n))
	return C.int(n)
}

// ---------------------------------------------------------------------------
// Packet I/O (key-based, bypasses IPv6 address lookup)
// ---------------------------------------------------------------------------

//export ygg_send_to
func ygg_send_to(handle C.int, peerKeyHex *C.char, data unsafe.Pointer, length C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	// Ensure bg reader is running so core.ReadFrom processes session
	// init/ack messages needed for Ironwood session establishment.
	ensureBgReader(node)
	keyBytes, err := hex.DecodeString(C.GoString(peerKeyHex))
	if err != nil {
		setLastError(err)
		return -1
	}
	// Trigger Ironwood path discovery for destinations we haven't resolved yet.
	// Without this, WriteTo silently drops packets to multi-hop destinations
	// because Ironwood doesn't know the route. This replaces the SendLookup
	// that ipv6rwc performed internally via sendKeyLookup.
	if _, known := node.knownPeers.Load(string(keyBytes)); !known {
		node.core.SendLookup(keyBytes)
	}
	n, err := node.core.WriteTo(C.GoBytes(data, length), iwt.Addr(keyBytes))
	if err != nil {
		setLastError(err)
		return -1
	}
	return C.int(n)
}

//export ygg_recv_from
func ygg_recv_from(handle C.int, buf unsafe.Pointer, bufLen C.int, peerKeyHexOut *C.char, peerKeyHexOutLen C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	ensureBgReader(node)
	pkt, ok := <-node.recvCh
	if !ok {
		setLastError(fmt.Errorf("node stopped"))
		return -1
	}
	n := len(pkt.data)
	if n > int(bufLen) {
		n = int(bufLen)
	}
	C.memcpy(buf, unsafe.Pointer(&pkt.data[0]), C.size_t(n))
	// Write sender's public key hex into output buffer
	if peerKeyHexOut != nil && peerKeyHexOutLen > 0 {
		keyHex := hex.EncodeToString([]byte(pkt.from.(iwt.Addr)))
		outSlice := (*[1 << 30]byte)(unsafe.Pointer(peerKeyHexOut))[:int(peerKeyHexOutLen):int(peerKeyHexOutLen)]
		copied := copy(outSlice, keyHex)
		if copied < int(peerKeyHexOutLen) {
			outSlice[copied] = 0
		} else {
			outSlice[int(peerKeyHexOutLen)-1] = 0
		}
	}
	return C.int(n)
}

//export ygg_recv_from_timeout
func ygg_recv_from_timeout(handle C.int, buf unsafe.Pointer, bufLen C.int, peerKeyHexOut *C.char, peerKeyHexOutLen C.int, timeoutMs C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	ensureBgReader(node)
	var pkt recvPacket
	var ok bool
	if timeoutMs < 0 {
		// Negative timeout = block forever (same as ygg_recv_from)
		pkt, ok = <-node.recvCh
	} else {
		select {
		case pkt, ok = <-node.recvCh:
		case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
			setLastError(fmt.Errorf("recv timeout"))
			return -1
		}
	}
	if !ok {
		setLastError(fmt.Errorf("node stopped"))
		return -1
	}
	n := len(pkt.data)
	if n > int(bufLen) {
		n = int(bufLen)
	}
	C.memcpy(buf, unsafe.Pointer(&pkt.data[0]), C.size_t(n))
	if peerKeyHexOut != nil && peerKeyHexOutLen > 0 {
		keyHex := hex.EncodeToString([]byte(pkt.from.(iwt.Addr)))
		outSlice := (*[1 << 30]byte)(unsafe.Pointer(peerKeyHexOut))[:int(peerKeyHexOutLen):int(peerKeyHexOutLen)]
		copied := copy(outSlice, keyHex)
		if copied < int(peerKeyHexOutLen) {
			outSlice[copied] = 0
		} else {
			outSlice[int(peerKeyHexOutLen)-1] = 0
		}
	}
	return C.int(n)
}

// ---------------------------------------------------------------------------
// Unreliable datagram I/O (QUIC datagrams, direct peers only)
// ---------------------------------------------------------------------------

// ensureDgBgReader lazily starts the background datagram reader goroutine.
func ensureDgBgReader(node *yggNode) {
	node.dgBgOnce.Do(func() {
		node.dgRecvCh = make(chan recvPacket, 256)
		go func() {
			ch := node.core.ReceiveDatagrams()
			for {
				select {
				case pkt, ok := <-ch:
					if !ok {
						close(node.dgRecvCh)
						return
					}
					rp := recvPacket{
						data: pkt.Data,
						from: iwt.Addr(pkt.From[:]),
					}
					select {
					case node.dgRecvCh <- rp:
					default:
						// Drop: unreliable semantics
					}
				}
			}
		}()
	})
}

//export ygg_send_to_unreliable
func ygg_send_to_unreliable(handle C.int, peerKeyHex *C.char, data unsafe.Pointer, length C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	keyBytes, err := hex.DecodeString(C.GoString(peerKeyHex))
	if err != nil {
		setLastError(err)
		return -1
	}
	if err := node.core.SendDatagram(C.GoBytes(data, length), keyBytes); err != nil {
		setLastError(err)
		return -1
	}
	return C.int(length)
}

//export ygg_recv_from_unreliable
func ygg_recv_from_unreliable(handle C.int, buf unsafe.Pointer, bufLen C.int, peerKeyHexOut *C.char, peerKeyHexOutLen C.int, timeoutMs C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	ensureDgBgReader(node)
	var pkt recvPacket
	var ok bool
	if timeoutMs < 0 {
		pkt, ok = <-node.dgRecvCh
	} else if timeoutMs == 0 {
		select {
		case pkt, ok = <-node.dgRecvCh:
		default:
			return 0 // No data available (poll)
		}
	} else {
		select {
		case pkt, ok = <-node.dgRecvCh:
		case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
			return 0 // Timeout, no data
		}
	}
	if !ok {
		setLastError(fmt.Errorf("node stopped"))
		return -1
	}
	n := len(pkt.data)
	if n > int(bufLen) {
		n = int(bufLen)
	}
	C.memcpy(buf, unsafe.Pointer(&pkt.data[0]), C.size_t(n))
	if peerKeyHexOut != nil && peerKeyHexOutLen > 0 {
		keyHex := hex.EncodeToString([]byte(pkt.from.(iwt.Addr)))
		outSlice := (*[1 << 30]byte)(unsafe.Pointer(peerKeyHexOut))[:int(peerKeyHexOutLen):int(peerKeyHexOutLen)]
		copied := copy(outSlice, keyHex)
		if copied < int(peerKeyHexOutLen) {
			outSlice[copied] = 0
		} else {
			outSlice[int(peerKeyHexOutLen)-1] = 0
		}
	}
	return C.int(n)
}

//export ygg_has_datagram_support
func ygg_has_datagram_support(handle C.int, peerKeyHex *C.char) C.int {
	node := getNode(handle)
	if node == nil {
		return 0
	}
	keyBytes, err := hex.DecodeString(C.GoString(peerKeyHex))
	if err != nil {
		return 0
	}
	if node.core.HasDatagramSupport(keyBytes) {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Peer management
// ---------------------------------------------------------------------------

func parseSintf(sintf *C.char) string {
	if sintf == nil {
		return ""
	}
	return C.GoString(sintf)
}

//export ygg_add_peer
func ygg_add_peer(handle C.int, uri *C.char, sintf *C.char) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	u, err := url.Parse(injectClientKey(C.GoString(uri)))
	if err != nil {
		setLastError(err)
		return -1
	}
	if err := node.core.CallPeer(u, parseSintf(sintf)); err != nil {
		setLastError(err)
		return -1
	}
	setLastError(nil)
	return 0
}

//export ygg_remove_peer
func ygg_remove_peer(handle C.int, uri *C.char, sintf *C.char) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	u, err := url.Parse(C.GoString(uri))
	if err != nil {
		setLastError(err)
		return -1
	}
	if err := node.core.RemovePeer(u, parseSintf(sintf)); err != nil {
		setLastError(err)
		return -1
	}
	setLastError(nil)
	return 0
}

//export ygg_retry_peers_now
func ygg_retry_peers_now(handle C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	node.core.RetryPeersNow()
	return 0
}

// ---------------------------------------------------------------------------
// Listener management
// ---------------------------------------------------------------------------

//export ygg_listen
func ygg_listen(handle C.int, uri *C.char) *C.char {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return nil
	}
	u, err := url.Parse(injectClientKey(C.GoString(uri)))
	if err != nil {
		setLastError(err)
		return nil
	}
	listener, err := node.core.Listen(u, "")
	if err != nil {
		setLastError(err)
		return nil
	}
	// Return the URI with the actual assigned address/port
	actualURI := u.Scheme + "://" + listener.Addr().String()
	setLastError(nil)
	return C.CString(actualURI)
}

//export ygg_get_listen_uri
func ygg_get_listen_uri(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return nil
	}
	if node.listener == nil {
		return nil
	}
	uri := "quic://" + node.listener.Addr().String()
	setLastError(nil)
	return C.CString(uri)
}

//export ygg_stop_listen
func ygg_stop_listen(handle C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	if node.listener != nil {
		node.listener.Cancel()
		node.listener = nil
		node.listenPort = 0
	}
	// Also disable UPnP — no point mapping a closed port
	if node.holepunch != nil {
		node.holepunch.DisableUPnP()
	}
	setLastError(nil)
	return 0
}

// ---------------------------------------------------------------------------
// Node information
// ---------------------------------------------------------------------------

//export ygg_get_address
func ygg_get_address(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		return nil
	}
	return C.CString(node.core.Address().String())
}

//export ygg_get_subnet
func ygg_get_subnet(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		return nil
	}
	sn := node.core.Subnet()
	return C.CString(sn.String())
}

//export ygg_get_public_key
func ygg_get_public_key(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		return nil
	}
	return C.CString(hex.EncodeToString(node.core.PublicKey()))
}

// ygg_resolve_address looks up the public key hex for a given yggdrasil
// IPv6 address by searching the routing table (tree + peers).
// Returns nil if not found. Caller must free with ygg_free_string.
//
//export ygg_resolve_address
func ygg_resolve_address(handle C.int, ipv6Addr *C.char) *C.char {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return nil
	}
	target := net.ParseIP(C.GoString(ipv6Addr))
	if target == nil {
		setLastError(fmt.Errorf("invalid IPv6 address"))
		return nil
	}
	// Search tree entries
	for _, t := range node.core.GetTree() {
		if t.Key != nil {
			a := address.AddrForKey(t.Key)
			if net.IP(a[:]).Equal(target) {
				return C.CString(hex.EncodeToString(t.Key))
			}
		}
	}
	// Search peers
	for _, p := range node.core.GetPeers() {
		if p.Key != nil {
			a := address.AddrForKey(p.Key)
			if net.IP(a[:]).Equal(target) {
				return C.CString(hex.EncodeToString(p.Key))
			}
		}
	}
	setLastError(fmt.Errorf("address not found in routing table"))
	return nil
}

//export ygg_get_mtu
func ygg_get_mtu(handle C.int) C.int {
	node := getNode(handle)
	if node == nil {
		return 0
	}
	return C.int(node.core.MTU())
}

//export ygg_get_routing_entries
func ygg_get_routing_entries(handle C.int) C.int {
	node := getNode(handle)
	if node == nil {
		return 0
	}
	return C.int(node.core.GetSelf().RoutingEntries)
}

//export ygg_get_tree_entries
func ygg_get_tree_entries(handle C.int) C.int {
	node := getNode(handle)
	if node == nil {
		return 0
	}
	return C.int(len(node.core.GetTree()))
}

// ygg_has_route checks whether Ironwood has discovered a route to the given
// public key. Returns 1 if a route is known (knownPeers contains the key),
// 0 if not. This is useful for avoiding silent packet drops — ygg_send_to
// will silently drop packets when no route exists.
//
//export ygg_has_route
func ygg_has_route(handle C.int, peerKeyHex *C.char) C.int {
	node := getNode(handle)
	if node == nil {
		return 0
	}
	keyBytes, err := hex.DecodeString(C.GoString(peerKeyHex))
	if err != nil {
		return 0
	}
	if _, known := node.knownPeers.Load(string(keyBytes)); known {
		return 1
	}
	return 0
}

//export ygg_get_version
func ygg_get_version() *C.char {
	return C.CString(version.BuildVersion())
}

// ---------------------------------------------------------------------------
// Network state (JSON)
// ---------------------------------------------------------------------------

func marshalOrEmpty(v interface{}) *C.char {
	j, err := json.Marshal(v)
	if err != nil {
		return C.CString("{}")
	}
	return C.CString(string(j))
}

//export ygg_get_self_json
func ygg_get_self_json(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		return nil
	}
	self := node.core.GetSelf()
	res := struct {
		Key            string `json:"key"`
		RoutingEntries uint64 `json:"routing_entries"`
	}{
		Key:            hex.EncodeToString(self.Key),
		RoutingEntries: self.RoutingEntries,
	}
	return marshalOrEmpty(res)
}

//export ygg_get_peers_json
func ygg_get_peers_json(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		return nil
	}
	peers := []struct {
		core.PeerInfo
		IP     string
		KeyHex string
	}{}
	for _, v := range node.core.GetPeers() {
		var ip string
		var keyHex string
		if v.Key != nil {
			a := address.AddrForKey(v.Key)
			ip = net.IP(a[:]).String()
			keyHex = hex.EncodeToString(v.Key)
		}
		peers = append(peers, struct {
			core.PeerInfo
			IP     string
			KeyHex string
		}{PeerInfo: v, IP: ip, KeyHex: keyHex})
	}
	return marshalOrEmpty(peers)
}

//export ygg_get_paths_json
func ygg_get_paths_json(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		return nil
	}
	return marshalOrEmpty(node.core.GetPaths())
}

//export ygg_get_tree_json
func ygg_get_tree_json(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		return nil
	}
	return marshalOrEmpty(node.core.GetTree())
}

//export ygg_get_sessions_json
func ygg_get_sessions_json(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		return nil
	}
	return marshalOrEmpty(node.core.GetSessions())
}

// ---------------------------------------------------------------------------
// Configuration utilities
// ---------------------------------------------------------------------------

//export ygg_config_summary
func ygg_config_summary(configJSON *C.char) *C.char {
	cfg := config.GenerateConfig()
	if err := cfg.UnmarshalHJSON([]byte(C.GoString(configJSON))); err != nil {
		setLastError(err)
		return nil
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
	return marshalOrEmpty(res)
}

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

//export ygg_free_string
func ygg_free_string(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// ---------------------------------------------------------------------------
// AllowedPublicKeys management
// ---------------------------------------------------------------------------

//export ygg_allow_public_key
func ygg_allow_public_key(handle C.int, keyHex *C.char) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	keyBytes, err := hex.DecodeString(C.GoString(keyHex))
	if err != nil {
		setLastError(err)
		return -1
	}
	node.core.AllowPublicKey(keyBytes)
	setLastError(nil)
	return 0
}

//export ygg_disallow_public_key
func ygg_disallow_public_key(handle C.int, keyHex *C.char) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	keyBytes, err := hex.DecodeString(C.GoString(keyHex))
	if err != nil {
		setLastError(err)
		return -1
	}
	node.core.DisallowPublicKey(keyBytes)
	setLastError(nil)
	return 0
}

// ---------------------------------------------------------------------------
// Hole punching
// ---------------------------------------------------------------------------

//export ygg_refresh_stun
func ygg_refresh_stun(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return nil
	}
	if node.holepunch == nil {
		setLastError(fmt.Errorf("holepunch not initialized"))
		return nil
	}
	result, err := node.holepunch.RefreshSTUN()
	if err != nil {
		setLastError(err)
		return nil
	}
	setLastError(nil)
	return C.CString(result.String())
}

//export ygg_get_candidates_json
func ygg_get_candidates_json(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return nil
	}
	if node.holepunch == nil {
		setLastError(fmt.Errorf("holepunch not initialized"))
		return nil
	}
	candidates := node.holepunch.GetCandidates()
	data, err := holepunch.MarshalCandidates(candidates)
	if err != nil {
		setLastError(err)
		return nil
	}
	setLastError(nil)
	return C.CString(data)
}

//export ygg_enable_upnp
func ygg_enable_upnp(handle C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	if node.holepunch == nil {
		setLastError(fmt.Errorf("holepunch not initialized"))
		return -1
	}
	if err := node.holepunch.EnableUPnP(); err != nil {
		setLastError(err)
		return -1
	}
	setLastError(nil)
	if node.holepunch.UPnPEnabled() {
		return 1 // mapping active
	}
	return 0 // no gateway found, not an error
}

//export ygg_disable_upnp
func ygg_disable_upnp(handle C.int) C.int {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return -1
	}
	if node.holepunch == nil {
		setLastError(fmt.Errorf("holepunch not initialized"))
		return -1
	}
	node.holepunch.DisableUPnP()
	setLastError(nil)
	return 0
}

//export ygg_get_external_uri
func ygg_get_external_uri(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return nil
	}
	if node.holepunch == nil {
		setLastError(fmt.Errorf("holepunch not initialized"))
		return nil
	}
	uri := node.holepunch.ExternalURI()
	setLastError(nil)
	if uri == "" {
		return nil
	}
	return C.CString(uri)
}

//export ygg_detect_nat
func ygg_detect_nat(handle C.int) *C.char {
	node := getNode(handle)
	if node == nil {
		setLastError(fmt.Errorf("invalid handle"))
		return nil
	}
	if node.holepunch == nil {
		setLastError(fmt.Errorf("holepunch not initialized"))
		return nil
	}
	info := node.holepunch.DetectNAT()
	result := map[string]interface{}{
		"type":    string(info.Type),
		"details": info.Details,
	}
	if info.PublicAddr != nil {
		result["publicAddr"] = info.PublicAddr.String()
	}
	data, err := json.Marshal(result)
	if err != nil {
		setLastError(err)
		return nil
	}
	setLastError(nil)
	return C.CString(string(data))
}

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

//export ygg_noop
func ygg_noop() {
	// Intentionally empty. Measures bare CGo call overhead.
}

//export ygg_noop_with_data
func ygg_noop_with_data(data unsafe.Pointer, length C.int) {
	// Access the data to prevent the compiler from optimizing the call away.
	// This measures CGo overhead when passing a data pointer of arbitrary size.
	if length > 0 {
		_ = C.GoBytes(data, length)
	}
}

// ---------------------------------------------------------------------------
// Required for c-shared / c-archive
// ---------------------------------------------------------------------------

func main() {}
