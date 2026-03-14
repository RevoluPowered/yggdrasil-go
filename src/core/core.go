package core

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	iwe "github.com/Arceliar/ironwood/encrypted"
	iwn "github.com/Arceliar/ironwood/network"
	iwt "github.com/Arceliar/ironwood/types"
	"github.com/Arceliar/phony"
	"github.com/gologme/log"
	"github.com/quic-go/quic-go"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/version"
)

// The Core object represents the Yggdrasil node. You should create a Core
// object for each Yggdrasil node you plan to run.
type Core struct {
	// This is the main data structure that holds everything else for a node
	// We're going to keep our own copy of the provided config - that way we can
	// guarantee that it will be covered by the mutex
	phony.Inbox
	*iwe.PacketConn
	ctx    context.Context
	cancel context.CancelFunc
	secret ed25519.PrivateKey
	public ed25519.PublicKey
	links  links
	proto  protoHandler
	log    Logger
	config struct {
		tls *tls.Config // immutable after startup
		//_peers             map[Peer]*linkInfo         // configurable after startup
		_listeners         map[ListenAddress]struct{} // configurable after startup
		peerFilter         func(ip net.IP) bool       // immutable after startup
		nodeinfo           NodeInfo                   // immutable after startup
		nodeinfoPrivacy    NodeInfoPrivacy            // immutable after startup
		_allowedPublicKeys map[[32]byte]struct{}      // configurable after startup
	}
	pathNotify func(ed25519.PublicKey)
	dgram struct {
		sync.RWMutex
		conns   map[keyArray]*quic.Conn
		frags   map[keyArray]*dgFragmenter
		reasm   *dgReassembler
		recvCh  chan DatagramPacket
	}
}

// DatagramPacket is an unreliable datagram received from a direct QUIC peer.
type DatagramPacket struct {
	Data []byte
	From keyArray
}

// ErrDatagramNoPeer is returned when the target peer has no datagram-capable connection.
var ErrDatagramNoPeer = errors.New("peer not connected via QUIC datagrams")

func New(cert *tls.Certificate, logger Logger, opts ...SetupOption) (*Core, error) {
	c := &Core{
		log: logger,
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if c.log == nil {
		c.log = log.New(io.Discard, "", 0)
	}

	if name := version.BuildName(); name != "unknown" {
		c.log.Infoln("Build name:", name)
	}
	if version := version.BuildVersion(); version != "unknown" {
		c.log.Infoln("Build version:", version)
	}

	var err error
	c.config._listeners = map[ListenAddress]struct{}{}
	c.config._allowedPublicKeys = map[[32]byte]struct{}{}
	for _, opt := range opts {
		switch opt.(type) {
		case Peer, ListenAddress:
			// We can't do peers yet as the links aren't set up.
			continue
		default:
			if err = c._applyOption(opt); err != nil {
				return nil, fmt.Errorf("failed to apply configuration option %T: %w", opt, err)
			}
		}
	}
	if cert == nil || cert.PrivateKey == nil {
		return nil, fmt.Errorf("no private key supplied")
	}
	var ok bool
	if c.secret, ok = cert.PrivateKey.(ed25519.PrivateKey); !ok {
		return nil, fmt.Errorf("private key must be ed25519")
	}
	if len(c.secret) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key is incorrect length")
	}
	c.public = c.secret.Public().(ed25519.PublicKey)

	if c.config.tls, err = c.generateTLSConfig(cert); err != nil {
		return nil, fmt.Errorf("error generating TLS config: %w", err)
	}
	keyXform := func(key ed25519.PublicKey) ed25519.PublicKey {
		return address.SubnetForKey(key).GetKey()
	}
	if c.PacketConn, err = iwe.NewPacketConn(
		c.secret,
		iwn.WithBloomTransform(keyXform),
		iwn.WithPeerMaxMessageSize(65535*2),
		iwn.WithPathNotify(c.doPathNotify),
		iwn.WithPeerQueueTimeout(5*time.Second),
		iwn.WithCipherMode(iwn.CipherAESGCM),
	); err != nil {
		return nil, fmt.Errorf("error creating encryption: %w", err)
	}
	c.proto.init(c)
	c.dgram.conns = make(map[keyArray]*quic.Conn)
	c.dgram.frags = make(map[keyArray]*dgFragmenter)
	c.dgram.reasm = newDgReassembler()
	c.dgram.recvCh = make(chan DatagramPacket, 256)
	if err := c.links.init(c); err != nil {
		return nil, fmt.Errorf("error initialising links: %w", err)
	}
	for _, opt := range opts {
		switch opt.(type) {
		case Peer, ListenAddress:
			// Now do the peers and listeners.
			if err = c._applyOption(opt); err != nil {
				return nil, fmt.Errorf("failed to apply configuration option %T: %w", opt, err)
			}
		default:
			continue
		}
	}
	if err := c.proto.nodeinfo.setNodeInfo(c.config.nodeinfo, bool(c.config.nodeinfoPrivacy)); err != nil {
		return nil, fmt.Errorf("error setting node info: %w", err)
	}
	for listenaddr := range c.config._listeners {
		u, err := url.Parse(string(listenaddr))
		if err != nil {
			c.log.Errorf("Invalid listener URI %q specified, ignoring\n", listenaddr)
			continue
		}
		if _, err = c.links.listen(u, "", false); err != nil {
			c.log.Errorf("Failed to start listener %q: %s\n", listenaddr, err)
		}
	}
	return c, nil
}

func (c *Core) RetryPeersNow() {
	phony.Block(&c.links, func() {
		for _, l := range c.links._links {
			select {
			case l.kick <- struct{}{}:
			default:
			}
		}
	})
}

// Stop shuts down the Yggdrasil node.
func (c *Core) Stop() {
	phony.Block(c, func() {
		c.log.Infoln("Stopping...")
		_ = c._close()
		c.log.Infoln("Stopped")
	})
}

// This function is unsafe and should only be ran by the core actor.
func (c *Core) _close() error {
	c.cancel()
	c.dgram.reasm.stop()
	c.links.shutdown()
	err := c.Close()
	return err
}

func (c *Core) MTU() uint64 {
	const sessionTypeOverhead = 1
	MTU := c.PacketConn.MTU() - sessionTypeOverhead
	if MTU > 65535 {
		MTU = 65535
	}
	return MTU
}

func (c *Core) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	buf := allocBytes(int(c.PacketConn.MTU()))
	defer freeBytes(buf)
	for {
		bs := buf
		n, from, err = c.PacketConn.ReadFrom(bs)
		if err != nil {
			return 0, from, err
		}
		if n == 0 {
			continue
		}
		switch bs[0] {
		case typeSessionTraffic:
			// This is what we want to handle here
		case typeSessionProto:
			var key keyArray
			copy(key[:], from.(iwt.Addr))
			data := append([]byte(nil), bs[1:n]...)
			c.proto.handleProto(nil, key, data)
			continue
		default:
			continue
		}
		bs = bs[1:n]
		copy(p, bs)
		if len(p) < len(bs) {
			n = len(p)
		} else {
			n = len(bs)
		}
		return
	}
}

func (c *Core) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := allocBytes(0)
	defer func() { freeBytes(buf) }()
	buf = append(buf, typeSessionTraffic)
	buf = append(buf, p...)
	n, err = c.PacketConn.WriteTo(buf, addr)
	if n > 0 {
		n -= 1
	}
	return
}

func (c *Core) doPathNotify(key ed25519.PublicKey) {
	c.Act(nil, func() {
		if c.pathNotify != nil {
			c.pathNotify(key)
		}
	})
}

func (c *Core) SetPathNotify(notify func(ed25519.PublicKey)) {
	c.Act(nil, func() {
		c.pathNotify = notify
	})
}

func (c *Core) registerDatagramConn(peerKey keyArray, conn *quic.Conn) {
	c.dgram.Lock()
	c.dgram.conns[peerKey] = conn
	c.dgram.frags[peerKey] = &dgFragmenter{}
	c.dgram.Unlock()
}

func (c *Core) unregisterDatagramConn(peerKey keyArray) {
	c.dgram.Lock()
	delete(c.dgram.conns, peerKey)
	delete(c.dgram.frags, peerKey)
	c.dgram.Unlock()
}

func (c *Core) datagramReceiver(peerKey keyArray, conn *quic.Conn) {
	for {
		wire, err := conn.ReceiveDatagram(c.ctx)
		if err != nil {
			return
		}
		data := c.dgram.reasm.process(peerKey, wire)
		if data == nil {
			continue // Incomplete fragment or malformed
		}
		pkt := DatagramPacket{
			Data: data,
			From: peerKey,
		}
		select {
		case c.dgram.recvCh <- pkt:
		case <-c.ctx.Done():
			return
		default:
			// Channel full, drop (unreliable semantics)
		}
	}
}

// SendDatagram sends data to a directly-connected peer via QUIC datagram (unreliable).
// Payloads larger than maxSafeDatagramSize are automatically fragmented.
// Max payload: 255 fragments * ~1095 bytes/fragment ≈ 279 KB.
func (c *Core) SendDatagram(data []byte, peerKey ed25519.PublicKey) error {
	var key keyArray
	copy(key[:], peerKey)
	c.dgram.RLock()
	conn, ok := c.dgram.conns[key]
	frag := c.dgram.frags[key]
	c.dgram.RUnlock()
	if !ok {
		return ErrDatagramNoPeer
	}

	chunks := frag.fragment(data, maxSafeDatagramSize)
	if chunks == nil {
		return nil // Empty payload
	}
	for _, chunk := range chunks {
		if err := conn.SendDatagram(chunk); err != nil {
			return err
		}
	}
	return nil
}

// ReceiveDatagrams returns the channel for incoming datagrams from direct QUIC peers.
func (c *Core) ReceiveDatagrams() <-chan DatagramPacket {
	return c.dgram.recvCh
}

// HasDatagramSupport returns true if the peer supports QUIC datagrams.
func (c *Core) HasDatagramSupport(peerKey ed25519.PublicKey) bool {
	var key keyArray
	copy(key[:], peerKey)
	c.dgram.RLock()
	_, ok := c.dgram.conns[key]
	c.dgram.RUnlock()
	return ok
}

type Logger interface {
	Printf(string, ...interface{})
	Println(...interface{})
	Infof(string, ...interface{})
	Infoln(...interface{})
	Warnf(string, ...interface{})
	Warnln(...interface{})
	Errorf(string, ...interface{})
	Errorln(...interface{})
	Debugf(string, ...interface{})
	Debugln(...interface{})
	Traceln(...interface{})
}
