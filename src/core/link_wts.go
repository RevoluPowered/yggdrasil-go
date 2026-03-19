//go:build !js

package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Arceliar/phony"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

type linkWT struct {
	phony.Inbox
	*links
	tlsconfig  *tls.Config
	listenTLS  *tls.Config // ECDSA P-256 cert for browser cert hash pinning
	certHash   []byte      // SHA-256 of the ECDSA cert DER
	quicconfig *quic.Config
}

// CertHash returns the hex-encoded SHA-256 hash of the WTS listener certificate.
// Browsers use this for serverCertificateHashes pinning.
func (l *linkWT) CertHash() string {
	if l.certHash == nil {
		return ""
	}
	return hex.EncodeToString(l.certHash)
}

// linkWTStream wraps a WebTransport session + bidirectional stream as net.Conn.
// Also implements DatagramConn by delegating to the session.
type linkWTStream struct {
	session *webtransport.Session
	*webtransport.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (s *linkWTStream) LocalAddr() net.Addr  { return s.localAddr }
func (s *linkWTStream) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *linkWTStream) Close() error {
	s.Stream.Close()
	return s.session.CloseWithError(0, "")
}

// DatagramConn implementation — delegates to session.
func (s *linkWTStream) SendDatagram(p []byte) error {
	return s.session.SendDatagram(p)
}

func (s *linkWTStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.session.ReceiveDatagram(ctx)
}

type linkWTListener struct {
	ch     <-chan *linkWTStream
	cancel context.CancelFunc
	addr   net.Addr
}

func (l *linkWTListener) Accept() (net.Conn, error) {
	wts := <-l.ch
	if wts == nil {
		return nil, context.Canceled
	}
	return wts, nil
}

func (l *linkWTListener) Addr() net.Addr { return l.addr }
func (l *linkWTListener) Close() error   { l.cancel(); return nil }

func (l *links) newLinkWT() *linkWT {
	tlscfg := l.core.config.tls.Clone()
	tlscfg.NextProtos = []string{"h3"}

	// Generate ECDSA P-256 cert for the listener — required by browsers
	// for WebTransport serverCertificateHashes (max 14 days validity).
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialBytes := make([]byte, 8)
	rand.Read(serialBytes)
	serial := new(big.Int).SetBytes(serialBytes)
	serial.Abs(serial)
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Hour), // small clock skew tolerance
		NotAfter:              time.Now().Add(14*24*time.Hour - time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &ecKey.PublicKey, ecKey)
	ecCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  ecKey,
	}
	// Compute SHA-256 hash for browser cert pinning
	certHash := sha256.Sum256(certDER)

	listenTLS := &tls.Config{
		Certificates: []tls.Certificate{ecCert},
		NextProtos:   []string{"h3"},
	}

	lt := &linkWT{
		links:        l,
		tlsconfig:    tlscfg,
		listenTLS:    listenTLS,
		certHash:     certHash[:],
		quicconfig: &quic.Config{
			MaxIdleTimeout:  time.Minute,
			KeepAlivePeriod:                    time.Second * 20,
			EnableDatagrams:                    true,
			EnableStreamResetPartialDelivery:   true,
		},
	}
	return lt
}

func (l *linkWT) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	tlsconfig := l.tlsconfig.Clone()
	return l.findSuitableIP(url, func(hostname string, ip net.IP, port int) (net.Conn, error) {
		tlsconfig.ServerName = hostname
		tlsconfig.MinVersion = tls.VersionTLS12
		tlsconfig.MaxVersion = tls.VersionTLS13
		hostport := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		dialer := &webtransport.Dialer{
			TLSClientConfig: tlsconfig,
			QUICConfig:      l.quicconfig,
		}
		wtURL := fmt.Sprintf("https://%s/ygg", hostport)
		_, session, err := dialer.Dial(ctx, wtURL, nil)
		if err != nil {
			return nil, err
		}
		stream, err := session.OpenStreamSync(ctx)
		if err != nil {
			session.CloseWithError(1, fmt.Sprintf("stream error: %s", err))
			return nil, err
		}
		remoteAddr, _ := net.ResolveTCPAddr("tcp", hostport)
		return &linkWTStream{
			session:    session,
			Stream:     stream,
			remoteAddr: remoteAddr,
		}, nil
	})
}

func (l *linkWT) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", url.Host)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	localAddr := udpConn.LocalAddr()

	mux := http.NewServeMux()
	ch := make(chan *linkWTStream)
	listenCtx, cancel := context.WithCancel(ctx)

	// Use ECDSA cert for the listener — browsers require P-256 for cert hash pinning
	h3Server := &http3.Server{
		TLSConfig:  l.listenTLS,
		QUICConfig: l.quicconfig,
		Handler:    mux,
	}
	webtransport.ConfigureHTTP3Server(h3Server)
	wtServer := &webtransport.Server{
		H3:          h3Server,
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux.HandleFunc("/ygg", func(w http.ResponseWriter, r *http.Request) {
		session, err := wtServer.Upgrade(w, r)
		if err != nil {
			return
		}
		stream, err := session.AcceptStream(listenCtx)
		if err != nil {
			session.CloseWithError(1, fmt.Sprintf("stream error: %s", err))
			return
		}
		remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		select {
		case ch <- &linkWTStream{
			session:    session,
			Stream:     stream,
			localAddr:  localAddr,
			remoteAddr: remoteAddr,
		}:
		case <-listenCtx.Done():
			session.CloseWithError(0, "listener closed")
		}
	})

	go func() {
		wtServer.Serve(udpConn)
	}()

	go func() {
		<-listenCtx.Done()
		wtServer.Close()
		close(ch)
	}()

	return &linkWTListener{
		ch:     ch,
		cancel: cancel,
		addr:   localAddr,
	}, nil
}
