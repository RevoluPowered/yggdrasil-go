//go:build !js

package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Arceliar/phony"
	"github.com/coder/websocket"
)

type linkWSS struct {
	phony.Inbox
	*links
	tlsconfig *tls.Config
}

type linkWSSConn struct {
	net.Conn
	done chan struct{} // closed when connection is done (unblocks HTTP handler)
}

func (c *linkWSSConn) Close() error {
	err := c.Conn.Close()
	if c.done != nil {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}
	return err
}

func (l *links) newLinkWSS() *linkWSS {
	// Use yggdrasil's own TLS config (Ed25519 cert, InsecureSkipVerify)
	// with http/1.1 ALPN added for WebSocket upgrade.
	tlscfg := l.core.config.tls.Clone()
	tlscfg.NextProtos = []string{"http/1.1"}
	lwss := &linkWSS{
		links:     l,
		tlsconfig: tlscfg,
	}
	return lwss
}

func (l *linkWSS) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	// Dial uses the base yggdrasil TLS config (InsecureSkipVerify) not the listener's RSA config
	tlsconfig := l.core.config.tls.Clone()
	return l.findSuitableIP(url, func(hostname string, ip net.IP, port int) (net.Conn, error) {
		tlsconfig.ServerName = hostname
		tlsconfig.MinVersion = tls.VersionTLS12
		tlsconfig.MaxVersion = tls.VersionTLS13
		u := *url
		u.Host = net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		addr := &net.TCPAddr{
			IP:   ip,
			Port: port,
		}
		dialer, err := l.tcp.dialerFor(addr, info.sintf)
		if err != nil {
			return nil, err
		}
		wsconn, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					Proxy:           http.ProxyFromEnvironment,
					Dial:            dialer.Dial,
					DialContext:     dialer.DialContext,
					TLSClientConfig: tlsconfig,
				},
			},
			Subprotocols: []string{"ygg-ws"},
			Host:         hostname,
		})
		if err != nil {
			return nil, err
		}
		return &linkWSSConn{
			Conn: websocket.NetConn(ctx, wsconn, websocket.MessageBinary),
		}, nil
	})
}

func (l *linkWSS) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error) {
	nl, err := net.Listen("tcp", url.Host)
	if err != nil {
		return nil, err
	}
	tlsListener := tls.NewListener(nl, l.tlsconfig)

	ch := make(chan *linkWSSConn)

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
				Subprotocols: []string{"ygg-ws"},
			})
			if err != nil {
				return
			}
			if c.Subprotocol() != "ygg-ws" {
				c.Close(websocket.StatusPolicyViolation, "client must speak the ygg-ws subprotocol")
				return
			}
			conn := websocket.NetConn(ctx, c, websocket.MessageBinary)
			done := make(chan struct{})
			ch <- &linkWSSConn{
				Conn: conn,
				done: done,
			}
			// Block the handler until the connection is closed,
			// otherwise the HTTP server reclaims the TLS connection.
			<-done
		}),
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	go httpServer.Serve(tlsListener) // nolint:errcheck

	return &linkWSSListener{
		ch:         ch,
		ctx:        ctx,
		httpServer: httpServer,
		listener:   tlsListener,
	}, nil
}

type linkWSSListener struct {
	ch         chan *linkWSSConn
	ctx        context.Context
	httpServer *http.Server
	listener   net.Listener
}

func (l *linkWSSListener) Accept() (net.Conn, error) {
	qs := <-l.ch
	if qs == nil {
		return nil, context.Canceled
	}
	return qs, nil
}

func (l *linkWSSListener) Addr() net.Addr { return l.listener.Addr() }
func (l *linkWSSListener) Close() error   { return l.httpServer.Close() }
