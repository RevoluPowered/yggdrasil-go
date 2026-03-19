//go:build js

package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"syscall/js"
	"time"

	"github.com/Arceliar/phony"
)

// linkWT implements WebTransport for WASM using the browser's native
// WebTransport API with serverCertificateHashes for self-signed cert pinning.
type linkWT struct {
	phony.Inbox
	*links
}

func (l *links) newLinkWT() *linkWT {
	return &linkWT{links: l}
}

func (l *linkWT) CertHash() string { return "" }

func (l *linkWT) dial(ctx context.Context, u *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	// Build the WebTransport URL — browser needs https://
	host := u.Host
	wtURL := fmt.Sprintf("https://%s/ygg", host)

	// Get the server's certificate hash from the query params (if provided)
	certHash := u.Query().Get("certHash")

	// Create WebTransport options
	jsOpts := js.Global().Get("Object").New()
	jsOpts.Set("requireUnreliable", true)

	if certHash != "" {
		// Pin the server's self-signed certificate by hash
		hashBytes := hexToBytes(certHash)
		if hashBytes != nil {
			jsArray := js.Global().Get("Uint8Array").New(len(hashBytes))
			js.CopyBytesToJS(jsArray, hashBytes)

			hashObj := js.Global().Get("Object").New()
			hashObj.Set("algorithm", "sha-256")
			hashObj.Set("value", jsArray.Get("buffer"))

			hashArray := js.Global().Get("Array").New()
			hashArray.Call("push", hashObj)
			jsOpts.Set("serverCertificateHashes", hashArray)
		}
	}

	// Create WebTransport connection
	wt := js.Global().Get("WebTransport").New(wtURL, jsOpts)

	// Wait for ready
	readyCh := make(chan error, 1)
	wt.Get("ready").Call("then",
		js.FuncOf(func(_ js.Value, _ []js.Value) any {
			readyCh <- nil
			return nil
		}),
		js.FuncOf(func(_ js.Value, args []js.Value) any {
			readyCh <- fmt.Errorf("WebTransport failed: %s", args[0].Get("message").String())
			return nil
		}),
	)

	select {
	case err := <-readyCh:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		wt.Call("close")
		return nil, ctx.Err()
	}

	// Open a bidirectional stream
	streamPromise := wt.Call("createBidirectionalStream")
	streamCh := make(chan js.Value, 1)
	errCh := make(chan error, 1)

	streamPromise.Call("then",
		js.FuncOf(func(_ js.Value, args []js.Value) any {
			streamCh <- args[0]
			return nil
		}),
		js.FuncOf(func(_ js.Value, args []js.Value) any {
			errCh <- fmt.Errorf("stream failed: %s", args[0].Get("message").String())
			return nil
		}),
	)

	var stream js.Value
	select {
	case stream = <-streamCh:
	case err := <-errCh:
		wt.Call("close")
		return nil, err
	case <-ctx.Done():
		wt.Call("close")
		return nil, ctx.Err()
	}

	readable := stream.Get("readable")
	writable := stream.Get("writable")
	reader := readable.Call("getReader")
	writer := writable.Call("getWriter")

	conn := &linkWTJSConn{
		wt:     wt,
		stream: stream,
		reader: reader,
		writer: writer,
		host:   host,
	}
	return conn, nil
}

func (l *linkWT) listen(_ context.Context, _ *url.URL, _ string) (net.Listener, error) {
	return nil, fmt.Errorf("wts:// listen not supported in WASM")
}

// linkWTJSConn wraps the browser's WebTransport stream as a net.Conn.
type linkWTJSConn struct {
	wt       js.Value
	stream   js.Value
	reader   js.Value
	writer   js.Value
	host     string
	readBuf  []byte
	readPos  int
	mu       sync.Mutex
	closed   bool
}

func (c *linkWTJSConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.EOF
	}

	// Return buffered data first
	if c.readPos < len(c.readBuf) {
		n := copy(p, c.readBuf[c.readPos:])
		c.readPos += n
		if c.readPos >= len(c.readBuf) {
			c.readBuf = nil
			c.readPos = 0
		}
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	// Read from stream
	ch := make(chan struct{ data []byte; err error }, 1)
	c.reader.Call("read").Call("then",
		js.FuncOf(func(_ js.Value, args []js.Value) any {
			result := args[0]
			if result.Get("done").Bool() {
				ch <- struct{ data []byte; err error }{nil, io.EOF}
				return nil
			}
			jsData := result.Get("value")
			data := make([]byte, jsData.Get("byteLength").Int())
			js.CopyBytesToGo(data, js.Global().Get("Uint8Array").New(jsData.Get("buffer")))
			ch <- struct{ data []byte; err error }{data, nil}
			return nil
		}),
		js.FuncOf(func(_ js.Value, args []js.Value) any {
			ch <- struct{ data []byte; err error }{nil, fmt.Errorf("read error: %s", args[0].Get("message").String())}
			return nil
		}),
	)

	result := <-ch
	if result.err != nil {
		return 0, result.err
	}

	n := copy(p, result.data)
	if n < len(result.data) {
		c.mu.Lock()
		c.readBuf = result.data
		c.readPos = n
		c.mu.Unlock()
	}
	return n, nil
}

func (c *linkWTJSConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, io.ErrClosedPipe
	}

	jsData := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(jsData, p)

	ch := make(chan error, 1)
	c.writer.Call("write", jsData).Call("then",
		js.FuncOf(func(_ js.Value, _ []js.Value) any {
			ch <- nil
			return nil
		}),
		js.FuncOf(func(_ js.Value, args []js.Value) any {
			ch <- fmt.Errorf("write error: %s", args[0].Get("message").String())
			return nil
		}),
	)

	if err := <-ch; err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *linkWTJSConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.writer.Call("close")
	c.reader.Call("cancel")
	c.wt.Call("close")
	return nil
}

type wtJSAddr struct{ host string }

func (a wtJSAddr) Network() string { return "webtransport" }
func (a wtJSAddr) String() string  { return a.host }

func (c *linkWTJSConn) LocalAddr() net.Addr  { return wtJSAddr{"browser"} }
func (c *linkWTJSConn) RemoteAddr() net.Addr { return wtJSAddr{c.host} }

func (c *linkWTJSConn) SetDeadline(t time.Time) error      { return nil }
func (c *linkWTJSConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *linkWTJSConn) SetWriteDeadline(t time.Time) error  { return nil }

// DatagramConn implementation for unreliable datagrams
func (c *linkWTJSConn) SendDatagram(p []byte) error {
	jsData := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(jsData, p)

	ch := make(chan error, 1)
	c.wt.Get("datagrams").Get("writable").Call("getWriter").Call("write", jsData).Call("then",
		js.FuncOf(func(_ js.Value, _ []js.Value) any {
			ch <- nil
			return nil
		}),
		js.FuncOf(func(_ js.Value, args []js.Value) any {
			ch <- fmt.Errorf("datagram write error: %s", args[0].Get("message").String())
			return nil
		}),
	)
	return <-ch
}

func (c *linkWTJSConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	ch := make(chan struct{ data []byte; err error }, 1)
	c.wt.Get("datagrams").Get("readable").Call("getReader").Call("read").Call("then",
		js.FuncOf(func(_ js.Value, args []js.Value) any {
			result := args[0]
			if result.Get("done").Bool() {
				ch <- struct{ data []byte; err error }{nil, io.EOF}
				return nil
			}
			jsData := result.Get("value")
			data := make([]byte, jsData.Get("byteLength").Int())
			js.CopyBytesToGo(data, js.Global().Get("Uint8Array").New(jsData.Get("buffer")))
			ch <- struct{ data []byte; err error }{data, nil}
			return nil
		}),
		js.FuncOf(func(_ js.Value, args []js.Value) any {
			ch <- struct{ data []byte; err error }{nil, fmt.Errorf("datagram read error: %s", args[0].Get("message").String())}
			return nil
		}),
	)
	select {
	case result := <-ch:
		return result.data, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// hexToBytes converts a hex string to bytes
func hexToBytes(s string) []byte {
	if len(s)%2 != 0 {
		return nil
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + c - '0'
			case c >= 'a' && c <= 'f':
				v = v*16 + c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = v*16 + c - 'A' + 10
			default:
				return nil
			}
		}
		b[i/2] = v
	}
	return b
}

// Ensure unused imports don't cause errors
var _ = binary.BigEndian
