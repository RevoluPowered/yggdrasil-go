//go:build js

package core

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/coder/websocket"
)

// WASM WebSocket implementations.
// WS (unencrypted) is not useful in browsers — use WSS.
// WSS uses coder/websocket which auto-detects WASM and uses the browser's
// native WebSocket API. No HTTPClient or Host fields needed.
// Listen is not supported — browsers can't accept incoming connections.

type linkWS struct{ *links }
type linkWSS struct{ *links }

func (l *links) newLinkWS() *linkWS   { return &linkWS{l} }
func (l *links) newLinkWSS() *linkWSS { return &linkWSS{l} }

func (l *linkWS) dial(_ context.Context, _ *url.URL, _ linkInfo, _ linkOptions) (net.Conn, error) {
	return nil, fmt.Errorf("ws:// not supported in WASM, use wss://")
}
func (l *linkWS) listen(_ context.Context, _ *url.URL, _ string) (net.Listener, error) {
	return nil, fmt.Errorf("ws:// listen not supported in WASM")
}

func (l *linkWSS) dial(ctx context.Context, u *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	wsconn, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		Subprotocols: []string{"ygg-ws"},
	})
	if err != nil {
		return nil, err
	}
	return websocket.NetConn(ctx, wsconn, websocket.MessageBinary), nil
}

func (l *linkWSS) listen(_ context.Context, _ *url.URL, _ string) (net.Listener, error) {
	return nil, fmt.Errorf("wss:// listen not supported in WASM")
}
