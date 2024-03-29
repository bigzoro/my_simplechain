// Copyright 2015 The go-simplechain Authors
// This file is part of the go-simplechain library.
//
// The go-simplechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-simplechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-simplechain library. If not, see <http://www.gnu.org/licenses/>.

package rpc

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/bigzoro/my_simplechain/rpc/tls"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/bigzoro/my_simplechain/log"
	mapset "github.com/deckarep/golang-set"
	"github.com/gorilla/websocket"
)

const (
	wssReadBuffer  = 1024
	wssWriteBuffer = 1024
)

var wssBufferPool = new(sync.Pool)

// NewWSServer creates a new websocket RPC server around an API provider.
//
// Deprecated: use Server.WebsocketHandler
func NewWSSServer(allowedOrigins []string, srv *Server) *http.Server {
	return &http.Server{Handler: srv.WebsocketsHandler(allowedOrigins)}
}

// WebsocketHandler returns a handler that serves JSON-RPC to WebSocket connections.
//
// allowedOrigins should be a comma-separated list of allowed origin URLs.
// To allow connections with any origin, pass "*".
func (s *Server) WebsocketsHandler(allowedOrigins []string) http.Handler {
	var upgrader = websocket.Upgrader{
		ReadBufferSize:  wssReadBuffer,
		WriteBufferSize: wssWriteBuffer,
		WriteBufferPool: wssBufferPool,
		CheckOrigin:     wssHandshakeValidator(allowedOrigins),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Debug("WebSocket upgrade failed", "err", err)
			return
		}
		codec := newWebsocketsCodec(conn)
		s.ServeCodec(codec, 0)
	})
}

// wsHandshakeValidator returns a handler that verifies the origin during the
// websocket upgrade process. When a '*' is specified as an allowed origins all
// connections are accepted.
func wssHandshakeValidator(allowedOrigins []string) func(*http.Request) bool {
	origins := mapset.NewSet()
	allowAllOrigins := false

	for _, origin := range allowedOrigins {
		if origin == "*" {
			allowAllOrigins = true
		}
		if origin != "" {
			origins.Add(strings.ToLower(origin))
		}
	}
	// allow localhost if no allowedOrigins are specified.
	if len(origins.ToSlice()) == 0 {
		origins.Add("https://localhost")
		if hostname, err := os.Hostname(); err == nil {
			origins.Add("https://" + strings.ToLower(hostname))
		}
	}
	log.Debug(fmt.Sprintf("Allowed origin(s) for WSS RPC interface %v", origins.ToSlice()))

	f := func(req *http.Request) bool {
		// Skip origin verification if no Origin header is present. The origin check
		// is supposed to protect against browser based attacks. Browsers always set
		// Origin. Non-browser software can put anything in origin and checking it doesn't
		// provide additional security.
		if _, ok := req.Header["Origin"]; !ok {
			return true
		}
		// Verify origin against whitelist.
		origin := strings.ToLower(req.Header.Get("Origin"))
		if allowAllOrigins || origins.Contains(origin) {
			return true
		}
		log.Warn("Rejected WebSocket connection", "origin", origin)
		return false
	}

	return f
}

type wssHandshakeError struct {
	err    error
	status string
}

func (e wssHandshakeError) Error() string {
	s := e.err.Error()
	if e.status != "" {
		s += " (HTTP status " + e.status + ")"
	}
	return s
}

// DialWebsocket creates a new RPC client that communicates with a JSON-RPC server
// that is listening on the given endpoint.
//
// The context is used for the initial connection establishment. It does not
// affect subsequent interactions with the client.
func DialWebsockets(ctx context.Context, endpoint, origin string, certFile string, keyFile string, certFiles []string) (*Client, error) {
	endpoint, header, err := wssClientHeaders(endpoint, origin)
	if err != nil {
		return nil, err
	}
	tlsClientConfig, err := tls.NewTLSClientConfig(certFile, keyFile, certFiles)
	if err != nil {
		return nil, err
	}
	dialer := websocket.Dialer{
		ReadBufferSize:  wssReadBuffer,
		WriteBufferSize: wssWriteBuffer,
		WriteBufferPool: wssBufferPool,
		TLSClientConfig: tlsClientConfig,
	}
	return newClient(ctx, func(ctx context.Context) (ServerCodec, error) {
		conn, resp, err := dialer.DialContext(ctx, endpoint, header)
		if err != nil {
			hErr := wssHandshakeError{err: err}
			if resp != nil {
				hErr.status = resp.Status
			}
			return nil, hErr
		}
		return newWebsocketsCodec(conn), nil
	})
}

func wssClientHeaders(endpoint, origin string) (string, http.Header, error) {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return endpoint, nil, err
	}
	header := make(http.Header)
	if origin != "" {
		header.Add("origin", origin)
	}
	if endpointURL.User != nil {
		b64auth := base64.StdEncoding.EncodeToString([]byte(endpointURL.User.String()))
		header.Add("authorization", "Basic "+b64auth)
		endpointURL.User = nil
	}
	return endpointURL.String(), header, nil
}

func newWebsocketsCodec(conn *websocket.Conn) ServerCodec {
	conn.SetReadLimit(maxRequestContentLength_https)
	return NewFuncCodec(conn, conn.WriteJSON, conn.ReadJSON)
}
