// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"strings"
)

// HttpTrace gathers infromation during the HTTP request/response cycle.
type HttpTrace struct {
	WaitedFor100Continue bool
	Seen100Continue      bool
}

type clientContextKey struct{}

func WithHttpTrace(ctx context.Context, trace *HttpTrace) context.Context {
	return context.WithValue(ctx, clientContextKey{}, trace)
}

func GetHttpTrace(ctx context.Context) *HttpTrace {
	trace, _ := ctx.Value(clientContextKey{}).(*HttpTrace)
	return trace
}

func (t *GSSAPITransport) setupLogging(req *http.Request) *http.Request {
	trace := GetHttpTrace(req.Context())
	if trace == nil {
		trace = &HttpTrace{}
		req = req.WithContext(WithHttpTrace(req.Context(), trace))
	}

	ctrace := httptrace.ContextClientTrace(req.Context())
	if ctrace == nil {
		ctrace = &httptrace.ClientTrace{
			GetConn: func(hostPort string) {
				t.logFunc("<> Getting connection to %s", hostPort)
			},
			GotConn: func(info httptrace.GotConnInfo) {
				if info.Conn.LocalAddr() == nil {
					t.logFunc("<> Obtained connection: <not network> %+v", info)
				} else {
					t.logFunc("<> Obtained connection: %s -> %s:  %+v", info.Conn.LocalAddr(), info.Conn.RemoteAddr(), info)
				}
			},
			GotFirstResponseByte: func() {
				t.logFunc("<> Got first response byte")
			},
			Got100Continue: func() {
				t.logFunc("<> Got 100-Continue")
				trace.Seen100Continue = true
			},
			WroteHeaders: func() {
				t.logFunc("<> Wrote headers")
			},
			Wait100Continue: func() {
				t.logFunc("<> Waited for 100-Continue")
				trace.WaitedFor100Continue = true
			},
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				t.logFunc("<> Wrote request: %+v", info)
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), ctrace))
	}

	return req
}

func (t *GSSAPITransport) requestLogging(req *http.Request) error {
	if t.logFunc == nil {
		return nil
	}

	// we don't dump the body
	by, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		return fmt.Errorf("failed to dump request: %w", err)
	}

	linesOut := strings.Split(string(by), "\n")
	for _, line := range linesOut {
		t.logFunc("> %s\n", line)
	}
	return nil
}

func (t *GSSAPITransport) responseLogging(resp *http.Response) error {
	if t.logFunc == nil {
		return nil
	}

	by, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return fmt.Errorf("failed to dump response: %w", err)
	}
	linesIn := strings.Split(string(by), "\n")

	for _, line := range linesIn {
		t.logFunc("< %s\n", line)
	}

	return nil
}
