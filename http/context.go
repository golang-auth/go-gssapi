// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"net"
	"net/http"

	"github.com/golang-auth/go-gssapi/v3"
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "gssapi/http context value " + k.name }

var connContextKey = &contextKey{"conn"}
var initiatorContextKey = &contextKey{"initiator"}
var hasCBContextKey = &contextKey{"has-cb"}
var delegatedCredContextKey = &contextKey{"delegated-cred"}

// Record the net.Conn in the connection's context which is passed to Handlers
// as part of the http.Request context.
func stashConnContext(ctx context.Context, c net.Conn) context.Context {
	ctx = context.WithValue(ctx, connContextKey, c)
	return ctx
}

// Record the initiator name in the request context
func stashInitiatorName(ctx context.Context, initiatorName *InitiatorName) context.Context {
	ctx = context.WithValue(ctx, initiatorContextKey, initiatorName)
	return ctx
}

func stashHasChannelBindings(ctx context.Context, has bool) context.Context {
	ctx = context.WithValue(ctx, hasCBContextKey, has)
	return ctx
}

// getConnContext returns the net.Conn from a context
func getConnContext(ctx context.Context) net.Conn {
	conn, ok := ctx.Value(connContextKey).(net.Conn)
	if !ok {
		return nil
	}
	return conn
}

// getServerContext returns the http.Server from a context
func getServerContext(ctx context.Context) *http.Server {
	server, ok := ctx.Value(http.ServerContextKey).(*http.Server)
	if !ok {
		return nil
	}
	return server
}

// GetInitiatorName returns the initiator name from the request context
func getInitiatorNameContext(ctx context.Context) *InitiatorName {
	initiatorName, ok := ctx.Value(initiatorContextKey).(*InitiatorName)
	if !ok {
		return nil
	}
	return initiatorName
}

func getHasCBContext(ctx context.Context) bool {
	hasCB, ok := ctx.Value(hasCBContextKey).(bool)
	if !ok {
		return false
	}

	return hasCB
}

// stashDelegatedCredential stores the delegated credential in the request context
func stashDelegatedCredential(ctx context.Context, cred gssapi.Credential) context.Context {
	ctx = context.WithValue(ctx, delegatedCredContextKey, cred)
	return ctx
}

// getDelegatedCredentialContext returns the delegated credential from a context
func getDelegatedCredentialContext(ctx context.Context) gssapi.Credential {
	cred, ok := ctx.Value(delegatedCredContextKey).(gssapi.Credential)
	if !ok {
		return nil
	}
	return cred
}
