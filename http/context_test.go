// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"net"
	"testing"
)

// simple net.Conn implementation for tests
type testConn struct {
	net.Conn
}

func TestStashAndGetConnContext(t *testing.T) {
	baseCtx := context.Background()
	conn := &testConn{}

	ctxWithConn := stashConnContext(baseCtx, conn)

	got := getConnContext(ctxWithConn)
	if got == nil {
		t.Fatalf("expected non-nil conn from context")
	}
	if got != conn {
		t.Fatalf("expected conn %p, got %p", conn, got)
	}

	// Unknown type or missing key should return nil
	if getConnContext(baseCtx) != nil {
		t.Fatalf("expected nil conn from base context")
	}
}

func TestStashAndGetInitiatorNameContext(t *testing.T) {
	baseCtx := context.Background()
	initiator := &InitiatorName{
		PrincipalName: "user@EXAMPLE.COM",
		LocalName:     "user",
	}

	ctxWithInitiator := stashInitiatorName(baseCtx, initiator)

	got := getInitiatorNameContext(ctxWithInitiator)
	if got == nil {
		t.Fatalf("expected non-nil initiator name from context")
	}
	if got != initiator {
		t.Fatalf("expected initiator %p, got %p", initiator, got)
	}

	// Missing key should return nil
	if getInitiatorNameContext(baseCtx) != nil {
		t.Fatalf("expected nil initiator name from base context")
	}
}
