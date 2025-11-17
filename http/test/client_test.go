// SPDX-License-Identifier: Apache-2.0

package test

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	ghttp "github.com/golang-auth/go-gssapi/v3/http"
)

func parseAuthzHeader(headers *http.Header) (string, string) {
	header := headers.Get("Authorization")
	if header == "" {
		return "", ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

type serverInfo struct {
	requestedNegotiate bool
	gotAuthzHeader     bool
	bodyBytes          int
	body               []byte
}

// The test server is a very cut down HTTP server that expects Negotiate authentication
// It is the acceptor side of a GSSAPI context establishment, and it will purposefully
// mess up the response if told to do so.
func newTestServer(t *testing.T, ignoreMutual bool, cantAccept bool, sendBadAuthzHeader bool, serverInfo *serverInfo) *httptest.Server {

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authzType, authzToken := parseAuthzHeader(&r.Header)
		if authzType == "Negotiate" && len(authzToken) > 0 {
			serverInfo.gotAuthzHeader = true

			authzTokenBytes, err := base64.StdEncoding.DecodeString(authzToken)
			if err != nil {
				t.Fatalf("Failed to decode authz token: %v", err)
			}

			// mess up the request token if the server should not accept the context
			if cantAccept {
				authzTokenBytes = []byte("Bad Token")
			}

			// Try to accept the context
			secCtx, err := ta.lib.AcceptSecContext()
			if err != nil {
				t.Logf("Failed to accept context: %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			defer secCtx.Delete() //nolint:errcheck

			respToken, _, err := secCtx.Continue(authzTokenBytes)
			if err != nil {
				t.Logf("Failed to continue context: %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// mess up the response token if the server should send a bad Authorization header
			if len(respToken) > 0 {
				if sendBadAuthzHeader {
					respToken = []byte("Bad Response Token")
				}

				if !ignoreMutual {
					respTokenBase64 := base64.StdEncoding.EncodeToString(respToken)
					w.Header().Set("WWW-Authenticate", "Negotiate "+respTokenBase64)
				}
			}

			if r.Method == "POST" {
				body, err := io.ReadAll(r.Body)
				serverInfo.bodyBytes = len(body)
				if err != nil {
					t.Logf("Failed to read request body: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				serverInfo.body = body
			}

			w.WriteHeader(http.StatusOK)
		} else {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.WriteHeader(http.StatusUnauthorized)
			serverInfo.requestedNegotiate = true
		}
	}))
}

func enableLogging() bool {
	loggingEnv := os.Getenv("GSSAPI_HTTP_LOGGING")
	enableLogging := false
	switch strings.ToLower(loggingEnv) {
	case "yes", "1", "true":
		enableLogging = true
	}
	return enableLogging
}

// TestClient uses a small rewindble POST body with Expect: Continue disabled.
// These tests verify how the client handles authentication and authentication failures.
func TestClient(t *testing.T) {
	ta.useAsset(t, testCredCache|testKeytabRack)

	body := []byte("I love GSSAPI!")

	tests := []struct {
		name                     string
		clientMutual             bool // the client should request mutual authentication
		clientOpportunistic      bool // the client should opportunistically authenticate
		serverIgnoreMutual       bool // the server should ignore mutual authentication
		serverBadAuthzHeader     bool // the server should send a bad Authorization header
		serverCantAccept         bool // the server should not accept the context
		expectRequestedNegotiate bool // the server should have sent a 401
		expectSuccess            bool // the client should return an error
		expectStatus             int  // the final response should have this status code
	}{
		{name: "No-Mutual-No-Opportunistic", expectRequestedNegotiate: true, expectSuccess: true, expectStatus: 200},
		{name: "No-Mutual-Opportunistic", clientOpportunistic: true, expectSuccess: true, expectStatus: 200},
		{name: "Server-Cant-Accept", clientOpportunistic: true, serverCantAccept: true, expectSuccess: true, expectStatus: 401},
		{name: "Mutual-No-Opportunistic", clientMutual: true, expectRequestedNegotiate: true, expectSuccess: true, expectStatus: 200},
		{name: "Mutual-Opportunistic", clientMutual: true, clientOpportunistic: true, expectSuccess: true, expectStatus: 200},
		{name: "Bad-Mutual-Token", clientMutual: true, clientOpportunistic: true, serverBadAuthzHeader: true, expectSuccess: false},
		{name: "Server-Ignore-Mutual", clientMutual: true, clientOpportunistic: true, serverIgnoreMutual: true, expectSuccess: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := NewAssert(t)
			bodyReader := bytes.NewBuffer(body)

			si := serverInfo{}
			ts := newTestServer(t, tt.serverIgnoreMutual, tt.serverCantAccept, tt.serverBadAuthzHeader, &si)
			defer ts.Close()

			opts := []ghttp.ClientOption{
				ghttp.WithSpnFunc(func(url url.URL) string {
					return "HTTP@foo.golang-auth.io"
				}),
			}
			if enableLogging() {
				opts = append(opts, ghttp.WithHttpLogging(),
					ghttp.WithLogFunc(func(format string, args ...interface{}) {
						t.Logf(format, args...)
					}))
			}

			if tt.clientMutual {
				opts = append(opts, ghttp.WithMutual())
			}
			if tt.clientOpportunistic {
				opts = append(opts, ghttp.WithOpportunistic())
			}

			client := ghttp.NewClient(ta.lib, nil, opts...)
			req, err := http.NewRequest("POST", ts.URL, bodyReader)
			assert.NoErrorFatal(err)

			resp, err := client.Do(req)
			if tt.expectSuccess {
				assert.NoErrorFatal(err)
				assert.Equal(tt.expectStatus, resp.StatusCode)
				if tt.expectStatus == 200 {
					assert.Equal(si.bodyBytes, len(body))
					assert.Equal(string(si.body), string(body))
				}
			} else {
				assert.Error(err)
			}

			if tt.expectRequestedNegotiate {
				assert.True(si.requestedNegotiate)
			}
		})
	}
}

func TestClient100Continue(t *testing.T) {
	ta.useAsset(t, testCredCache|testKeytabRack)

	// Generate 2kb (2048 bytes) of random data for the request body
	body := make([]byte, 2048)
	for i := range body {
		body[i] = byte('a' + i%26)
	}

	enableLogging := enableLogging()

	tests := []struct {
		name                    string
		expectContinueThreshold int64 // the threshold for using 100-continue
		clientOpportunistic     bool  // the client should preemptively authenticate
		rewindableBody          bool  // should the request body be rewindable?
		expect100Continue       bool  // expect the 100-continue header?
		expectError             bool  // expect an error?
	}{
		// these tests should note trigger 100-continue header because opportunistic authentication is requested
		{"BigBody-Opportunistic-Rewindable", 100, true, true, false, false},
		{"BigBody-Opportunistic-Non-Rewindable", 100, true, false, false, false},
		// these tests should trigger the 100-continue header because the body size is larger than the threshold value
		{"BigBody-Non-Opportunistic-Rewindable", 100, false, true, true, false},
		{"BigBody-Non-Opportunistic-Non-Rewindable", 100, false, false, true, false},
		// these tests should not trigger the 100-continue header because the body is smaller than the threshold value or
		// opportunistic authentication is requested
		{"SmallBody-Opportunistic-Rewindable", 4096, true, true, false, false},
		{"SmallBody-Opportunistic-Non-Rewindable", 4096, true, false, false, false},
		{"SmallBody-Non-Opportunistic-Rewindable", 4096, false, true, false, false},
		// this test will trigger the 100-continue header because it is non-opportunistic and the body is not rewindable, making the request successful
		{"SmallBody-Non-Opportunistic-Non-Rewindable", 4096, false, false, true, false},
		// should fail not trigger 100-continue (disabled) - so will fail because the non-rewindable body will be sent before receiving the 401
		{"SmallBody-Non-Opportunistic-Non-Rewindable-100-disabled", 0, false, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := NewAssert(t)
			bodyReader := bytes.NewBuffer(body)

			// well behaved server
			si := serverInfo{}
			ts := newTestServer(t, false, false, false, &si)
			defer ts.Close()

			opts := []ghttp.ClientOption{
				ghttp.WithSpnFunc(func(url url.URL) string {
					return "HTTP@foo.golang-auth.io"
				}),
				ghttp.WithHttpLogging(),
				ghttp.WithLogFunc(func(format string, args ...interface{}) {
					if enableLogging {
						t.Logf(format, args...)
					}
				}),
				ghttp.WithExpect100Threshold(tt.expectContinueThreshold),
			}
			if tt.clientOpportunistic {
				opts = append(opts, ghttp.WithOpportunistic())
			}

			req, err := http.NewRequest("POST", ts.URL, bodyReader)
			assert.NoErrorFatal(err)
			if !tt.rewindableBody {
				req.GetBody = nil
			}

			// capture the trace to inspect for receipt of the 100-continue header
			trace := &ghttp.HttpTrace{}
			req = req.WithContext(ghttp.WithHttpTrace(req.Context(), trace))

			client := ghttp.NewClient(ta.lib, nil, opts...)
			resp, err := client.Do(req)
			if tt.expectError {
				assert.Equal(0, si.bodyBytes)
				assert.Error(err)
			} else {
				assert.Equal(len(body), si.bodyBytes)
				assert.NoErrorFatal(err)
				assert.Equal(http.StatusOK, resp.StatusCode)
			}
			if tt.expect100Continue {
				assert.True(trace.Seen100Continue)
			} else {
				assert.False(trace.Seen100Continue)
			}

		})
	}

}
