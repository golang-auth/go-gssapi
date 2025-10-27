package test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			defer secCtx.Delete() //nolint:errcheck

			respToken, _, err := secCtx.Continue(authzTokenBytes)
			if err != nil {
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
					w.Header().Set("Authorization", "Negotiate "+respTokenBase64)
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

			}

			w.WriteHeader(http.StatusOK)
		} else {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.WriteHeader(http.StatusUnauthorized)
			serverInfo.requestedNegotiate = true
		}
	}))
}

func TestClient(t *testing.T) {
	ta.useAsset(t, testCredCache|testKeytabRack)

	// Generate 2kb (2048 bytes) of random data for the request body
	body := make([]byte, 2048)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("Failed to generate random body: %v", err)
	}

	tests := []struct {
		name                     string
		clientMutual             bool // the client should request mutual authentication
		clientPreemptive         bool // the client should preemptively authenticate
		serverIgnoreMutual       bool // the server should ignore mutual authentication
		serverBadAuthzHeader     bool // the server should send a bad Authorization header
		serverCantAccept         bool // the server should not accept the context
		expectRequestedNegotiate bool // the server should have sent a 401
		expectSuccess            bool // the client should return an error
		expectStatus             int  // the final response should have this status code
	}{
		{name: "No-Mutual-No-Preemptive", expectRequestedNegotiate: true, expectSuccess: true, expectStatus: 200},
		{name: "No-Mutual-Preemptive", clientPreemptive: true, expectSuccess: true, expectStatus: 200},
		{name: "Server-Cant-Accept", clientPreemptive: true, serverCantAccept: true, expectSuccess: true, expectStatus: 401},
		{name: "Mutual-No-Preemptive", clientMutual: true, expectRequestedNegotiate: true, expectSuccess: true, expectStatus: 200},
		{name: "Mutual-Preemptive", clientMutual: true, clientPreemptive: true, expectSuccess: true, expectStatus: 200},
		{name: "Bad-Mutual-Token", clientMutual: true, clientPreemptive: true, serverBadAuthzHeader: true, expectSuccess: false},
		{name: "Server-Ignore-Mutual", clientMutual: true, clientPreemptive: true, serverIgnoreMutual: true, expectSuccess: false},
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

			if tt.clientMutual {
				opts = append(opts, ghttp.WithMutual())
			}
			if tt.clientPreemptive {
				opts = append(opts, ghttp.WithPreemptive())
			}

			client := ghttp.NewClient(ta.lib, opts...)
			req, err := http.NewRequest("POST", ts.URL, bodyReader)
			assert.NoErrorFatal(err)

			resp, err := client.Do(req)
			if tt.expectSuccess {
				assert.NoErrorFatal(err)
				assert.Equal(tt.expectStatus, resp.StatusCode)
			} else {
				assert.Error(err)
			}

			if tt.expectRequestedNegotiate {
				assert.True(si.requestedNegotiate)
			}
		})
	}
}

func Test100Continue(t *testing.T) {
	ta.useAsset(t, testCredCache|testKeytabRack)

	// Generate 2kb (2048 bytes) of random data for the request body
	body := make([]byte, 2048)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("Failed to generate random body: %v", err)
	}

	tests := []struct {
		name             string
		use100Continue   bool // should the client use 100-continue?
		clientPreemptive bool // the client should preemptively authenticate
		rewindableBody   bool // should the request body be rewindable?
		expectError      bool // expect an error?
	}{
		{"Use100-Preemptive-Rewindable", true, true, true, false},
		{"Use100-Preemptive-Non-Rewindable", true, true, false, false},
		{"Use100-Non-Preemptive-Rewindable", true, false, true, false},
		{"Use100-Non-Preemptive-Non-Rewindable", true, false, false, false},
		{"No100-Preemptive-Rewindable", false, true, true, false},
		{"No100-Preemptive-Non-Rewindable", false, true, false, false},
		{"No100-Non-Preemptive-Rewindable", false, false, true, false},
		{"No100-Non-Preemptive-Non-Rewindable", false, false, false, true}, // should fail because we'll send the body before we get the 401
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
			}
			if !tt.use100Continue {
				opts = append(opts, ghttp.WithNoExpect100())
			}
			if tt.clientPreemptive {
				opts = append(opts, ghttp.WithPreemptive())
			}

			req, err := http.NewRequest("POST", ts.URL, bodyReader)
			assert.NoErrorFatal(err)
			if !tt.rewindableBody {
				req.GetBody = nil
			}

			client := ghttp.NewClient(ta.lib, opts...)
			resp, err := client.Do(req)
			if tt.expectError {
				assert.Equal(0, si.bodyBytes)
				assert.Error(err)
			} else {
				assert.Equal(len(body), si.bodyBytes)
				assert.NoErrorFatal(err)
				assert.Equal(http.StatusOK, resp.StatusCode)
			}

		})
	}

}
