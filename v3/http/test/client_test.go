package test

import (
	"encoding/base64"
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
	sent401     bool
	authzHeader string
}

// The test server is a very cut down HTTP server that expects Negotiate authentication
// It is the acceptor side of a GSSAPI context establishment, and it will purposefully
// mess up the response if told to do so.
func newTestServer(t *testing.T, ignoreMutual bool, serverInfo *serverInfo) *httptest.Server {

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authzType, authzToken := parseAuthzHeader(&r.Header)
		if authzType == "Negotiate" && len(authzToken) > 0 {
			secCtx, err := ta.lib.AcceptSecContext()
			if err != nil {
				t.Fatalf("Failed to accept context: %v", err)
			}
			defer secCtx.Delete() //nolint:errcheck

			authzTokenBytes, err := base64.StdEncoding.DecodeString(authzToken)
			if err != nil {
				t.Fatalf("Failed to decode authz token: %v", err)
			}

			respToken, _, err := secCtx.Continue(authzTokenBytes)
			if err != nil {
				t.Fatalf("acceptor failed to continue context: %v", err)
			}
			respTokenBase64 := base64.StdEncoding.EncodeToString(respToken)
			if ignoreMutual {
				respTokenBase64 = "Ignoring you!"
			}
			w.Header().Set("Authorization", "Negotiate "+respTokenBase64)
			w.WriteHeader(http.StatusOK)
			serverInfo.authzHeader = r.Header.Get("Authorization")
		} else {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.WriteHeader(http.StatusUnauthorized)
			serverInfo.sent401 = true
		}
	}))
}

func TestClient(t *testing.T) {
	ta.useAsset(t, testCredCache|testKeytabRack)

	t.Log("KT:", ta.ktfileRack)

	tests := []struct {
		name             string
		clientMutual     bool
		clientPreemptive bool
		serverBadMutual  bool
		expect401        bool
		expectSuccess    bool
	}{
		{name: "No-Mutual-No-Preemptive", clientMutual: false, clientPreemptive: false, serverBadMutual: false, expect401: true, expectSuccess: true},
		{name: "No-Mutual-Preemptive", clientMutual: false, clientPreemptive: true, serverBadMutual: false, expect401: false, expectSuccess: true},
		{name: "Mutual-No-Preemptive", clientMutual: true, clientPreemptive: false, serverBadMutual: false, expect401: true, expectSuccess: true},
		{name: "Mutual-Preemptive", clientMutual: true, clientPreemptive: true, serverBadMutual: false, expect401: false, expectSuccess: true},
		{name: "Bad-Authz-Header", clientMutual: false, clientPreemptive: false, serverBadMutual: false, expect401: true, expectSuccess: false},
		{name: "Ignore-Mutual", clientMutual: true, clientPreemptive: false, serverBadMutual: true, expect401: false, expectSuccess: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := NewAssert(t)

			si := serverInfo{}
			ts := newTestServer(t, tt.serverBadMutual, &si)
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
			req, err := http.NewRequest("GET", ts.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to do request: %v", err)
			}

			if tt.expectSuccess {
				assert.Equal(http.StatusOK, resp.StatusCode)
			}
			if tt.expect401 {
				assert.True(si.sent401)
			}
		})
	}
}
