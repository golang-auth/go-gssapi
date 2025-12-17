package test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	gssapi "github.com/golang-auth/go-gssapi/v3"
	ghttp "github.com/golang-auth/go-gssapi/v3/http"
)

func TestHandler(t *testing.T) {
	ta.useAsset(t, testKeytabRack|testCredCache)

	type testCase struct {
		name                               string
		initiatorChannelBindingDisposition ghttp.ChannelBindingDisposition
		acceptorChannelBindingDisposition  ghttp.ChannelBindingDisposition
		expectedChannelBindingPresent      bool
		expectStatus                       int
		expectedInitiatorName              string
	}

	tests := []testCase{
		{
			name:                               "No Channel Bindings",
			initiatorChannelBindingDisposition: ghttp.ChannelBindingDispositionIgnore,
			acceptorChannelBindingDisposition:  ghttp.ChannelBindingDispositionIgnore,
			expectedChannelBindingPresent:      false,
			expectStatus:                       http.StatusOK,
			expectedInitiatorName:              cliname,
		},
		{
			name:                               "CB:init=ignore:acc=ifavail",
			initiatorChannelBindingDisposition: ghttp.ChannelBindingDispositionIgnore,
			acceptorChannelBindingDisposition:  ghttp.ChannelBindingDispositionIfAvailable,
			expectedChannelBindingPresent:      false,
			expectStatus:                       http.StatusOK,
			expectedInitiatorName:              cliname,
		},
		{
			name:                               "CB:init=ifavail:acc=ignore",
			initiatorChannelBindingDisposition: ghttp.ChannelBindingDispositionIfAvailable,
			acceptorChannelBindingDisposition:  ghttp.ChannelBindingDispositionIgnore,
			expectedChannelBindingPresent:      false,
			expectStatus:                       http.StatusOK,
			expectedInitiatorName:              cliname,
		},
	}

	if ta.lib.HasExtension(gssapi.HasExtChannelBindingSignalling) {
		tests = append(tests, []testCase{
			{
				name:                               "CB:init=ifavail:acc=ifavail",
				initiatorChannelBindingDisposition: ghttp.ChannelBindingDispositionIfAvailable,
				acceptorChannelBindingDisposition:  ghttp.ChannelBindingDispositionIfAvailable,
				expectedChannelBindingPresent:      true,
				expectStatus:                       http.StatusOK,
				expectedInitiatorName:              cliname,
			},
			{
				name:                               "CB:init=ifavail:acc=require",
				initiatorChannelBindingDisposition: ghttp.ChannelBindingDispositionIfAvailable,
				acceptorChannelBindingDisposition:  ghttp.ChannelBindingDispositionRequire,
				expectedChannelBindingPresent:      true,
				expectStatus:                       http.StatusOK,
				expectedInitiatorName:              cliname,
			},
			{
				name:                               "CB:init=ignore:acc=require",
				initiatorChannelBindingDisposition: ghttp.ChannelBindingDispositionIgnore,
				acceptorChannelBindingDisposition:  ghttp.ChannelBindingDispositionRequire,
				expectedChannelBindingPresent:      false,
				expectStatus:                       http.StatusForbidden,
			},
			// TODO: this doesn't seem to work - it should result in the authenticator being stamped with
			// the KERB_AP_OPTIONS_CBT extension but that doesn't seem to be the case on Fedora 42 with MIT 1.21
			// {
			// 	name:                               "CB:init=require:acc=ignore",
			// 	initiatorChannelBindingDisposition: ghttp.ChannelBindingDispositionRequire,
			// 	acceptorChannelBindingDisposition:  ghttp.ChannelBindingDispositionIgnore,
			// 	expectedChannelBindingPresent:      false,
			// 	expectStatus:                       http.StatusForbidden,
			// },
		}...)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := NewAssert(t)
			var initiatorName ghttp.InitiatorName
			var channelBindingPresent bool
			handlerOptions := []ghttp.HandlerOption{}

			if tt.acceptorChannelBindingDisposition != ghttp.ChannelBindingDispositionIgnore {
				handlerOptions = append(handlerOptions, ghttp.WithAcceptorChannelBindingDisposition(tt.acceptorChannelBindingDisposition))
			}

			handler, err := ghttp.NewHandler(ta.lib, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				in, ok := ghttp.GetInitiatorName(r)
				if !ok {
					t.Fatalf("Failed to get initiator name")
				}
				initiatorName = *in
				channelBindingPresent = ghttp.HasChannelBindings(r)
				w.WriteHeader(http.StatusOK)
			}), handlerOptions...)

			assert.NoErrorFatal(err)

			server := httptest.NewUnstartedServer(handler)
			defer server.Close()

			server.Config = ghttp.ServerWithStashConn(server.Config)

			// Todo: enable when Go 1.24 is deprecated
			//server.Config.ErrorLog = log.New(t.Output(), t.Name()+": ", 0)

			server.StartTLS()

			if enableLogging() {
				// for discecting in Wireshark
				server.TLS.KeyLogWriter = os.Stdout
			}

			// Copy the TLS config into the server -- why doesn't httptest do this?
			server.Config.TLSConfig = server.TLS

			client := server.Client()

			opts := []ghttp.ClientOption{
				ghttp.WithInitiatorSpnFunc(func(url url.URL) string {
					return "HTTP@foo.golang-auth.io"
				}),
			}

			if tt.initiatorChannelBindingDisposition != ghttp.ChannelBindingDispositionIgnore {
				opts = append(opts, ghttp.WithInitiatorChannelBindingDisposition(tt.initiatorChannelBindingDisposition))
			}

			client, err = ghttp.NewClient(ta.lib, client, opts...)
			assert.NoErrorFatal(err)
			req, err := http.NewRequest("GET", server.URL, nil)
			assert.NoErrorFatal(err)

			resp, err := client.Do(req)
			assert.NoErrorFatal(err)

			defer resp.Body.Close()

			assert.Equal(tt.expectStatus, resp.StatusCode)

			// initiator name would only be available if GSSAPI authentication happned
			assert.Equal(tt.expectedInitiatorName, initiatorName.PrincipalName)
			// check channel binding present
			assert.Equal(tt.expectedChannelBindingPresent, channelBindingPresent)
		})
	}

}

type testResponseWriter struct {
	headers http.Header
	code    int
}

func newTestResponseWriter() *testResponseWriter {
	return &testResponseWriter{
		headers: make(http.Header),
	}
}

func (w *testResponseWriter) WriteHeader(code int) {
	w.code = code
}

func (w *testResponseWriter) Header() http.Header {
	return w.headers
}

func (w *testResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func TestHandlerNegotiateBadInputToken(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testKeytabRack|testCredCache)

	handler, err := ghttp.NewHandler(ta.lib, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	assert.NoErrorFatal(err)

	req := httptest.NewRequest("GET", "/", nil)

	// not base 64 encoded
	w := newTestResponseWriter()
	req.Header.Set("Authorization", "Negotiate BadToken")
	handler.ServeHTTP(w, req)
	assert.Equal(http.StatusForbidden, w.code)

	// not a GSSAPI token
	w = newTestResponseWriter()
	req.Header.Set("Authorization", "Negotiate YmFkIHRva2VuCg==")
	handler.ServeHTTP(w, req)
	assert.Equal(http.StatusForbidden, w.code)

	// No negotiate header at all (not an error..)
	w = newTestResponseWriter()
	req.Header.Set("Authorization", "Bearer token")
	handler.ServeHTTP(w, req)
	assert.Equal(http.StatusUnauthorized, w.code)
}
