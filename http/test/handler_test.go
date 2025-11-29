package test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	gssapi "github.com/golang-auth/go-gssapi/v3"
	ghttp "github.com/golang-auth/go-gssapi/v3/http"
)

func mkTestHandler(t *testing.T, useCredStore bool) (http.Handler, *ghttp.InitiatorName) {
	var initiatorName ghttp.InitiatorName

	handleFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in, ok := ghttp.GetInitiatorName(r)
		if !ok {
			t.Fatalf("Failed to get initiator name")
		}
		initiatorName = *in
		w.WriteHeader(http.StatusOK)
	})

	opts := []ghttp.HandlerOption{}

	if useCredStore {
		// clear the keytab pointed to by KRB5_KTNAME
		ta.useAsset(t, testNoKeytab)

		opts = append(opts, ghttp.WithAcceptorCredentialStoreOptions(
			gssapi.WithCredStoreServerKeytab(ta.ktfileRack),
		))
	} else {
		ta.useAsset(t, testKeytabRack)
	}

	handler := ghttp.NewHandler(ta.lib, handleFunc, opts...)

	return handler, &initiatorName
}

func TestHandler(t *testing.T) {
	ta.useAsset(t, testCredCache)

	for _, useCredStore := range []bool{false, true} {
		t.Run(fmt.Sprintf("useCredStore=%t", useCredStore), func(t *testing.T) {
			if !ta.lib.HasExtension(gssapi.HasExtCredStore) {
				t.Skip("provider does not support credential store options")
			}

			assert := NewAssert(t)
			handler, initiatorName := mkTestHandler(t, useCredStore)

			server := httptest.NewServer(handler)
			defer server.Close()

			opts := []ghttp.ClientOption{
				ghttp.WithSpnFunc(func(url url.URL) string {
					return "HTTP@foo.golang-auth.io"
				}),
			}

			client := ghttp.NewClient(ta.lib, nil, opts...)
			req, err := http.NewRequest("GET", server.URL, nil)
			assert.NoErrorFatal(err)

			resp, err := client.Do(req)
			assert.NoErrorFatal(err)

			defer resp.Body.Close()

			assert.Equal(http.StatusOK, resp.StatusCode)

			// initiator name would only be available if GSSAPI authenticatinon happned
			assert.Equal(cliname, initiatorName.PrincipalName)
		})
	}
}

func TestHandlerNegotiateOnceBadInputToken(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testKeytabRack|testCredCache)

	handler := ghttp.NewHandler(ta.lib, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// not base 64 encoded
	_, _, err := handler.NegotiateOnce("Bad Token")
	assert.Error(err)

	// not a GSSAPI token
	_, _, err = handler.NegotiateOnce("YmFkIHRva2VuCg==")
	assert.Error(err)
}
