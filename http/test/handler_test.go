package test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	ghttp "github.com/golang-auth/go-gssapi/v3/http"
)

func TestHandler(t *testing.T) {
	assert := NewAssert(t)
	ta.useAsset(t, testKeytabRack|testCredCache)

	var initiatorName ghttp.InitiatorName

	handler := ghttp.NewHandler(ta.lib, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in, ok := ghttp.GetInitiatorName(r)
		if !ok {
			t.Fatalf("Failed to get initiator name")
		}
		initiatorName = *in
		w.WriteHeader(http.StatusOK)
	}))

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
