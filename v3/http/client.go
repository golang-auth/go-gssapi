// SPDX-License-Identifier: Apache-2.0

/*
Package http provides a GSSAPI enabled http.Client.

[Client] is a wrapper around the http.Client that adds GSSAPI authentication
to the client.

[WithNegotiate] creates a new [Client] with the given GSSAPI provider and options.

[NewClient] creates a new [Client] with the given GSSAPI provider and options.

[Client.Do] sends an HTTP request and returns an HTTP response, following
policy (such as redirects, cookies, auth) as configured on the client.
*/
package http

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-auth/go-gssapi/v3"
)

// SpnFunc is a function that returns the Service Principal Name (SPN) for a given URL.
type SpnFunc func(url url.URL) string

func defaultSpnFunc(url url.URL) string {
	return "HTTP@" + url.Host
}

// DefaultSpnFunc is the default SPN function used for new clients.
var DefaultSpnFunc SpnFunc = defaultSpnFunc

// Client is an http.Client that supports GSSAPI authentication.  It is a wrapper around the http.Client
type Client struct {
	*http.Client

	provider    gssapi.Provider
	credential  gssapi.Credential
	spnFunc     SpnFunc
	preemptive  bool
	mutual      bool
	noExpect100 bool
}

// ClientOption is a function that configures a Client
type ClientOption func(c *Client)

// WithPreemptive configures the client to preemptively authenticate
//
// Preemptive authentication means that the client does not wait for the server to
// respond with a 401 status code before sending an authentication token.  This
// is a performance optimization that can be used to reduce the number of round trips
// between the client and server, at the cost of initializing the GSSAPI context and
// potentially exposing authentcation credentials to the server unnecessarily.
func WithPreemptive() ClientOption {
	return func(c *Client) {
		c.preemptive = true
	}
}

// WithMutual configures the client to request mutual authentication
//
// Mutual authentication means that the client and server both authenticate each other.
// It causes the server to respond with a GSSAPI authentication token in the Authorization header
// that the client can use to complete the context establishment and verify the server's identity.
func WithMutual() ClientOption {
	return func(c *Client) {
		c.mutual = true
	}
}

// WithCredential configures the client to use a specific credential
func WithCredential(cred gssapi.Credential) ClientOption {
	return func(c *Client) {
		c.credential = cred
	}
}

// WithSpnFunc provides a custom function to provide the Service Principal Name (SPN) for a given URL.
//
// The default uses "HTTP@" + the host name of the URL.
func WithSpnFunc(spnFunc SpnFunc) ClientOption {
	return func(c *Client) {
		c.spnFunc = spnFunc
	}
}

// WithNoExpect100 disables the use of the Expect: Continue header
//
// By default, the client will send the Expect: Continue header if there is a request body to send,
// so that the server can let the client know when it has authenticated the client and is ready to receive
// the request body.
//
// If this option is enabled, the client will not send the Expect header, and will instead
// send the request body immediately.  This can be useful to work around servers that do not honour the Expect
// header or as an optimization when used in conjunction with WithPreemptive.  Care should be taken when enabling
// this option when not using WithPreemptive as the request will fail if the request body is not rewindable.
func WithNoExpect100() ClientOption {
	return func(c *Client) {
		c.noExpect100 = true
	}
}

// WithNegotiate wraps an existing http.Client with a GSSAPI client.
//
// The provider is the GSSAPI provider to use for authentication.
// The options are the ClientOptions to use for the client.
//
// If client is nil, the default http.Client will be used.
func WithNegotiate(client *http.Client, provider gssapi.Provider, options ...ClientOption) Client {
	if client == nil {
		client = http.DefaultClient
	}
	c := Client{
		Client:   client,
		provider: provider,
		spnFunc:  DefaultSpnFunc,
	}
	for _, option := range options {
		option(&c)
	}
	return c
}

// NewClient creates a new Client with the given GSSAPI provider and options.
//
// The provider is the GSSAPI provider to use for authentication.
// The options are the ClientOptions to use for the client.
func NewClient(provider gssapi.Provider, options ...ClientOption) Client {
	return WithNegotiate(nil, provider, options...)
}

func (c *Client) setInitialToken(req *http.Request) (gssapi.SecContext, error) {
	spn := c.spnFunc(*req.URL)
	spnName, err := c.provider.ImportName(spn, gssapi.GSS_NT_HOSTBASED_SERVICE)
	if err != nil {
		return nil, err
	}
	defer spnName.Release()

	// always request integrity
	flags := gssapi.ContextFlagInteg
	if c.mutual {
		// optionally request mutual authentication
		flags |= gssapi.ContextFlagMutual
	}

	opts := []gssapi.InitSecContextOption{
		gssapi.WithInitiatorFlags(flags),
	}

	secCtx, err := c.provider.InitSecContext(spnName, opts...)
	if err != nil {
		return nil, err
	}
	token, _, err := secCtx.Continue(nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))

	return secCtx, nil
}

// Post issues a POST to the specified URL.
//
// Caller should close resp.Body when done reading from it.
//
// If the provided body is an [io.Closer], it is closed after the
// request.
//
// To set custom headers, use [NewRequest] and [Client.Do].
//
// To make a request with a specified context.Context, use [NewRequestWithContext]
// and [Client.Do].
//
// See the [Client.Do] method documentation for details on how redirects
// are handled.
func (c *Client) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// Get issues a GET to the specified URL. If the response is one of the
// following redirect codes, Get follows the redirect after calling the
// [Client.CheckRedirect] function:
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// An error is returned if the [Client.CheckRedirect] function fails
// or if there was an HTTP protocol error. A non-2xx response doesn't
// cause an error. Any returned error will be of type [*url.Error]. The
// url.Error value's Timeout method will report true if the request
// timed out.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// To make a request with custom headers, use [NewRequest] and [Client.Do].
//
// To make a request with a specified context.Context, use [NewRequestWithContext]
// and Client.Do.
func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Head issues a HEAD to the specified URL. If the response is one of the
// following redirect codes, Head follows the redirect after calling the
// [Client.CheckRedirect] function:
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// To make a request with a specified [context.Context], use [NewRequestWithContext]
// and [Client.Do].
func (c *Client) Head(url string) (*http.Response, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// PostForm issues a POST to the specified URL,
// with data's keys and values URL-encoded as the request body.
//
// The Content-Type header is set to application/x-www-form-urlencoded.
// To set other headers, use [NewRequest] and [Client.Do].
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// See the [Client.Do] method documentation for details on how redirects
// are handled.
//
// To make a request with a specified context.Context, use [NewRequestWithContext]
// and Client.Do.
func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// Do sends an HTTP request and returns an HTTP response, following
// policy (such as redirects, cookies, auth) as configured on the
// client.
//
// An error is returned if caused by client policy (such as
// CheckRedirect), or failure to speak HTTP (such as a network
// connectivity problem). A non-2xx status code doesn't cause an
// error.
//
// If the returned error is nil, the [Response] will contain a non-nil
// Body which the user is expected to close. If the Body is not both
// read to EOF and closed, the [Client]'s underlying [RoundTripper]
// (typically [Transport]) may not be able to re-use a persistent TCP
// connection to the server for a subsequent "keep-alive" request.
//
// The request Body, if non-nil, will be closed by the underlying
// Transport, even on errors. The Body may be closed asynchronously after
// Do returns.
//
// On error, any Response can be ignored. A non-nil Response with a
// non-nil error only occurs when CheckRedirect fails, and even then
// the returned [Response.Body] is already closed.
//
// Generally [Get], [Post], or [PostForm] will be used instead of Do.
//
// If the server replies with a redirect, the Client first uses the
// CheckRedirect function to determine whether the redirect should be
// followed. If permitted, a 301, 302, or 303 redirect causes
// subsequent requests to use HTTP method GET
// (or HEAD if the original request was HEAD), with no body.
// A 307 or 308 redirect preserves the original HTTP method and body,
// provided that the [Request.GetBody] function is defined.
// The [NewRequest] function automatically sets GetBody for common
// standard library body types.
//
// Any returned error will be of type [*url.Error]. The url.Error
// value's Timeout method will report true if the request timed out.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	var secCtx gssapi.SecContext
	var err error

	defer func() {
		if secCtx != nil {
			secCtx.Delete() //nolint:errcheck
		}
	}()

	// Preemptively set the initial token if preemptive authentication is requested
	if c.preemptive {
		secCtx, err = c.setInitialToken(req)
		if err != nil {
			return nil, err
		}
	}

	// Don't send the body until the server has authenticated us.  Unfortunately the server
	// won't send us its mutual authentication token with its 100-Continue response (we only see
	// that after it has processed the request)so this doesn't allow us to verify the server's identity
	// before sending it the request body.
	if req.Body != nil && !c.noExpect100 {
		req.Header.Set("Expect", "100-continue")
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	// Redo the request with an initial token if we didn't already send one preemptively
	if resp.StatusCode == 401 && !c.preemptive {
		secCtx, err = c.setInitialToken(req)
		if err != nil {
			return nil, err
		}

		resp, err = c.Client.Do(req)
		if err != nil {
			return nil, err
		}
	}

	// If we are doing mutual auth (which is of dubious value for HTTP), we need to
	// validate the response token.  At least we can catch a trojan server even if we
	// will have sent it the request body already.
	if resp.StatusCode != 401 && c.mutual {
		authzType, authzToken := parseAuthzHeader(&resp.Header)

		// Validate the response token - which will be supplied if we're doing
		// mutual authentication.
		if authzType == "Negotiate" && len(authzToken) > 0 {
			rawToken, err := base64.StdEncoding.DecodeString(authzToken)
			if err != nil {
				return nil, err
			}
			_, info, err := secCtx.Continue(rawToken)
			if err != nil {
				return nil, err
			}

			// verify that we have the flags we requested
			if info.Flags&gssapi.ContextFlagMutual == 0 {
				return nil, fmt.Errorf("mutual authentication requested but not available")
			}
		} else {
			return nil, fmt.Errorf("no response token - required for mutual authentication")
		}

	}
	return resp, nil
}

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
