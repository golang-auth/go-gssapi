// SPDX-License-Identifier: Apache-2.0

package http

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-auth/go-gssapi/v3"
)

// SpnFunc is a function that returns the Service Principal Name (SPN) for a given URL.
type SpnFunc func(url url.URL) string

func defaultSpnFunc(url url.URL) string {
	return "HTTP@" + url.Host
}

// DefaultSpnFunc is the default SPN function used for new clients.
var DefaultSpnFunc SpnFunc = defaultSpnFunc

// OpportunisticFunc is a function that returns true if opportunistic authentication should be used for a given URL.
type OpportunisticFunc func(url url.URL) bool

func opportunisticsFuncAlways(url url.URL) bool {
	return true
}

// DelegationPolicy is the policy for delegation of credentials to the server.
type DelegationPolicy int

const (
	// DelegationPolicyNever means that credentials will not be delegated to the server.
	DelegationPolicyNever DelegationPolicy = iota
	// DelegationPolicyAlways means that credentials will be delegated to the server.
	DelegationPolicyAlways
	// DelegationPolicyIfAllowed means that credentials will be delegated to the server
	// if the policy (eg. Kerberos OK-as-delegate policy) allows it.
	DelegationPolicyIfAllowed
)

// DefaultDelegationPolicy is the default delegation policy used for new clients.
var DefaultDelegationPolicy DelegationPolicy = DelegationPolicyNever

// GSSAPITransport is a http.RoundTripper implementation that includes GSSAPI
// (HTTP Negotiate) authentication.
type GSSAPITransport struct {
	transport http.RoundTripper

	provider           gssapi.Provider
	credential         gssapi.Credential
	spnFunc            SpnFunc
	opportunisticFunc  OpportunisticFunc
	delegationPolicy   DelegationPolicy
	mutual             bool
	expect100Threshold int64

	httpLogging bool
	logFunc     func(format string, args ...interface{})
}

// ClientOption is a function that configures a Client
type ClientOption func(c *GSSAPITransport)

// WithOpportunistic configures the client to opportunisticly authenticate
//
// Opportunistic authentication means that the client does not wait for the server to
// respond with a 401 status code before sending an authentication token.  This
// is a performance optimization that can be used to reduce the number of round trips
// between the client and server, at the cost of initializing the GSSAPI context and
// potentially exposing authentcation credentials to the server unnecessarily.
func WithOpportunistic() ClientOption {
	return func(c *GSSAPITransport) {
		c.opportunisticFunc = opportunisticsFuncAlways
	}
}

// WithOpportunisticFunc configures the client to use a custom function to determine
// if opportunistic authentication should be used for a given URL.
func WithOpportunisticFunc(opportunisticFunc OpportunisticFunc) ClientOption {
	return func(c *GSSAPITransport) {
		c.opportunisticFunc = opportunisticFunc
	}
}

// WithMutual configures the client to request mutual authentication
//
// Mutual authentication means that the client and server both authenticate each other.
// It causes the server to respond with a GSSAPI authentication token in the Authorization header
// that the client can use to complete the context establishment and verify the server's identity.
func WithMutual() ClientOption {
	return func(c *GSSAPITransport) {
		c.mutual = true
	}
}

// WithCredential configures the client to use a specific credential
func WithCredential(cred gssapi.Credential) ClientOption {
	return func(c *GSSAPITransport) {
		c.credential = cred
	}
}

// WithSpnFunc provides a custom function to provide the Service Principal Name (SPN) for a given URL.
//
// The default uses "HTTP@" + the host name of the URL.
func WithSpnFunc(spnFunc SpnFunc) ClientOption {
	return func(c *GSSAPITransport) {
		c.spnFunc = spnFunc
	}
}

// WithDelegationPolicy configures the client to use a custom credential delegation policy.
func WithDelegationPolicy(delegationPolicy DelegationPolicy) ClientOption {
	return func(c *GSSAPITransport) {
		c.delegationPolicy = delegationPolicy
	}
}

// WithExpect100Threshold configures the client to use the Expect: Continue header
// if the request body is larger than the threshold.
//
// Use of the Expect: Continue header is disabled by default due to concerns about the
// correct implementation by some servers.
func WithExpect100Threshold(threshold int64) ClientOption {
	return func(c *GSSAPITransport) {
		c.expect100Threshold = threshold
	}
}

// WithRoundTripper configures the client to use a custom round tripper
func WithRoundTripper(transport http.RoundTripper) ClientOption {
	return func(c *GSSAPITransport) {
		c.transport = transport
	}
}

// WithHttpLogging configures the client to log the HTTP requests and responses
// Does nothing without a log function
func WithHttpLogging() ClientOption {
	return func(c *GSSAPITransport) {
		c.httpLogging = true
	}
}

// WithLogFunc configures the client to use a custom log function
func WithLogFunc(logFunc func(format string, args ...interface{})) ClientOption {
	return func(c *GSSAPITransport) {
		c.logFunc = logFunc
	}
}

// NewTransport creates a new GSSAPI transport with the given provider and options.
//
// The transport is a wrapper around the standard [http.Transport] that adds GSSAPI
// authentication support. By default it wraps [http.DefaultTransport] - this can be
// overridden by passing a custom round tripper with [WithRoundTripper].
func NewTransport(provider gssapi.Provider, options ...ClientOption) *GSSAPITransport {
	t := &GSSAPITransport{
		transport:        http.DefaultTransport,
		provider:         provider,
		delegationPolicy: DefaultDelegationPolicy,
	}
	for _, option := range options {
		option(t)
	}
	if t.httpLogging && t.logFunc == nil {
		t.httpLogging = false
	}
	return t
}

// NewClient returns a [http.Client] that uses [GSSAPITransport] to enable GSSAPI authentication.
//
// If an existing client is provided, it will be copied and the [http.RoundTripper] will be replaced with a
// new [GSSAPITransport].  Otherwise the default [http.Client] will be used. The [http.RoundTripper] in the
// returned client will wrap the transport from the supplied client or [http.DefaultTransport].
func NewClient(provider gssapi.Provider, client *http.Client, options ...ClientOption) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}

	if client.Transport != nil {
		options = append(options, WithRoundTripper(client.Transport))
	}

	// Copy the client to avoid modifying the original
	newClient := *client
	newClient.Transport = NewTransport(provider, options...)
	return &newClient
}

func (t *GSSAPITransport) initSecContext(req *http.Request) (gssapi.SecContext, error) {
	spn := t.spnFunc(*req.URL)
	spnName, err := t.provider.ImportName(spn, gssapi.GSS_NT_HOSTBASED_SERVICE)
	if err != nil {
		return nil, err
	}
	defer spnName.Release() //nolint:errcheck

	// always request integrity
	flags := gssapi.ContextFlagInteg
	if t.mutual {
		// optionally request mutual authentication
		flags |= gssapi.ContextFlagMutual
	}
	switch t.delegationPolicy {
	case DelegationPolicyAlways:
		flags |= gssapi.ContextFlagDeleg
	case DelegationPolicyIfAllowed:
		flags |= gssapi.ContextFlagDelegPolicy
	}

	opts := []gssapi.InitSecContextOption{
		gssapi.WithInitiatorFlags(flags),
	}

	secCtx, err := t.provider.InitSecContext(spnName, opts...)
	if err != nil {
		return nil, err
	}

	return secCtx, nil
}

func (t *GSSAPITransport) continueSecContext(secCtx gssapi.SecContext, inToken string, req *http.Request) (*gssapi.SecContextInfoPartial, error) {
	var rawInToken []byte
	var err error
	if inToken != "" {
		rawInToken, err = base64.StdEncoding.DecodeString(inToken)
		if err != nil {
			return nil, err
		}
	}

	outToken, info, err := secCtx.Continue(rawInToken)
	if err != nil {
		return nil, err
	}

	if outToken != nil {
		req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(outToken))
	}

	return &info, nil
}

// Use the underlying transport's RoundTripper wrapped in HTTP logging
// if enabled.
func (t *GSSAPITransport) roundTrip(req *http.Request) (*http.Response, error) {
	if t.httpLogging {
		err := t.requestLogging(req)
		if err != nil {
			return nil, err
		}
	}

	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if t.httpLogging {
		err := t.responseLogging(resp)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// RoundTrip implements the [http.RoundTripper] interface and performs one HTTP
// request, including potentially multiple round-trips to the server to complete the
// GSSAPI context establishment.
func (t *GSSAPITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.httpLogging {
		req = t.setupLogging(req)
	}

	var info *gssapi.SecContextInfoPartial = nil

	// We are not meant to modify the request, so we need to create a new one
	req = req.Clone(req.Context())

	secCtx, err := t.initSecContext(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		if secCtx != nil {
			secCtx.Delete() //nolint:errcheck
		}
	}()

	// Should we opportunistically set the initial token?
	useOpportunistic := t.opportunisticFunc != nil && t.opportunisticFunc(*req.URL)

	// use Expect: Continue for large requests or if we can't rewind the body, when we're not doing opportunistic authentication
	if !useOpportunistic && t.expect100Threshold > 0 {
		useExpect100 := false
		if req.ContentLength > t.expect100Threshold {
			t.logFunc("Using Expect: Continue header because request body is larger than %d bytes", t.expect100Threshold)
			useExpect100 = true
		} else if req.GetBody == nil {
			t.logFunc("Using Expect: Continue header because request body is not rewindable and opportunistic authentication is not requested")
			useExpect100 = true
		}
		if useExpect100 {
			req.Header.Set("Expect", "100-continue")
		}
	}

	var resp *http.Response = nil
contextLoop:
	for {
		var err error
		inToken := ""

		// Skip the server round-trip if we are doing opportunistic authentication and haven't started auth yet
		if !(info == nil && useOpportunistic) {
			// Send the request / get a response
			resp, err = t.roundTrip(req)
			if err != nil {
				return nil, err
			}

			// Check for a negotiate challenge in the response - which can be in a 401 or any other final response
			challenges := findSchemeChallenges(&resp.Header, "Negotiate")
			switch len(challenges) {
			default:
				return nil, fmt.Errorf("multiple negotiate challenges found in response")
			case 0:
				// no challenge - the context should be fully established or never have started (eg. URL doesn't need auth)
				break contextLoop
			case 1:
				// one challenge - this is the initial challenge or a subsequent challenge
				negotiateChallenge := challenges[0]

				// Negotiate doesn't use parameters
				if len(negotiateChallenge.Parameters) > 0 {
					return nil, fmt.Errorf("negotiate challenge must not have parameters")
				}

				// The challenge should have a token unless this is a 401 response
				if negotiateChallenge.Token68 == "" && resp.StatusCode != 401 {
					return nil, fmt.Errorf("negotiate challenge must have a token unless this is a 401 response")
				}

				// The challenege should have a token if we have already started authentication
				if negotiateChallenge.Token68 == "" && info != nil {
					return nil, fmt.Errorf("empty challenge received during context establishment")
				}
				inToken = negotiateChallenge.Token68
			}
		}

		if secCtx.ContinueNeeded() {
			// leaves any token that needs to be send to the server in the request's Authorization header
			// which will be sent in the next round trip
			info, err = t.continueSecContext(secCtx, inToken, req)
			if err != nil {
				return nil, err
			}

			// We don't need to send anytihng to the server if it didn't challenge us,
			// as long as we've already got a response (not the first RT of an opportunistic request)
			if resp != nil && resp.StatusCode != 401 {
				break contextLoop
			}

		} else {
			break contextLoop
		}
	}

	// If we never started authentication then we should return the response we got
	if info == nil {
		return resp, nil
	}

	// We started authenticaiton and should be fully established by now
	if !info.FullyEstablished {
		return nil, fmt.Errorf("context not fully established")
	}

	// verify that we have the flags we requested
	if t.mutual && info.Flags&gssapi.ContextFlagMutual == 0 {
		return nil, fmt.Errorf("mutual authentication requested but not available")
	}

	if t.delegationPolicy == DelegationPolicyAlways && info.Flags&gssapi.ContextFlagDeleg == 0 {
		return nil, fmt.Errorf("delegation requested but not available")
	}

	return resp, nil
}
