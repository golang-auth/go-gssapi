package http

import (
	"encoding/base64"
	"fmt"
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

type Client struct {
	*http.Client

	provider   gssapi.Provider
	credential gssapi.Credential
	spnFunc    SpnFunc
	preemptive bool
	mutual     bool
}

type ClientOption func(c *Client)

func WithPreemptive() ClientOption {
	return func(c *Client) {
		c.preemptive = true
	}
}

func WithMutual() ClientOption {
	return func(c *Client) {
		c.mutual = true
	}
}

func WithCredential(cred gssapi.Credential) ClientOption {
	return func(c *Client) {
		c.credential = cred
	}
}

func WithSpnFunc(spnFunc SpnFunc) ClientOption {
	return func(c *Client) {
		c.spnFunc = spnFunc
	}
}

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

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	var secCtx gssapi.SecContext
	var err error

	if c.preemptive {
		secCtx, err = c.setInitialToken(req)
		if err != nil {
			return nil, err
		}
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
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

	// If we are doing mutual auth (which is dubious for HTTP), we need to
	// validate the response token.
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
			if info.Flags&gssapi.ContextFlagMutual == 0 && c.mutual {
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
