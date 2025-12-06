// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	cb "github.com/golang-auth/go-channelbinding"
	"github.com/golang-auth/go-gssapi/v3"
)

type ChannelBindingDisposition int

const (
	ChannelBindingDispositionIgnore ChannelBindingDisposition = iota
	ChannelBindingDispositionIfAvailable
	ChannelBindingDispositionRequire
)

func krbEndpointBinding(tlsState *tls.ConnectionState, serverCert *x509.Certificate) (*gssapi.ChannelBinding, error) {
	if serverCert == nil {
		// must be the client then -- the server cert is in the peer certificates list
		if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
			return nil, fmt.Errorf("no server certificate found in TLS connection state, needed for channel binding")
		}
		serverCert = tlsState.PeerCertificates[0]
	}

	data, err := cb.MakeTLSChannelBinding(*tlsState, serverCert, cb.TLSChannelBindingEndpoint)
	if err != nil {
		return nil, fmt.Errorf("channel binding: %w", err)
	}

	binding := &gssapi.ChannelBinding{
		Data: data,
	}
	return binding, nil
}
