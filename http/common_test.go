package http

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCertificate creates a self-signed certificate for testing
func createTestCertificate(t *testing.T) *x509.Certificate {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: nil,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestKrbEndpointBinding(t *testing.T) {
	tests := []struct {
		name        string
		tlsState    *tls.ConnectionState
		serverCert  *x509.Certificate
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid server cert provided",
			tlsState: &tls.ConnectionState{
				Version:     tls.VersionTLS13,
				CipherSuite: tls.TLS_AES_128_GCM_SHA256,
			},
			serverCert:  createTestCertificate(t),
			expectError: false,
		},
		{
			name: "valid peer certificate in TLS state",
			tlsState: &tls.ConnectionState{
				Version:          tls.VersionTLS13,
				CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
				PeerCertificates: []*x509.Certificate{createTestCertificate(t)},
			},
			serverCert:  nil,
			expectError: false,
		},
		{
			name:        "nil TLS state and nil server cert",
			tlsState:    nil,
			serverCert:  nil,
			expectError: true,
			errorMsg:    "no server certificate found in TLS connection state, needed for channel binding",
		},
		{
			name: "empty peer certificates in TLS state",
			tlsState: &tls.ConnectionState{
				Version:          tls.VersionTLS13,
				CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
				PeerCertificates: []*x509.Certificate{},
			},
			serverCert:  nil,
			expectError: true,
			errorMsg:    "no server certificate found in TLS connection state, needed for channel binding",
		},
		{
			name: "TLS state with nil peer certificates",
			tlsState: &tls.ConnectionState{
				Version:          tls.VersionTLS13,
				CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
				PeerCertificates: nil,
			},
			serverCert:  nil,
			expectError: true,
			errorMsg:    "no server certificate found in TLS connection state, needed for channel binding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding, err := krbEndpointBinding(tt.tlsState, tt.serverCert)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, binding)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, binding)
				assert.NotNil(t, binding.Data)
				assert.Greater(t, len(binding.Data), 0, "Channel binding data should not be empty")
			}
		})
	}
}

func TestKrbEndpointBinding_ServerCertPriority(t *testing.T) {
	// Test that when both serverCert and peer certificates are provided,
	// the explicitly provided serverCert takes precedence
	cert1 := createTestCertificate(t)
	cert2 := createTestCertificate(t)

	tlsState := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{cert2},
	}

	binding1, err1 := krbEndpointBinding(tlsState, cert1)
	require.NoError(t, err1)

	binding2, err2 := krbEndpointBinding(tlsState, nil)
	require.NoError(t, err2)

	// The bindings should be different since different certificates were used
	assert.NotEqual(t, binding1.Data, binding2.Data, "Channel bindings should differ when using different certificates")
}

func TestKrbEndpointBinding_ConsistentOutput(t *testing.T) {
	// Test that the same inputs produce the same output
	cert := createTestCertificate(t)
	tlsState := &tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
	}

	binding1, err1 := krbEndpointBinding(tlsState, cert)
	require.NoError(t, err1)

	binding2, err2 := krbEndpointBinding(tlsState, cert)
	require.NoError(t, err2)

	assert.Equal(t, binding1.Data, binding2.Data, "Same inputs should produce identical channel bindings")
}
