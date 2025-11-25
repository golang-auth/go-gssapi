// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"errors"
	"net"
	"testing"
	"time"
)

type someProvider struct {
	name string
}

func (p someProvider) Release() error {
	return nil
}

func (p someProvider) Name() string {
	return p.name
}

func (someProvider) ImportName(name string, nameType GssNameType) (GssName, error) {
	return nil, nil
}

func (someProvider) AcquireCredential(name GssName, mechs []GssMech, usage CredUsage, lifetime *GssLifetime) (Credential, error) {
	return nil, nil
}

func (someProvider) InitSecContext(name GssName, opts ...InitSecContextOption) (SecContext, error) {
	return nil, nil
}

func (someProvider) AcceptSecContext(opts ...AcceptSecContextOption) (SecContext, error) {
	return nil, nil
}

func (someProvider) ImportSecContext(b []byte) (SecContext, error) {
	return nil, nil
}

func (someProvider) InquireNamesForMech(m GssMech) ([]GssNameType, error) {
	return nil, nil
}

func (someProvider) IndicateMechs() ([]GssMech, error) {
	return nil, nil
}

func (someProvider) HasExtension(e GssapiExtension) bool {
	return false
}

func TestRegister(t *testing.T) {
	assert := NewAssert(t)

	registry.libs = make(map[string]ProviderConstructor)

	assert.Equal(0, len(registry.libs))

	constructor := func() (Provider, error) {
		return someProvider{name: "TEST"}, nil
	}

	RegisterProvider("test", constructor)
	assert.Equal(1, len(registry.libs))
	f, ok := registry.libs["test"]
	assert.True(ok)
	assert.NotNil(f)

	p, err := NewProvider("test")
	assert.NoError(err)
	assert.NotNil(p)
	sp, ok := p.(someProvider)
	assert.True(ok)
	assert.Equal("TEST", sp.name)

	p, err = NewProvider("xyz")
	assert.Error(err)
	assert.Nil(p)

	assert.NotPanics(func() { MustNewProvider("test") })
	assert.Panics(func() { MustNewProvider("") })
	assert.Panics(func() { MustNewProvider("xyz") })
}

func TestNewProvider(t *testing.T) {
	assert := NewAssert(t)

	registry.libs = make(map[string]ProviderConstructor)

	// Register a valid provider
	constructor := func() (Provider, error) {
		return someProvider{name: "PROVIDER1"}, nil
	}
	RegisterProvider("provider1", constructor)

	// Case: provider exists, should succeed
	p, err := NewProvider("provider1")
	assert.NoErrorFatal(err)
	assert.NotNil(p)
	if sp, ok := p.(someProvider); assert.True(ok) {
		assert.Equal("PROVIDER1", sp.name)
	}

	// Case: provider not registered, should error
	p2, err2 := NewProvider("does_not_exist")
	assert.Error(err2)
	assert.Nil(p2)

	// Case: constructor returns an error
	badConstructor := func() (Provider, error) {
		return nil, errors.New("test constructor error")
	}
	RegisterProvider("badprovider", badConstructor)

	p3, err3 := NewProvider("badprovider")
	assert.Error(err3)
	assert.Nil(p3)
}

func TestMustNewProvider(t *testing.T) {
	assert := NewAssert(t)

	registry.libs = make(map[string]ProviderConstructor)

	// Register a valid provider
	RegisterProvider("provider42", func() (Provider, error) {
		return someProvider{name: "PROVIDER42"}, nil
	})

	// Should not panic for a valid provider
	assert.NotPanics(func() {
		p := MustNewProvider("provider42")
		assert.NotNil(p)
	})

	// Should panic for non-existent provider
	assert.Panics(func() { MustNewProvider("nope") })

	// Should panic if the constructor returns an error
	RegisterProvider("errprovider", func() (Provider, error) {
		return nil, errors.New("fail!!!")
	})
	assert.Panics(func() { MustNewProvider("errprovider") })
}

type someCredential struct{}

func (someCredential) Release() error {
	return nil
}

func (someCredential) Inquire() (*CredInfo, error) {
	return nil, nil
}

func (c someCredential) Add(name GssName, mech GssMech, usage CredUsage, initiatorLifetime *GssLifetime, acceptorLifetime *GssLifetime, mutate bool) (Credential, error) {
	return c, nil
}

func (someCredential) InquireByMech(mech GssMech) (*CredInfo, error) {
	return nil, nil
}

func TestInitSecContextOptions(t *testing.T) {
	assert := NewAssert(t)

	cred := &someCredential{}

	opts := []InitSecContextOption{
		WithInitiatorCredential(cred),
		WithInitiatorMech(GSS_MECH_KRB5),
		WithInitiatorFlags(ContextFlagMutual | ContextFlagInteg),
		WithInitiatorLifetime(time.Second * 123),
	}

	isco := InitSecContextOptions{}
	for _, f := range opts {
		f(&isco)
	}

	assert.EqualValues(cred, isco.Credential)
	assert.EqualValues(GSS_MECH_KRB5, isco.Mech)
	assert.Equal(ContextFlagMutual|ContextFlagInteg, isco.Flags)
	assert.Equal(time.Second*123, isco.Lifetime)
}

func TestWithInitiatorCredential(t *testing.T) {
	assert := NewAssert(t)
	isco := InitSecContextOptions{}
	cred := &someCredential{}
	opt := WithInitiatorCredential(cred)
	opt(&isco)
	assert.Equal(cred, isco.Credential)
}

func TestWithInitiatorMech(t *testing.T) {
	assert := NewAssert(t)
	isco := InitSecContextOptions{}
	opt := WithInitiatorMech(GSS_MECH_SPNEGO)
	opt(&isco)
	assert.Equal(GSS_MECH_SPNEGO, isco.Mech)
}

func TestWithInitiatorFlags(t *testing.T) {
	assert := NewAssert(t)
	isco := InitSecContextOptions{}
	flags := ContextFlagDeleg | ContextFlagConf
	opt := WithInitiatorFlags(flags)
	opt(&isco)
	assert.Equal(flags, isco.Flags)
}

func TestWithInitiatorLifetime(t *testing.T) {
	assert := NewAssert(t)
	isco := InitSecContextOptions{}
	lifetime := time.Minute * 5
	opt := WithInitiatorLifetime(lifetime)
	opt(&isco)
	assert.Equal(lifetime, isco.Lifetime)
}

func TestWithMultipleOptions(t *testing.T) {
	assert := NewAssert(t)
	isco := InitSecContextOptions{}
	cred := &someCredential{}
	flags := ContextFlagDeleg | ContextFlagConf
	lifetime := time.Hour

	options := []InitSecContextOption{
		WithInitiatorCredential(cred),
		WithInitiatorMech(GSS_MECH_SPNEGO),
		WithInitiatorFlags(flags),
		WithInitiatorLifetime(lifetime),
	}

	for _, opt := range options {
		opt(&isco)
	}

	assert.Equal(cred, isco.Credential)
	assert.Equal(GSS_MECH_SPNEGO, isco.Mech)
	assert.Equal(flags, isco.Flags)
	assert.Equal(lifetime, isco.Lifetime)
}

func TestWithInitiatorChannelBinding(t *testing.T) {
	assert := NewAssert(t)
	isco := InitSecContextOptions{}
	cb := &ChannelBinding{
		InitiatorAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		AcceptorAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		Data:          []byte("test"),
	}
	opt := WithInitiatorChannelBinding(cb)
	opt(&isco)
	assert.Equal(cb, isco.ChannelBinding)
}

func TestWithAcceptorCredential(t *testing.T) {
	assert := NewAssert(t)
	isco := AcceptSecContextOptions{}
	cred := &someCredential{}
	opt := WithAcceptorCredential(cred)
	opt(&isco)
	assert.Equal(cred, isco.Credential)
}

func TestWithAcceptorChannelBinding(t *testing.T) {
	assert := NewAssert(t)
	isco := AcceptSecContextOptions{}
	cb := &ChannelBinding{
		InitiatorAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		AcceptorAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		Data:          []byte("test"),
	}
	opt := WithAcceptorChannelBinding(cb)
	opt(&isco)
	assert.Equal(cb, isco.ChannelBinding)
}
