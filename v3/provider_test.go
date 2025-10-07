// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type someProvider struct {
	name string
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
	assert := assert.New(t)

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

type someCredential struct{}

func (someCredential) Release() error {
	return nil
}

func (someCredential) Inquire() (*CredInfo, error) {
	return nil, nil
}

func (someCredential) Add(name GssName, mech GssMech, usage CredUsage, initiatorLifetime *GssLifetime, acceptorLifetime *GssLifetime) error {
	return nil
}

func (someCredential) InquireByMech(mech GssMech) (*CredInfo, error) {
	return nil, nil
}

func TestInitSecContextOptions(t *testing.T) {
	assert := assert.New(t)

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
