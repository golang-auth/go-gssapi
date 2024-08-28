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

func (someProvider) ImportName(name string, nameType GssNameType) (GssName, error) {
	return nil, nil
}

func (someProvider) AcquireCredential(name GssName, mechs []GssMech, usage CredUsage, lifetime time.Duration) (Credential, error) {
	return nil, nil
}

func (someProvider) InitSecContext(name GssName, opts ...InitSecContextOption) (SecContext, []byte, error) {
	return nil, nil, nil
}

func (someProvider) AcceptSecContext(cred Credential, inputToken []byte) (SecContext, []byte, error) {
	return nil, nil, nil
}

func (someProvider) ImportSecContext(b []byte) (SecContext, error) {
	return nil, nil
}

func (someProvider) InquireNamesForMech(m GssMech) ([]GssNameType, error) {
	return nil, nil
}

func TestRegister(t *testing.T) {
	assert := assert.New(t)

	registry.libs = make(map[string]ProviderFactory)

	assert.Equal(0, len(registry.libs))

	factory := func() Provider {
		return someProvider{name: "TEST"}
	}

	RegisterProvider("test", factory)
	assert.Equal(1, len(registry.libs))
	f, ok := registry.libs["test"]
	assert.True(ok)
	assert.NotNil(f)

	p := NewProvider("test")
	assert.NotNil(p)
	sp, ok := p.(someProvider)
	assert.True(ok)
	assert.Equal("TEST", sp.name)

	assert.Panics(func() { NewProvider("") })
	assert.Panics(func() { NewProvider("xyz") })
}

type someCredential struct{}

func (someCredential) Release() error {
	return nil
}

func (someCredential) Inquire() (*CredInfo, error) {
	return nil, nil
}

func (someCredential) Add(name GssName, mech GssMech, usage CredUsage, initiatorLifetime time.Duration, acceptorLifetime time.Duration) error {
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
		WithInitatorMech(GSS_MECH_KRB5),
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
