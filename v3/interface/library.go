package gsscommon

import (
	"sync"
	"time"
)

var registry struct {
	sync.Mutex
	libs map[string]libFactory
}

func init() {
	registry.libs = make(map[string]libFactory)
}

type libFactory func() Library

func RegisterLibrary(name string, f libFactory) {
	registry.Lock()
	defer registry.Unlock()

	registry.libs[name] = f
}

func NewLibrary(name string) Library {
	registry.Lock()
	defer registry.Unlock()

	if name == "" {
		panic("GSSAPI library name not set")
	}

	f, ok := registry.libs[name]
	if !ok {
		panic("GSSAPI library not found: " + name)
	}

	return f()
}

type InitSecContextOptions struct {
	Credential Credential
	Mech       GssMech
	Flags      ContextFlag
	Lifetime   time.Duration
}

type InitSecContextOption func(o *InitSecContextOptions)

func WithInitiatorCredential(cred Credential) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Credential = cred
	}
}

func WithInitatorMech(mech GssMech) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Mech = mech
	}
}

func WithInitiatorFlags(flags ContextFlag) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Flags = flags
	}
}

func WithInitiatorLifetime(life time.Duration) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Lifetime = life
	}
}

type Library interface {
	ImportName(name string, nameType GssNameType) (GssName, error)                                                // RFC 2743 § 2.4.5
	AcquireCredential(name GssName, mechs []GssMech, usage CredUsage, lifetime time.Duration) (Credential, error) // RFC 2743 § 2.1.1
	//	InitSecContext(name GssName, cred Credential, mech GssMech, flags ContextFlag, lifetime time.Duration) (SecContext, []byte, error) // RFC 2743 § 2.2.1
	InitSecContext(name GssName, opts ...InitSecContextOption) (SecContext, []byte, error) // RFC 2743 § 2.2.1
	AcceptSecContext(cred Credential, inputToken []byte) (SecContext, []byte, error)       // RFC 2743 § 2.2.2
}
