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

type Library interface {
	ImportName(name string, nameType GssNameType) (GssName, error)                                                                     // RFC 2743 § 2.4.5
	AcquireCredential(name GssName, mechs []GssMech, usage CredUsage, lifetime time.Duration) (Credential, error)                      // RFC 2743 § 2.1.1
	InitSecContext(cred Credential, name GssName, mech GssMech, flags ContextFlag, lifetime time.Duration) (SecContext, []byte, error) // RFC 2743 § 2.2.1
	AcceptSecContext(cred Credential, inputToken []byte) (SecContext, *SecContextInfo, []byte, error)                                  // RFC 2743 § 2.2.2
}
