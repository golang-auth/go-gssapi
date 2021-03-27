package gssapi

import "strings"

type MechFactory func() Mech

var mechs map[string]MechFactory

func init() {
	mechs = make(map[string]MechFactory)
}

// Register should be called by Mech implementations to enable
// a mechanism to be used by clients
func Register(name string, f MechFactory) {
	name = strings.ToLower(name)
	_, ok := mechs[name]

	// can't register two mechs with the same name
	if ok {
		panic("Cannot have two mechs named " + name)
	}

	mechs[name] = f
}

// IsRegistered can be used to find out whether a named
// mechanism is registered or not
func IsRegistered(name string) bool {
	name = strings.ToLower(name)
	_, ok := mechs[name]

	return ok
}

// NewMech returns a mechanism context by name
func NewMech(name string) Mech {
	name = strings.ToLower(name)
	f, ok := mechs[name]

	if ok {
		return f()
	}

	return nil
}

// Mechs returns the list of registered mechanism names
func Mechs() (l []string) {
	l = make([]string, 0, len(mechs))

	for name := range mechs {
		l = append(l, name)
	}

	return
}
