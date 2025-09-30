// SPDX-License-Identifier: Apache-2.0

package gssapi

import "time"

// GssLifetimeStatus defines the possible states of a GssLifetime
// instance
type GssLifetimeStatus int

const (
	// Indicates that the lifetime ExpiresAt value is valid
	GssLifetimeAvailable GssLifetimeStatus = iota

	// Indicates that the lifetime has expired and the ExpiresAt value is not valid
	GssLifetimeExpired

	// Indicates that the lifetime is indefinite;  the ExpiresAt value is not valid
	GssLifetimeIndefinite
)

// GssLifetime represents the possible context lifetimes.  The go-gssapi interface
// separates the status from the expiry time as it does not make sense in Go to overload
// the ExpiresAt value as is specified in RFC 2743/2744.
type GssLifetime struct {
	Status    GssLifetimeStatus
	ExpiresAt time.Time
}

func MakeGssLifetime(lifetime time.Duration) *GssLifetime {
	status := GssLifetimeAvailable
	if lifetime == 0 {
		status = GssLifetimeExpired
	}

	return &GssLifetime{
		Status:    status,
		ExpiresAt: time.Now().Add(lifetime),
	}
}
