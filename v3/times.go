// SPDX-License-Identifier: Apache-2.0
package gssapi

import "time"

type GssLifetime struct {
	IsExpired    bool
	IsIndefinite bool
	ExpiresAt    time.Time
}
