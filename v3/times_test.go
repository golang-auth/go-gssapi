// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMakeGssLifetime(t *testing.T) {
	assert := assert.New(t)

	lifetime := MakeGssLifetime(10 * time.Second)
	assert.Equal(GssLifetimeAvailable, lifetime.Status)
	assert.WithinDuration(time.Now().Add(10*time.Second), lifetime.ExpiresAt, 1*time.Second)

	lifetime = MakeGssLifetime(0)
	assert.Equal(GssLifetimeExpired, lifetime.Status)
	assert.WithinDuration(time.Now(), lifetime.ExpiresAt, 1*time.Second)
}
