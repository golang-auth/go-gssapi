// SPDX-License-Identifier: Apache-2.0

package test

import (
	"errors"
	"testing"
)

func TestNoErrorFatalOK(t *testing.T) {

	ch := make(chan bool)
	tt := &testing.T{}

	go func() {
		defer func() {
			ch <- true
		}()

		assert := NewAssert(tt)
		assert.NoErrorFatal(nil)
	}()

	<-ch

	if tt.Failed() {
		t.Error("test should not have failed")
	}
}

func TestNoErrorFatalWithError(t *testing.T) {

	ch := make(chan bool)
	tt := &testing.T{}

	go func() {
		defer func() {
			ch <- true
		}()

		assert := NewAssert(tt)
		assert.NoErrorFatal(errors.New("test"))
	}()

	<-ch

	if !tt.Failed() {
		t.Error("test should have failed")
	}
}

func TestNewAssert(t *testing.T) {
	assert := NewAssert(t)
	assert.NotNil(assert)
}
