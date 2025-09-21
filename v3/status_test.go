// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConstValues(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(FatalErrorCode(0), complete)
	assert.Equal(FatalErrorCode(1), errBadMech)

	assert.Equal(FatalErrorCode(6), errBadSig)
	assert.Equal(FatalErrorCode(6), errBadMic)
	assert.Equal(FatalErrorCode(7), errNoCred)

	assert.Equal(FatalErrorCode(18), errNameNotMn)

	assert.Equal(InformationCode(1), infoContinueNeeded)
	assert.Equal(InformationCode(16), infoGapToken)
}

func TestFatal(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		code        FatalErrorCode
		errContains string
	}{
		{errBadMech, "unsupported mech"},
		{errBadName, "invalid name"},
		{errBadNameType, "unsupported type"},
		{errBadBindings, "channel bindings"},
		{errBadStatus, "invalid status"},
		{errBadMic, "invalid signature"},
		{errNoCred, "no credentials"},
		{errNoContext, "no context"},
		{errDefectiveToken, "invalid token"},
		{errDefectiveCredential, "invalid credential"},
		{errCredentialsExpired, "credentials have expired"},
		{errContextExpired, "context has expired"},
		{errFailure, "unspecified GSS"},
		{errBadQop, "quality-of-protection"},
		{errUnauthorized, "operation is forbidden"},
		{errUnavailable, "not available"},
		{errDuplicateElement, "already exists"},
		{errNameNotMn, "not mechanism"},
		{1000, "invalid status"},
	}

	for _, tt := range tests {
		fs := FatalStatus{FatalErrorCode: tt.code}
		assert.Contains(fs.Fatal().Error(), tt.errContains)
	}
}

func TestFatalUnwrap(t *testing.T) {
	assert := assert.New(t)

	var err error = FatalStatus{
		FatalErrorCode: errBadMech,
		InfoStatus: InfoStatus{
			InformationCode: infoDuplicateToken | infoGapToken,
		},
	}

	assert.ErrorIs(err, ErrBadMech)
	assert.ErrorIs(err, InfoDuplicateToken)
	assert.ErrorIs(err, InfoGapToken)
	assert.NotErrorIs(err, InfoOldToken)

	assert.ErrorAs(err, &FatalStatus{})
}

func TestFatalError(t *testing.T) {
	assert := assert.New(t)

	var err error = FatalStatus{
		FatalErrorCode: errBadMech,
		InfoStatus: InfoStatus{
			InformationCode: infoDuplicateToken | infoGapToken,
			MechErrors:      []error{errors.New("TEST")},
		},
	}

	msg := err.Error()

	assert.Contains(msg, "unsupported mech")
	assert.Contains(msg, "earlier token")
	assert.Contains(msg, "was not received")
}

func TestInfoUnwrap(t *testing.T) {
	assert := assert.New(t)

	var err error = InfoStatus{
		InformationCode: infoDuplicateToken | infoGapToken,
	}

	assert.ErrorIs(err, InfoDuplicateToken)
	assert.ErrorIs(err, InfoGapToken)
	assert.NotErrorIs(err, InfoOldToken)

	asInfo := errors.As(err, &InfoStatus{})
	assert.True(asInfo)

	asFatal := errors.As(err, &FatalStatus{})
	assert.False(asFatal)
}

func TestInfoError(t *testing.T) {
	assert := assert.New(t)

	var err error = InfoStatus{
		InformationCode: infoDuplicateToken | infoGapToken,
	}
	msg := err.Error()

	assert.Contains(msg, "earlier token")
	assert.Contains(msg, "was not received")
}
