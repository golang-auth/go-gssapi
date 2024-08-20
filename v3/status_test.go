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
