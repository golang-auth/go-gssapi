package gssapi

import (
	"testing"

	g "github.com/golang-auth/go-gssapi/v3/interface"
	"github.com/stretchr/testify/assert"
)

func TestConstValues(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(CallingErrorCode(1), inaccessibleRead)
	assert.Equal(CallingErrorCode(2), inaccessibleWrite)
	assert.Equal(CallingErrorCode(3), badStructure)
}

func TestCallingUnwrap(t *testing.T) {
	assert := assert.New(t)

	var err error = CallingError{
		CallingErrorCode: inaccessibleRead,
		FatalStatus: g.FatalStatus{
			FatalErrorCode: 2,
			InfoStatus: g.InfoStatus{
				InformationCode: 18,
			},
		},
	}

	assert.ErrorIs(err, ErrInaccessibleRead)
	assert.ErrorIs(err, g.ErrBadName)
	assert.ErrorIs(err, g.InfoDuplicateToken)
	assert.ErrorIs(err, g.InfoGapToken)
	assert.NotErrorIs(err, g.InfoOldToken)

	assert.ErrorAs(err, &CallingError{})
}

func TestCallingError(t *testing.T) {
	assert := assert.New(t)

	var err error = CallingError{
		CallingErrorCode: inaccessibleRead,
		FatalStatus: g.FatalStatus{
			FatalErrorCode: 1,
			InfoStatus: g.InfoStatus{
				InformationCode: 18,
			},
		},
	}

	msg := err.Error()

	assert.Contains(msg, "required input parameter")
	assert.Contains(msg, "unsupported mech")
	assert.Contains(msg, "earlier token")
	assert.Contains(msg, "was not received")
}

func TestMakeStatus(t *testing.T) {
	assert := assert.New(t)

	err := makeStatus(0x02<<24|0x03<<16|0x01, 123)
	msg := err.Error()

	assert.Contains(msg, "could not be written")
	assert.Contains(msg, "a supplied name")
	assert.Contains(msg, "must be called again")

	assert.ErrorIs(err, ErrInaccessibleWrite)
	assert.ErrorIs(err, g.ErrBadNameType)
	assert.ErrorIs(err, g.InfoContinueNeeded)
}
