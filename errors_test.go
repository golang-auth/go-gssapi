package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCallingErrorString(t *testing.T) {
	assert.Contains(t, StatusCallInaccessibleRead.String(), "read")
	assert.Contains(t, StatusCallInaccessibleWrite.String(), "written")
	assert.Contains(t, StatusCallBadStructure.String(), "malformed")
}

func TestRoutineErrorString(t *testing.T) {
	assert.Contains(t, StatusBadMech.String(), "unsupported mechanism")
	assert.Contains(t, StatusBadMIC.String(), "invalid signature")
	assert.Contains(t, StatusBadSig.String(), "invalid signature")
	assert.Contains(t, StatusNoCred.String(), "No cred")
	assert.Contains(t, StatusNameNotMN.String(), "mechanism specifc")
}

func TestSupplementaryInfoString(t *testing.T) {
	assert.Contains(t, StatusContinueNeeded.String(), "called again")
	assert.Contains(t, StatusGapToken.String(), "per-message token")

	x := StatusContinueNeeded + StatusUnseqToken
	assert.Contains(t, x.String(), "must be called again")
	assert.Contains(t, x.String(), "already been processed")
}

func TestErrorString(t *testing.T) {
	e := GSSAPIError{StatusCallBadStructure, StatusNoCred, StatusContinueNeeded}

	s := e.Error()
	t.Log(s)
	assert.Contains(t, s, "malformed")
	assert.Contains(t, s, "No cred")
	assert.Contains(t, s, "called again")
}
