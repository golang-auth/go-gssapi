package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Local version of testify/assert  with some extensions
type myassert struct {
	*assert.Assertions

	t *testing.T
}

// Fail the test immediately on error
func (a *myassert) NoErrorFatal(err error) {
	a.NoError(err)
	if err != nil {
		a.t.Logf("Stopping test %s due to fatal error", a.t.Name())
		a.t.FailNow()
	}
}

func NewAssert(t *testing.T) *myassert {
	a := assert.New(t)
	return &myassert{a, t}
}
