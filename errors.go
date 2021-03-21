package gssapi

import (
	"errors"
)

var ContinueNeeded = errors.New("gssapi: the routine must be called again to complete its function")
