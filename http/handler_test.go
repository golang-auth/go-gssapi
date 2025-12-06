// SPDX-License-Identifier: Apache-2.0
package http

import (
	"testing"

	"github.com/golang-auth/go-gssapi/v3/test"
)

func TestHandlerWithChannelBindingDisposition(t *testing.T) {
	assert := test.NewAssert(t)
	handler := Handler{}
	opt := WithAcceptorChannelBindingDisposition(ChannelBindingDispositionRequire)
	opt(&handler)
	assert.Equal(ChannelBindingDispositionRequire, handler.channelBindingDisposition)
}
