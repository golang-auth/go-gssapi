package http

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/golang-auth/go-gssapi/v3/test"
)

func TestInitiatorWithOpportunistic(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithInitiatorOpportunistic()
	opt(transport)

	f1 := reflect.ValueOf(opportunisticsFuncAlways).Pointer()
	f2 := reflect.ValueOf(transport.opportunisticFunc).Pointer()
	assert.Equal(f1, f2)
}

func TestInitiatorWithOpportunisticFunc(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithInitiatorOpportunisticFunc(func(url url.URL) bool {
		return url.Host == "example.com"
	})
	opt(transport)

	assert.True(transport.opportunisticFunc(url.URL{Host: "example.com"}))
	assert.False(transport.opportunisticFunc(url.URL{Host: "blah.com"}))
}

func TestInitiatorWithMutual(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithInitiatorMutual()
	opt(transport)
	assert.True(transport.mutual)
}

func TestInitiatorWithCredential(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithInitiatorCredential(nil)
	opt(transport)
	assert.Nil(transport.credential)
}

func TestInitiatorWithSpnFunc(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithInitiatorSpnFunc(func(url url.URL) string {
		return "XXX@" + url.Host
	})
	opt(transport)
	assert.Equal("XXX@example.com", transport.spnFunc(url.URL{Host: "example.com"}))
}

func TestInitiatorWithDelegationPolicy(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithIniiatorDelegationPolicy(DelegationPolicyAlways)
	opt(transport)
	assert.Equal(DelegationPolicyAlways, transport.delegationPolicy)
}

func TestInitiatorWithExpect100Threshold(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithInitiatorExpect100Threshold(100)
	opt(transport)
	assert.Equal(int64(100), transport.expect100Threshold)
}

func TestInitiatorWithRoundTripper(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithInitiatorRoundTripper(&http.Transport{})
	opt(transport)
	assert.Equal(&http.Transport{}, transport.transport)
}

func TestInititorWithHttpLogging(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithInititorHttpLogging()
	opt(transport)
	assert.True(transport.httpLogging)
}

func TestInitiatorWithLogFunc(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)

	msg := ""
	logFunc := func(format string, args ...interface{}) {
		msg = fmt.Sprintf(format, args...)
	}
	opt := WithInitiatorLogFunc(logFunc)
	opt(transport)

	transport.logFunc("test")
	assert.Equal("test", msg)
}

func TestInitiatorWithChannelBindingDisposition(t *testing.T) {
	assert := test.NewAssert(t)
	transport, err := NewTransport(nil)
	assert.NoErrorFatal(err)
	opt := WithInitiatorChannelBindingDisposition(ChannelBindingDispositionRequire)
	opt(transport)
	assert.Equal(ChannelBindingDispositionRequire, transport.channelBindingDisposition)
}
