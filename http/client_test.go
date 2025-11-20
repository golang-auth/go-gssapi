package http

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/golang-auth/go-gssapi/v3/test"
)

func TestWithOpportunistic(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)
	opt := WithOpportunistic()
	opt(transport)

	f1 := reflect.ValueOf(opportunisticsFuncAlways).Pointer()
	f2 := reflect.ValueOf(transport.opportunisticFunc).Pointer()
	assert.Equal(f1, f2)
}

func TestWithOpportunisticFunc(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)
	opt := WithOpportunisticFunc(func(url url.URL) bool {
		return url.Host == "example.com"
	})
	opt(transport)

	assert.True(transport.opportunisticFunc(url.URL{Host: "example.com"}))
	assert.False(transport.opportunisticFunc(url.URL{Host: "blah.com"}))
}

func TestWithMutual(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)
	opt := WithMutual()
	opt(transport)
	assert.True(transport.mutual)
}

func TestWithCredential(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)
	opt := WithCredential(nil)
	opt(transport)
	assert.Nil(transport.credential)
}

func TestWithSpnFunc(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)
	opt := WithSpnFunc(func(url url.URL) string {
		return "XXX@" + url.Host
	})
	opt(transport)
	assert.Equal("XXX@example.com", transport.spnFunc(url.URL{Host: "example.com"}))
}

func TestWithDelegationPolicy(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)
	opt := WithDelegationPolicy(DelegationPolicyAlways)
	opt(transport)
	assert.Equal(DelegationPolicyAlways, transport.delegationPolicy)
}

func TestWithExpect100Threshold(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)
	opt := WithExpect100Threshold(100)
	opt(transport)
	assert.Equal(int64(100), transport.expect100Threshold)
}

func TestWithRoundTripper(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)
	opt := WithRoundTripper(&http.Transport{})
	opt(transport)
	assert.Equal(&http.Transport{}, transport.transport)
}

func TestWithHttpLogging(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)
	opt := WithHttpLogging()
	opt(transport)
	assert.True(transport.httpLogging)
}

func TestWithLogFunc(t *testing.T) {
	assert := test.NewAssert(t)
	transport := NewTransport(nil)

	msg := ""
	logFunc := func(format string, args ...interface{}) {
		msg = fmt.Sprintf(format, args...)
	}
	opt := WithLogFunc(logFunc)
	opt(transport)

	transport.logFunc("test")
	assert.Equal("test", msg)
}
