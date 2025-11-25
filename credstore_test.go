package gssapi

import (
	"errors"
	"testing"
)

// TestCredStoreOpt tests the CredStoreOpt constants to ensure they have unique bit values
func TestCredStoreOpt(t *testing.T) {
	assert := NewAssert(t)

	tests := []struct {
		name     string
		opt      CredStoreOpt
		expected int
	}{
		{"CredStoreCCache", CredStoreCCache, 1},
		{"CredStoreClientKeytab", CredStoreClientKeytab, 2},
		{"CredStoreServerKeytab", CredStoreServerKeytab, 4},
		{"CredStorePassword", CredStorePassword, 8},
		{"CredStoreRCache", CredStoreRCache, 16},
		{"CredStoreVerify", CredStoreVerify, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(tt.expected, int(tt.opt), "Expected %s to have value %d", tt.name, tt.expected)
		})
	}
}

// mockCredStore implements the CredStore interface for testing
type mockCredStore struct {
	options map[int]string
	errors  map[int]error
}

func newMockCredStore() *mockCredStore {
	return &mockCredStore{
		options: make(map[int]string),
		errors:  make(map[int]error),
	}
}

func (m *mockCredStore) SetOption(option int, value string) error {
	if err, exists := m.errors[option]; exists {
		return err
	}
	m.options[option] = value
	return nil
}

func (m *mockCredStore) GetOption(option int) (string, bool) {
	value, exists := m.options[option]
	return value, exists
}

func (m *mockCredStore) setError(option int, err error) {
	m.errors[option] = err
}

// TestCredStoreInterface tests the CredStore interface methods
func TestCredStoreInterface(t *testing.T) {
	assert := NewAssert(t)
	store := newMockCredStore()

	t.Run("SetOption and GetOption", func(t *testing.T) {
		// Test setting and getting an option
		err := store.SetOption(int(CredStoreCCache), "/tmp/krb5cc_1000")
		assert.NoError(err)

		value, exists := store.GetOption(int(CredStoreCCache))
		assert.True(exists, "Expected option to exist after setting")
		assert.Equal("/tmp/krb5cc_1000", value)
	})

	t.Run("GetOption non-existent", func(t *testing.T) {
		// Test getting a non-existent option
		value, exists := store.GetOption(int(CredStorePassword))
		assert.False(exists, "Expected option to not exist")
		assert.Equal("", value, "Expected empty value for non-existent option")
	})

	t.Run("SetOption error", func(t *testing.T) {
		// Test error handling in SetOption
		expectedErr := errors.New("test error")
		store.setError(int(CredStoreClientKeytab), expectedErr)

		err := store.SetOption(int(CredStoreClientKeytab), "/etc/krb5.keytab")
		assert.Equal(expectedErr, err)
	})

	t.Run("Multiple options", func(t *testing.T) {
		// Test setting multiple options
		options := map[int]string{
			int(CredStoreServerKeytab): "/etc/krb5.keytab",
			int(CredStoreRCache):       "/tmp/rcache",
			int(CredStoreVerify):       "host/server.example.com",
		}

		for opt, val := range options {
			err := store.SetOption(opt, val)
			assert.NoError(err, "Unexpected error setting option %d", opt)
		}

		for opt, expectedVal := range options {
			value, exists := store.GetOption(opt)
			assert.True(exists, "Expected option %d to exist", opt)
			assert.Equal(expectedVal, value, "Expected value for option %d", opt)
		}
	})

	t.Run("Overwrite option", func(t *testing.T) {
		// Test overwriting an existing option
		err := store.SetOption(int(CredStoreCCache), "/tmp/krb5cc_new")
		assert.NoError(err)

		value, exists := store.GetOption(int(CredStoreCCache))
		assert.True(exists, "Expected option to exist after overwriting")
		assert.Equal("/tmp/krb5cc_new", value)
	})
}

// TestCredStoreOptions tests the CredStoreOption functions
func TestCredStoreOptions(t *testing.T) {
	assert := NewAssert(t)
	store := newMockCredStore()

	t.Run("WithCredStoreCCache", func(t *testing.T) {
		option := WithCredStoreCCache("/tmp/krb5cc_1000")
		err := option(store)
		assert.NoError(err)

		value, exists := store.GetOption(int(CredStoreCCache))
		assert.True(exists, "Expected CredStoreCCache option to be set")
		assert.Equal("/tmp/krb5cc_1000", value)
	})

	t.Run("WithCredStoreClientKeytab", func(t *testing.T) {
		option := WithCredStoreClientKeytab("/etc/client.keytab")
		err := option(store)
		assert.NoError(err)

		value, exists := store.GetOption(int(CredStoreClientKeytab))
		assert.True(exists, "Expected CredStoreClientKeytab option to be set")
		assert.Equal("/etc/client.keytab", value)
	})

	t.Run("WithCredStoreServerKeytab", func(t *testing.T) {
		option := WithCredStoreServerKeytab("/etc/server.keytab")
		err := option(store)
		assert.NoError(err)

		value, exists := store.GetOption(int(CredStoreServerKeytab))
		assert.True(exists, "Expected CredStoreServerKeytab option to be set")
		assert.Equal("/etc/server.keytab", value)
	})

	t.Run("WithCredStorePassword", func(t *testing.T) {
		option := WithCredStorePassword("secret123")
		err := option(store)
		assert.NoError(err)

		value, exists := store.GetOption(int(CredStorePassword))
		assert.True(exists, "Expected CredStorePassword option to be set")
		assert.Equal("secret123", value)
	})

	t.Run("WithCredStoreRCache", func(t *testing.T) {
		option := WithCredStoreRCache("/tmp/rcache")
		err := option(store)
		assert.NoError(err)

		value, exists := store.GetOption(int(CredStoreRCache))
		assert.True(exists, "Expected CredStoreRCache option to be set")
		assert.Equal("/tmp/rcache", value)
	})

	t.Run("WithCredStoreVerify", func(t *testing.T) {
		option := WithCredStoreVerify("host/server.example.com")
		err := option(store)
		assert.NoError(err)

		value, exists := store.GetOption(int(CredStoreVerify))
		assert.True(exists, "Expected CredStoreVerify option to be set")
		assert.Equal("host/server.example.com", value)
	})

	t.Run("WithCredStoreVerify empty string", func(t *testing.T) {
		// Test with empty string (uses any host service principal)
		option := WithCredStoreVerify("")
		err := option(store)
		assert.NoError(err)

		value, exists := store.GetOption(int(CredStoreVerify))
		assert.True(exists, "Expected CredStoreVerify option to be set")
		assert.Equal("", value)
	})

	t.Run("Multiple options", func(t *testing.T) {
		// Test applying multiple options
		store2 := newMockCredStore()
		options := []CredStoreOption{
			WithCredStoreCCache("/tmp/krb5cc_test"),
			WithCredStoreClientKeytab("/etc/test.keytab"),
			WithCredStoreRCache("/tmp/test_rcache"),
		}

		for _, opt := range options {
			err := opt(store2)
			assert.NoError(err)
		}

		// Verify all options were set
		ccache, exists := store2.GetOption(int(CredStoreCCache))
		assert.True(exists, "Expected ccache option to exist")
		assert.Equal("/tmp/krb5cc_test", ccache)

		keytab, exists := store2.GetOption(int(CredStoreClientKeytab))
		assert.True(exists, "Expected keytab option to exist")
		assert.Equal("/etc/test.keytab", keytab)

		rcache, exists := store2.GetOption(int(CredStoreRCache))
		assert.True(exists, "Expected rcache option to exist")
		assert.Equal("/tmp/test_rcache", rcache)
	})

	t.Run("Option error handling", func(t *testing.T) {
		// Test error handling when SetOption fails
		store3 := newMockCredStore()
		expectedErr := errors.New("set option failed")
		store3.setError(int(CredStoreCCache), expectedErr)

		option := WithCredStoreCCache("/tmp/krb5cc_error")
		err := option(store3)
		assert.Equal(expectedErr, err)
	})
}
