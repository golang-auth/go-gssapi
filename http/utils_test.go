// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"
	"reflect"
	"testing"
)

func TestParseWwwAuthenticateHeader(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		expected *wwwAuthenticate
	}{
		{
			name:     "No header",
			headers:  map[string][]string{},
			expected: nil,
		},
		{
			name: "Basic with realm and charset",
			headers: map[string][]string{
				"WWW-Authenticate": {`Basic realm="Dev", charset="UTF-8"`},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme: "Basic",
						Parameters: map[string]string{
							"realm":   "Dev",
							"charset": "UTF-8",
						},
					},
				},
			},
		},
		{
			name: "Negotiate simple",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate"},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme:     "Negotiate",
						Token68:    "",
						Parameters: map[string]string{},
					},
				},
			},
		},

		{
			name: "Negotiate with token68",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB"},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme:     "Negotiate",
						Token68:    "YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB",
						Parameters: map[string]string{},
					},
				},
			},
		},
		{
			name: "Negotiate with token68 with one-padding",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate SGVsbG8xMgo="},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme:     "Negotiate",
						Token68:    "SGVsbG8xMgo=",
						Parameters: map[string]string{},
					},
				},
			},
		},
		{
			name: "Negotiate with token68 with two-padding",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate SGVsbG8xCg=="},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme:     "Negotiate",
						Token68:    "SGVsbG8xCg==",
						Parameters: map[string]string{},
					},
				},
			},
		},
		{
			name: "Basic with realm only",
			headers: map[string][]string{
				"WWW-Authenticate": {"Basic realm=\"staging environment\""},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme: "Basic",
						Parameters: map[string]string{
							"realm": "staging environment",
						},
					},
				},
			},
		},
		{
			name: "Multiple challenges in one header",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate, Basic realm=\"Dev\""},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme:     "Negotiate",
						Token68:    "",
						Parameters: map[string]string{},
					},
					{
						Scheme: "Basic",
						Parameters: map[string]string{
							"realm": "Dev",
						},
					},
				},
			},
		},
		{
			name: "Multiple headers",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate", "Basic realm=\"Dev\""},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme:     "Negotiate",
						Token68:    "",
						Parameters: map[string]string{},
					},
					{
						Scheme: "Basic",
						Parameters: map[string]string{
							"realm": "Dev",
						},
					},
				},
			},
		},
		{
			name: "Digest with multiple parameters",
			headers: map[string][]string{
				"WWW-Authenticate": {"Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme: "Digest",
						Parameters: map[string]string{
							"realm":  "testrealm@host.com",
							"qop":    "auth,auth-int",
							"nonce":  "dcd98b7102dd2f0e8b11d0f600bfb0c093",
							"opaque": "5ccc069c403ebaf9f0171e9517f40e41",
						},
					},
				},
			},
		},
		{
			name: "Quoted value with comma",
			headers: map[string][]string{
				"WWW-Authenticate": {"Basic realm=\"staging, environment\""},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme: "Basic",
						Parameters: map[string]string{
							"realm": "staging, environment",
						},
					},
				},
			},
		},
		{
			name: "AWS4-HMAC-SHA256 example",
			headers: map[string][]string{
				"WWW-Authenticate": {"AWS4-HMAC-SHA256 Credential=\"AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request\", SignedHeaders=\"host;x-amz-date\", Signature=\"5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7\""},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme: "AWS4-HMAC-SHA256",
						Parameters: map[string]string{
							"Credential":    "AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request",
							"SignedHeaders": "host;x-amz-date",
							"Signature":     "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
						},
					},
				},
			},
		},
		{
			name: "Case insensitive scheme",
			headers: map[string][]string{
				"WWW-Authenticate": {"basic realm=\"Dev\""},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme: "basic",
						Parameters: map[string]string{
							"realm": "Dev",
						},
					},
				},
			},
		},
		{
			name: "Empty header value",
			headers: map[string][]string{
				"WWW-Authenticate": {""},
			},
			expected: nil,
		},
		{
			name: "Multiple challenges with mixed formats",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB, Basic realm=\"Dev\", charset=\"UTF-8\""},
			},
			expected: &wwwAuthenticate{
				Challenges: []authChallenge{
					{
						Scheme:     "Negotiate",
						Token68:    "YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB",
						Parameters: map[string]string{},
					},
					{
						Scheme: "Basic",
						Parameters: map[string]string{
							"realm":   "Dev",
							"charset": "UTF-8",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			for k, v := range tt.headers {
				for _, val := range v {
					headers.Add(k, val)
				}
			}

			result := parseWwwAuthenticateHeader(&headers)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Errorf("expected %+v, got nil", tt.expected)
				return
			}

			if len(result.Challenges) != len(tt.expected.Challenges) {
				t.Errorf("expected %d challenges, got %d", len(tt.expected.Challenges), len(result.Challenges))
				return
			}

			for i, expectedChallenge := range tt.expected.Challenges {
				actualChallenge := result.Challenges[i]

				if actualChallenge.Scheme != expectedChallenge.Scheme {
					t.Errorf("challenge[%d].Scheme: expected %q, got %q", i, expectedChallenge.Scheme, actualChallenge.Scheme)
				}

				if actualChallenge.Token68 != expectedChallenge.Token68 {
					t.Errorf("challenge[%d].Token68: expected %q, got %q", i, expectedChallenge.Token68, actualChallenge.Token68)
				}

				if !reflect.DeepEqual(actualChallenge.Parameters, expectedChallenge.Parameters) {
					t.Errorf("challenge[%d].Parameters: expected %+v, got %+v", i, expectedChallenge.Parameters, actualChallenge.Parameters)
				}
			}
		})
	}
}

func TestParseAuthzHeader(t *testing.T) {
	tests := []struct {
		name           string
		headers        map[string][]string
		expectedScheme string
		expectedValue  string
	}{
		{
			name:           "No Authorization header",
			headers:        map[string][]string{},
			expectedScheme: "",
			expectedValue:  "",
		},
		{
			name: "Basic authorization",
			headers: map[string][]string{
				"Authorization": {"Basic dXNlcjpwYXNz"},
			},
			expectedScheme: "basic",
			expectedValue:  "dXNlcjpwYXNz",
		},
		{
			name: "Negotiate authorization",
			headers: map[string][]string{
				"Authorization": {"Negotiate YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB"},
			},
			expectedScheme: "negotiate",
			expectedValue:  "YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB",
		},
		{
			name: "Bearer authorization",
			headers: map[string][]string{
				"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
			},
			expectedScheme: "bearer",
			expectedValue:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name: "Case insensitive scheme",
			headers: map[string][]string{
				"Authorization": {"BASIC dXNlcjpwYXNz"},
			},
			expectedScheme: "basic",
			expectedValue:  "dXNlcjpwYXNz",
		},
		{
			name: "Invalid format - no credential",
			headers: map[string][]string{
				"Authorization": {"Basic"},
			},
			expectedScheme: "",
			expectedValue:  "",
		},
		{
			name: "Multiple spaces",
			headers: map[string][]string{
				"Authorization": {"Basic  dXNlcjpwYXNz"},
			},
			expectedScheme: "basic",
			expectedValue:  " dXNlcjpwYXNz",
		},
		{
			name: "Empty value",
			headers: map[string][]string{
				"Authorization": {"Basic "},
			},
			expectedScheme: "basic",
			expectedValue:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			for k, v := range tt.headers {
				for _, val := range v {
					headers.Add(k, val)
				}
			}

			scheme, value := parseAuthzHeader(&headers)
			if scheme != tt.expectedScheme {
				t.Errorf("expected scheme %q, got %q", tt.expectedScheme, scheme)
			}
			if value != tt.expectedValue {
				t.Errorf("expected value %q, got %q", tt.expectedValue, value)
			}
		})
	}
}

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *authChallenge
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: nil,
		},
		{
			name:  "Scheme only",
			input: "Negotiate",
			expected: &authChallenge{
				Scheme:     "Negotiate",
				Token68:    "",
				Parameters: map[string]string{},
			},
		},
		{
			name:  "Scheme with token68",
			input: "Negotiate YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB",
			expected: &authChallenge{
				Scheme:     "Negotiate",
				Token68:    "YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB",
				Parameters: map[string]string{},
			},
		},
		{
			name:  "Scheme with token68 ending with =",
			input: "Negotiate SGVsbG8xMgo=",
			expected: &authChallenge{
				Scheme:     "Negotiate",
				Token68:    "SGVsbG8xMgo=",
				Parameters: map[string]string{},
			},
		},
		{
			name:  "Scheme with token68 ending with ==",
			input: "Negotiate SGVsbG8xCg==",
			expected: &authChallenge{
				Scheme:     "Negotiate",
				Token68:    "SGVsbG8xCg==",
				Parameters: map[string]string{},
			},
		},
		{
			name:  "Scheme with parameters",
			input: `Basic realm="Dev", charset="UTF-8"`,
			expected: &authChallenge{
				Scheme: "Basic",
				Parameters: map[string]string{
					"realm":   "Dev",
					"charset": "UTF-8",
				},
			},
		},
		{
			name:  "Token68 with equals in middle (parsed as parameter)",
			input: "Negotiate abc=123",
			expected: &authChallenge{
				Scheme: "Negotiate",
				Parameters: map[string]string{
					"abc": "123",
				},
			},
		},
		{
			name:  "Multiple spaces",
			input: "Basic   realm=\"Dev\"",
			expected: &authChallenge{
				Scheme: "Basic",
				Parameters: map[string]string{
					"realm": "Dev",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseChallenge(tt.input)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Errorf("expected %+v, got nil", tt.expected)
				return
			}

			if result.Scheme != tt.expected.Scheme {
				t.Errorf("expected Scheme %q, got %q", tt.expected.Scheme, result.Scheme)
			}

			if result.Token68 != tt.expected.Token68 {
				t.Errorf("expected Token68 %q, got %q", tt.expected.Token68, result.Token68)
			}

			if !reflect.DeepEqual(result.Parameters, tt.expected.Parameters) {
				t.Errorf("expected Parameters %+v, got %+v", tt.expected.Parameters, result.Parameters)
			}
		})
	}
}

func TestParseAuthParams(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:     "Whitespace only",
			input:    "   ",
			expected: map[string]string{},
		},
		{
			name:  "Single parameter",
			input: `realm="Dev"`,
			expected: map[string]string{
				"realm": "Dev",
			},
		},
		{
			name:  "Multiple parameters",
			input: `realm="Dev", charset="UTF-8"`,
			expected: map[string]string{
				"realm":   "Dev",
				"charset": "UTF-8",
			},
		},
		{
			name:  "Parameter with comma in value",
			input: `realm="staging, environment"`,
			expected: map[string]string{
				"realm": "staging, environment",
			},
		},
		{
			name:  "Unquoted value",
			input: `realm=Dev`,
			expected: map[string]string{
				"realm": "Dev",
			},
		},
		{
			name:  "Parameter with escaped backslash",
			input: `realm="test\\value"`,
			expected: map[string]string{
				"realm": "test\\\\value",
			},
		},
		{
			name:  "Multiple parameters with commas in values",
			input: `realm="test,realm", qop="auth,auth-int"`,
			expected: map[string]string{
				"realm": "test,realm",
				"qop":   "auth,auth-int",
			},
		},
		{
			name:  "Parameter with spaces",
			input: `realm = "Dev" , charset = "UTF-8"`,
			expected: map[string]string{
				"realm":   "Dev",
				"charset": "UTF-8",
			},
		},
		{
			name:  "Empty parameter value",
			input: `realm=""`,
			expected: map[string]string{
				"realm": "",
			},
		},
		{
			name:     "Invalid parameter (no equals)",
			input:    `realm`,
			expected: map[string]string{},
		},
		{
			name:  "Parameter with escaped quote",
			input: `realm="test\"value"`,
			expected: map[string]string{
				"realm": "test\\\"value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAuthParams(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}

func TestParseParam(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedKey string
		expectedVal string
	}{
		{
			name:        "Quoted value",
			input:       `realm="Dev"`,
			expectedKey: "realm",
			expectedVal: "Dev",
		},
		{
			name:        "Unquoted value",
			input:       `realm=Dev`,
			expectedKey: "realm",
			expectedVal: "Dev",
		},
		{
			name:        "Value with spaces",
			input:       `realm = "staging environment"`,
			expectedKey: "realm",
			expectedVal: "staging environment",
		},
		{
			name:        "Empty value",
			input:       `realm=""`,
			expectedKey: "realm",
			expectedVal: "",
		},
		{
			name:        "No equals sign",
			input:       `realm`,
			expectedKey: "",
			expectedVal: "",
		},
		{
			name:        "Only equals sign",
			input:       `=`,
			expectedKey: "",
			expectedVal: "",
		},
		{
			name:        "Key with spaces",
			input:       ` realm = "Dev"`,
			expectedKey: "realm",
			expectedVal: "Dev",
		},
		{
			name:        "Value with quotes in middle",
			input:       `realm="test"value"`,
			expectedKey: "realm",
			expectedVal: "test\"value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, val := parseParam(tt.input)
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
			if val != tt.expectedVal {
				t.Errorf("expected val %q, got %q", tt.expectedVal, val)
			}
		})
	}
}

func TestParseChallenges(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "Single challenge",
			input:    "Negotiate",
			expected: []string{"Negotiate"},
		},
		{
			name:     "Two challenges",
			input:    "Negotiate, Basic realm=\"Dev\"",
			expected: []string{"Negotiate", "Basic realm=\"Dev\""},
		},
		{
			name:     "Challenge with comma in quoted value",
			input:    `Basic realm="staging, environment"`,
			expected: []string{`Basic realm="staging, environment"`},
		},
		{
			name:     "Multiple challenges with commas in values",
			input:    `Negotiate, Basic realm="test,realm", Digest realm="auth,auth-int"`,
			expected: []string{"Negotiate", `Basic realm="test,realm"`, `Digest realm="auth,auth-int"`},
		},
		{
			name:     "Challenge with escaped backslash",
			input:    `Basic realm="test\\value"`,
			expected: []string{`Basic realm="test\\value"`},
		},
		{
			name:     "Whitespace around challenges",
			input:    "  Negotiate  ,  Basic realm=\"Dev\"  ",
			expected: []string{"Negotiate", "Basic realm=\"Dev\""},
		},
		{
			name:     "Three challenges",
			input:    "Negotiate, Basic realm=\"Dev\", Digest realm=\"test\"",
			expected: []string{"Negotiate", "Basic realm=\"Dev\"", "Digest realm=\"test\""},
		},
		{
			name:     "Challenge with token68",
			input:    "Negotiate YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB, Basic realm=\"Dev\"",
			expected: []string{"Negotiate YIIBzgYJKoZIhvcSAQICAQBuggHXMIIB0wIBADCBvQYJKoZIhvcNAQcB", "Basic realm=\"Dev\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseChallenges(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected length %d, got %d", len(tt.expected), len(result))
				return
			}
			if tt.expected == nil && result != nil {
				t.Errorf("expected nil, got %+v", result)
				return
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}

func TestSchemeChallenges(t *testing.T) {
	tests := []struct {
		name     string
		wwwAuth  *wwwAuthenticate
		scheme   string
		expected []authChallenge
	}{
		{
			name: "No challenges",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{},
			},
			scheme:   "Negotiate",
			expected: nil,
		},
		{
			name: "Single matching challenge",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{
					{Scheme: "Negotiate", Token68: "token1"},
				},
			},
			scheme: "Negotiate",
			expected: []authChallenge{
				{Scheme: "Negotiate", Token68: "token1"},
			},
		},
		{
			name: "Multiple matching challenges",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{
					{Scheme: "Negotiate", Token68: "token1"},
					{Scheme: "Basic", Parameters: map[string]string{"realm": "Dev"}},
					{Scheme: "Negotiate", Token68: "token2"},
				},
			},
			scheme: "Negotiate",
			expected: []authChallenge{
				{Scheme: "Negotiate", Token68: "token1"},
				{Scheme: "Negotiate", Token68: "token2"},
			},
		},
		{
			name: "No matching challenges",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{
					{Scheme: "Basic", Parameters: map[string]string{"realm": "Dev"}},
					{Scheme: "Digest", Parameters: map[string]string{"realm": "test"}},
				},
			},
			scheme:   "Negotiate",
			expected: nil,
		},
		{
			name: "Case sensitive matching",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{
					{Scheme: "Negotiate", Token68: "token1"},
					{Scheme: "negotiate", Token68: "token2"},
				},
			},
			scheme: "Negotiate",
			expected: []authChallenge{
				{Scheme: "Negotiate", Token68: "token1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.wwwAuth.SchemeChallenges(tt.scheme)
			if len(result) != len(tt.expected) {
				t.Errorf("expected length %d, got %d", len(tt.expected), len(result))
				return
			}
			if tt.expected == nil && result != nil {
				t.Errorf("expected nil, got %+v", result)
				return
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}

func TestFindOneSchemeChallenge(t *testing.T) {
	tests := []struct {
		name          string
		wwwAuth       *wwwAuthenticate
		scheme        string
		expected      *authChallenge
		expectedError string
	}{
		{
			name: "No challenges",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{},
			},
			scheme:        "Negotiate",
			expected:      nil,
			expectedError: "no Negotiate challenge found in WWW-Authenticate header",
		},
		{
			name: "Single matching challenge",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{
					{Scheme: "Negotiate", Token68: "token1"},
				},
			},
			scheme: "Negotiate",
			expected: &authChallenge{
				Scheme:  "Negotiate",
				Token68: "token1",
			},
			expectedError: "",
		},
		{
			name: "Multiple matching challenges",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{
					{Scheme: "Negotiate", Token68: "token1"},
					{Scheme: "Negotiate", Token68: "token2"},
				},
			},
			scheme:        "Negotiate",
			expected:      nil,
			expectedError: "multiple Negotiate challenges found in WWW-Authenticate header",
		},
		{
			name: "No matching challenges",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{
					{Scheme: "Basic", Parameters: map[string]string{"realm": "Dev"}},
				},
			},
			scheme:        "Negotiate",
			expected:      nil,
			expectedError: "no Negotiate challenge found in WWW-Authenticate header",
		},
		{
			name: "One matching challenge among others",
			wwwAuth: &wwwAuthenticate{
				Challenges: []authChallenge{
					{Scheme: "Basic", Parameters: map[string]string{"realm": "Dev"}},
					{Scheme: "Negotiate", Token68: "token1"},
					{Scheme: "Digest", Parameters: map[string]string{"realm": "test"}},
				},
			},
			scheme: "Negotiate",
			expected: &authChallenge{
				Scheme:  "Negotiate",
				Token68: "token1",
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.wwwAuth.FindOneSchemeChallenge(tt.scheme)

			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.expectedError)
					return
				}
				if err.Error() != tt.expectedError {
					t.Errorf("expected error %q, got %q", tt.expectedError, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("expected no error, got %v", err)
				return
			}

			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Errorf("expected %+v, got nil", tt.expected)
				return
			}

			if result.Scheme != tt.expected.Scheme {
				t.Errorf("expected Scheme %q, got %q", tt.expected.Scheme, result.Scheme)
			}

			if result.Token68 != tt.expected.Token68 {
				t.Errorf("expected Token68 %q, got %q", tt.expected.Token68, result.Token68)
			}

			if !reflect.DeepEqual(result.Parameters, tt.expected.Parameters) {
				t.Errorf("expected Parameters %+v, got %+v", tt.expected.Parameters, result.Parameters)
			}
		})
	}
}

func TestFindSchemeChallenges(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		scheme   string
		expected []authChallenge
	}{
		{
			name:     "No headers",
			headers:  map[string][]string{},
			scheme:   "Negotiate",
			expected: nil,
		},
		{
			name: "Single matching challenge",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate"},
			},
			scheme: "Negotiate",
			expected: []authChallenge{
				{Scheme: "Negotiate", Token68: "", Parameters: map[string]string{}},
			},
		},
		{
			name: "Multiple matching challenges",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate token1, Negotiate token2"},
			},
			scheme: "Negotiate",
			expected: []authChallenge{
				{Scheme: "Negotiate", Token68: "token1", Parameters: map[string]string{}},
				{Scheme: "Negotiate", Token68: "token2", Parameters: map[string]string{}},
			},
		},
		{
			name: "No matching challenges",
			headers: map[string][]string{
				"WWW-Authenticate": {"Basic realm=\"Dev\""},
			},
			scheme:   "Negotiate",
			expected: nil,
		},
		{
			name: "Mixed challenges",
			headers: map[string][]string{
				"WWW-Authenticate": {"Negotiate token1, Basic realm=\"Dev\", Negotiate token2"},
			},
			scheme: "Negotiate",
			expected: []authChallenge{
				{Scheme: "Negotiate", Token68: "token1", Parameters: map[string]string{}},
				{Scheme: "Negotiate", Token68: "token2", Parameters: map[string]string{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			for k, v := range tt.headers {
				for _, val := range v {
					headers.Add(k, val)
				}
			}

			result := findSchemeChallenges(&headers, tt.scheme)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Errorf("expected %+v, got nil", tt.expected)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d challenges, got %d", len(tt.expected), len(result))
				return
			}

			for i, expectedChallenge := range tt.expected {
				actualChallenge := result[i]

				if actualChallenge.Scheme != expectedChallenge.Scheme {
					t.Errorf("challenge[%d].Scheme: expected %q, got %q", i, expectedChallenge.Scheme, actualChallenge.Scheme)
				}

				if actualChallenge.Token68 != expectedChallenge.Token68 {
					t.Errorf("challenge[%d].Token68: expected %q, got %q", i, expectedChallenge.Token68, actualChallenge.Token68)
				}

				if !reflect.DeepEqual(actualChallenge.Parameters, expectedChallenge.Parameters) {
					t.Errorf("challenge[%d].Parameters: expected %+v, got %+v", i, expectedChallenge.Parameters, actualChallenge.Parameters)
				}
			}
		})
	}
}

func TestFilterIterator(t *testing.T) {
	tests := []struct {
		name     string
		slice    []int
		match    func(int) bool
		expected []int
	}{
		{
			name:     "Empty slice",
			slice:    []int{},
			match:    func(x int) bool { return x > 0 },
			expected: []int{},
		},
		{
			name:     "All match",
			slice:    []int{1, 2, 3},
			match:    func(x int) bool { return x > 0 },
			expected: []int{1, 2, 3},
		},
		{
			name:     "None match",
			slice:    []int{1, 2, 3},
			match:    func(x int) bool { return x < 0 },
			expected: []int{},
		},
		{
			name:     "Some match",
			slice:    []int{1, 2, 3, 4, 5},
			match:    func(x int) bool { return x%2 == 0 },
			expected: []int{2, 4},
		},
		{
			name:     "Early termination",
			slice:    []int{1, 2, 3, 4, 5},
			match:    func(x int) bool { return x > 0 },
			expected: []int{1, 2, 3, 4, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iterator := filterIterator(tt.slice, tt.match)
			result := []int{}
			iterator(func(x int) bool {
				result = append(result, x)
				return true // continue
			})

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}

	// Test early termination
	t.Run("Early termination with return false", func(t *testing.T) {
		slice := []int{1, 2, 3, 4, 5}
		iterator := filterIterator(slice, func(x int) bool { return x > 0 })
		result := []int{}
		count := 0
		iterator(func(x int) bool {
			result = append(result, x)
			count++
			return count < 2 // stop after 2 items
		})

		expected := []int{1, 2}
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("expected %+v, got %+v", expected, result)
		}
	})
}
