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
