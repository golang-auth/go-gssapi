package http

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
)

func parseAuthzHeader(headers *http.Header) (string, string) {
	header := headers.Get("Authorization")
	if header == "" {
		return "", ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.ToLower(parts[0]), parts[1]
}

// authChallenge represents a single authentication challenge from a WWW-Authenticate header.
type authChallenge struct {
	// Scheme is the authentication scheme (e.g., "Negotiate", "Basic", "Digest").
	Scheme string

	// Token68 is the token68 value if present (base64-like token without parameters).
	// This is typically used by schemes like "Negotiate" that can have a token directly.
	Token68 string

	// Parameters contains the authentication parameters as key-value pairs.
	// For example, Basic authentication might have {"realm": "Dev", "charset": "UTF-8"}.
	Parameters map[string]string
}

// wwwAuthenticate represents the parsed WWW-Authenticate header response.
// It contains all authentication challenges found in the header(s).
type wwwAuthenticate struct {
	// Challenges contains all authentication challenges found in the header(s).
	// The order is preserved from the header order.
	Challenges []authChallenge
}

// filterIterator returns an iterator function that yields elements from slice
// for which the match function returns true. The returned function can be
// used with slices.Collect.
func filterIterator[T any](slice []T, match func(T) bool) func(func(T) bool) {
	return func(yield func(T) bool) {
		for _, item := range slice {
			if match(item) {
				if !yield(item) {
					return
				}
			}
		}
	}
}

func (w *wwwAuthenticate) SchemeChallenges(scheme string) []authChallenge {
	iterator := filterIterator(w.Challenges, func(c authChallenge) bool {
		return c.Scheme == scheme
	})
	return slices.Collect(iterator)
}

func (w *wwwAuthenticate) FindOneSchemeChallenge(scheme string) (*authChallenge, error) {
	challenges := w.SchemeChallenges(scheme)
	switch len(challenges) {
	default:
		return nil, fmt.Errorf("multiple %s challenges found in WWW-Authenticate header", scheme)
	case 0:
		return nil, fmt.Errorf("no %s challenge found in WWW-Authenticate header", scheme)
	case 1:
		return &challenges[0], nil
	}
}

func findOneWwwAuthenticateChallenge(headers *http.Header, scheme string) (*authChallenge, error) {
	wwwAuth := parseWwwAuthenticateHeader(headers)
	if wwwAuth == nil {
		return nil, fmt.Errorf("no valid WWW-Authenticate header found in response")
	}
	return wwwAuth.FindOneSchemeChallenge(scheme)
}

func findSchemeChallenges(headers *http.Header, scheme string) []authChallenge {
	wwwAuth := parseWwwAuthenticateHeader(headers)
	if wwwAuth == nil {
		return nil
	}
	return wwwAuth.SchemeChallenges(scheme)
}

// parseWwwAuthenticateHeader parses the WWW-Authenticate header from a response.
// It returns a WwwAuthenticate struct containing all authentication challenges found.
// Returns nil if no WWW-Authenticate header is present.
//
// Unfortunately the format is complex to parse: there can be multiple comma-separated
// challenges in a single header, and challenges themselves can contain commas.
//
// According to RFC 7235 and MDN, the WWW-Authenticate header can have the format:
//
//	WWW-Authenticate: <auth-scheme> [token68]
//	WWW-Authenticate: <auth-scheme> <auth-param1=value1>, <auth-param2=value2>
//
// Multiple challenges can be comma-separated in one header, or multiple headers can be sent.
// For the Negotiate scheme, the format is typically just "Negotiate" or "Negotiate <token68>".
func parseWwwAuthenticateHeader(headers *http.Header) *wwwAuthenticate {
	// Get all WWW-Authenticate headers (there can be multiple)
	wwwAuthHeaders := headers.Values("WWW-Authenticate")
	if len(wwwAuthHeaders) == 0 {
		return nil
	}

	var allChallenges []authChallenge

	// Process all headers and challenges
	for _, headerValue := range wwwAuthHeaders {
		challengeStrings := parseChallenges(headerValue)
		for _, challengeStr := range challengeStrings {
			if challengeStr == "" {
				continue
			}

			challenge := parseChallenge(challengeStr)
			if challenge != nil {
				allChallenges = append(allChallenges, *challenge)
			}
		}
	}

	if len(allChallenges) == 0 {
		return nil
	}

	return &wwwAuthenticate{
		Challenges: allChallenges,
	}
}

// parseChallenge parses a single challenge string into an AuthChallenge struct.
func parseChallenge(challengeStr string) *authChallenge {
	// Split the challenge into scheme and the rest
	parts := strings.Fields(challengeStr)
	if len(parts) == 0 {
		return nil
	}

	challenge := &authChallenge{
		Scheme:     parts[0],
		Parameters: make(map[string]string),
	}

	if len(parts) > 1 {
		// Rejoin the remaining parts (token68 or parameters might have been split)
		remaining := strings.TrimSpace(strings.Join(parts[1:], " "))

		// Check if this is token68 or parameters
		// Token68 can end with Base64 padding characters (= or ==)
		// If the string ends with = or ==, it's clearly token68 padding, not a parameter
		if !strings.Contains(remaining, "=") {
			// No '=' sign, definitely token68
			challenge.Token68 = remaining
		} else if strings.HasSuffix(remaining, "==") || strings.HasSuffix(remaining, "=") {
			// Ends with padding, it's token68
			challenge.Token68 = remaining
		} else {
			// Has '=' but doesn't end with padding, parse as parameters
			params := parseAuthParams(remaining)
			if len(params) == 0 {
				// Empty params means it didn't parse as parameters, treat as token68
				challenge.Token68 = remaining
			} else {
				challenge.Parameters = params
			}
		}
	}

	return challenge
}

// parseAuthParams parses a comma-separated list of authentication parameters.
// It handles quoted values that may contain commas.
func parseAuthParams(paramList string) map[string]string {
	params := make(map[string]string)
	paramList = strings.TrimSpace(paramList)
	if paramList == "" {
		return params
	}

	// Parse parameters, respecting quoted values
	inQuotes := false
	escapeNext := false
	start := 0

	for i, r := range paramList {
		if escapeNext {
			// The previous character was a backslash, so this character is escaped
			// Escaped characters don't change quote state or trigger separators
			escapeNext = false
			continue
		}

		switch r {
		case '\\':
			escapeNext = true
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				// Found a parameter separator
				paramStr := strings.TrimSpace(paramList[start:i])
				if paramStr != "" {
					key, value := parseParam(paramStr)
					if key != "" {
						params[key] = value
					}
				}
				start = i + 1
			}
		}
	}

	// Handle the last parameter
	if start < len(paramList) {
		paramStr := strings.TrimSpace(paramList[start:])
		if paramStr != "" {
			key, value := parseParam(paramStr)
			if key != "" {
				params[key] = value
			}
		}
	}

	return params
}

// parseParam parses a single parameter in the format "key=value" or "key=\"value\"".
// Returns the key and value (with quotes removed if present).
func parseParam(paramStr string) (string, string) {
	idx := strings.Index(paramStr, "=")
	if idx == -1 {
		return "", ""
	}

	key := strings.TrimSpace(paramStr[:idx])
	value := strings.TrimSpace(paramStr[idx+1:])
	// Remove quotes if present
	value = strings.Trim(value, `"`)

	return key, value
}

// parseChallenges splits a header value into individual challenges.
// It only treats a comma as a challenge separator if the comma is outside
// of quotes AND the next segment does not look like a parameter list
// (i.e., there is no '=' before the next top-level comma). This allows
// commas inside auth-parameter lists to be preserved.
func parseChallenges(headerValue string) []string {
	var challenges []string
	var current strings.Builder
	inQuotes := false
	escapeNext := false

	// Helper to decide if the text after a comma begins a new challenge.
	// It treats it as a new challenge if the next non-space token does NOT
	// contain an '=' (i.e., it looks like an auth-scheme), regardless of
	// whether parameters follow after a space.
	isNewChallengeStart := func(s string, start int) bool {
		// skip spaces
		i := start
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			return false
		}
		// capture token until space or comma (ignore quotes here; schemes won't be quoted)
		j := i
		for j < len(s) {
			if s[j] == ' ' || s[j] == ',' {
				break
			}
			j++
		}
		token := s[i:j]
		if token == "" {
			return false
		}
		if strings.Contains(token, "=") {
			return false // looks like a parameter key
		}
		return true // looks like an auth-scheme token
	}

	for i := 0; i < len(headerValue); i++ {
		r := rune(headerValue[i])
		if escapeNext {
			current.WriteByte(headerValue[i])
			escapeNext = false
			continue
		}

		switch r {
		case '\\':
			escapeNext = true
			current.WriteByte(headerValue[i])
		case '"':
			inQuotes = !inQuotes
			current.WriteByte(headerValue[i])
		case ',':
			if !inQuotes {
				// Peek ahead to decide whether this comma starts a new challenge
				// Skip spaces after comma
				k := i + 1
				for k < len(headerValue) && headerValue[k] == ' ' {
					k++
				}
				if isNewChallengeStart(headerValue, k) {
					// Treat as challenge separator
					challenge := strings.TrimSpace(current.String())
					if challenge != "" {
						challenges = append(challenges, challenge)
					}
					current.Reset()
					continue
				}
			}
			// Not a separator; keep the comma
			current.WriteByte(headerValue[i])
		default:
			current.WriteByte(headerValue[i])
		}
	}

	// Handle the last challenge (or the only challenge if no separators)
	if s := strings.TrimSpace(current.String()); s != "" {
		challenges = append(challenges, s)
	}

	return challenges
}
