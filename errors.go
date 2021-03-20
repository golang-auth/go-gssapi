package gssapi

import (
	"errors"
	"strings"
)

var ContinueNeeded = errors.New("gssapi: the routine must be called again to complete its function")

type CallingError uint8
type RoutineError uint8
type SupplementaryInfo uint16

const (
	StatusCallInaccessibleRead  CallingError = iota + 1 // A required input parameter could not be read
	StatusCallInaccessibleWrite                         // A required output parameter could not be written
	StatusCallBadStructure                              // A parameter was malformed
)

const (
	StatusBadMech             RoutineError = iota + 1     // An unsupported mechanism was requested
	StatusBadName                                         // An invalid name was supplied
	StatusBadNameType                                     // Asupplied name was of an unsupported type
	StatusBadBindings                                     // Incorrect channel bindings were supplied
	StatusBadStatus                                       // An invalid status code was supplied
	StatusBadMIC                                          // A token had an invalid MIC
	StatusBadSig                           = StatusBadMIC // A token had an invalid MIC
	StatusNoCred              RoutineError = iota         // No credentials were supplied, or the credentials were unavailable or inaccessible
	StatusNoContext                                       // No context has been established
	StatusDefectiveToken                                  // A token was invalid
	StatusDefectiveCredential                             // A credential was invalid
	StatusCredentialsExpired                              // The referenced credentials have expired
	StatusContextExpired                                  // The context has expired
	StatusFailure                                         // Miscellaneous failure (see text)
	StatusBadQOP                                          // The quality-of-protection requested could not be provided
	StatusUnauthorized                                    // The operation is forbidden by local security policy
	StatusUnavailable                                     // The operation or option is unavailable
	StatusDuplicateElement                                // The requested credential element already exists
	StatusNameNotMN                                       // The provided name was not a mechanism name
)

const (
	StatusContinueNeeded SupplementaryInfo = 1 << iota // Returned only by gss_init_sec_context or gss_accept_sec_context. The routine must be called again	to complete its function. See routine documentation for	detailed description
	StatusDuplicateToken                               // The token was a duplicate of an earlier token
	StatusOldtoken                                     // The token's validity period has expired
	StatusUnseqToken                                   // A later token has already been processed
	StatusGapToken                                     // An expected per-message token	was not received
)

// error strings from MIT Kerberos 1.19.1 (lib/gssapi/generic/disp_major_status.c)
func (c CallingError) String() string {
	return [...]string{
		"A required input parameter could not be read",
		"A required input parameter could not be written",
		"A parameter was malformed",
	}[c-1]
}

func (c RoutineError) String() string {
	return [...]string{
		"An unsupported mechanism was requested",
		"An invalid name was supplied",
		"A supplied name was of an unsupported type",
		"Incorrect channel bindings were supplied",
		"An invalid status code was supplied",
		"A token had an invalid signature",
		"No credentials were supplied, or the credentials were unavailable or inaccessible",
		"No context has been established",
		"A token was invalid",
		"A credential was invalid",
		"The referenced credentials have expired",
		"The context has expired",
		"Unspecified GSS failure",
		"The quality-of-protection requested could not be provided",
		"The operation is forbidden by the local security policy",
		"The operation or option is not available or unsupported",
		"The requested credential element already exists",
		"The provided name was not mechanism specifc (MN)",
	}[c-1]
}

func (c SupplementaryInfo) String() string {
	messages := [...]string{
		"The routine must be called again to complete its function",
		"The token was a duplicate of an earlier token",
		"The token's validity period has expired",
		"A later token has already been processed",
		"An expected per-message token was not received",
	}

	var strs []string

	if c&StatusContinueNeeded != 0 {
		strs = append(strs, messages[0])
	}
	if c&StatusDuplicateToken != 0 {
		strs = append(strs, messages[1])
	}
	if c&StatusOldtoken != 0 {
		strs = append(strs, messages[2])
	}
	if c&StatusUnseqToken != 0 {
		strs = append(strs, messages[3])
	}
	if c&StatusGapToken != 0 {
		strs = append(strs, messages[4])
	}

	return strings.Join(strs, ", ")
}

type GSSAPIError struct {
	CallingError      CallingError
	RoutineError      RoutineError
	SupplementaryInfo SupplementaryInfo
}

func (e GSSAPIError) Error() string {
	var strs []string

	if e.CallingError != 0 {
		strs = append(strs, e.CallingError.String())
	}
	if e.RoutineError != 0 {
		strs = append(strs, e.RoutineError.String())
	}
	if e.SupplementaryInfo != 0 {
		strs = append(strs, e.SupplementaryInfo.String())
	}

	return strings.Join(strs, "; ")
}
