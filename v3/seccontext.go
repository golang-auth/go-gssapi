// SPDX-License-Identifier: Apache-2.0

package gssapi

// GSSAPI Security-Context Management, RFC 2743 § 2.2

// SecContextInfo contains information about a security context returned by the Inquire method.
type SecContextInfo struct {
	InitiatorName    GssName     // The initiator name (MN - mechanism name)
	AcceptorName     GssName     // The acceptor name (MN - mechanism name)
	Mech             GssMech     // The mechanism used by the context
	Flags            ContextFlag // The protection flags available
	ExpiresAt        GssLifetime // Context expiration information
	LocallyInitiated bool        // True if the caller initiated the security context
	FullyEstablished bool        // True once the context is fully established
	ProtectionReady  bool        // True when per-message methods can be used to protect messages
	Transferrable    bool        // True if the context can be transferred to another process
}

// SecContext represents a GSSAPI security context. A security context is created through the
// (possible mutual) authentication of an initiator to an acceptor. Authentication is achieved
// by exchanging tokens between the parties until both agree that the process is complete.
// RFC 2743 § 2.2 defines a set of calls related to security contexts.
//
// The Go bindings define an interface for operations on existing contexts, and the Provider
// interface provides methods to construct new contexts.
type SecContext interface {
	// Delete clears context-specific information. It should be called on any non-nil SecContext
	// object to release associated resources. If a token is returned, it should be sent to the peer to
	// notify them to clear their own context. This call implements GSS_Delete_sec_context from RFC 2743 § 2.2.3.
	//
	// Returns:
	//   - token: Token to send to the peer, if not empty
	//   - err: Error if one occurred, otherwise nil
	Delete() (token []byte, err error) // RFC 2743 § 2.2.3

	// ProcessToken implements GSS_Process_context_token from RFC 2743 § 2.2.4. It processes context
	// tokens received from a peer after the context is fully established. One use is for processing the
	// output of Delete() from the peer.
	//
	// Parameters:
	//   - token: Context token received from the peer
	//
	// Returns:
	//   - Error if one occurred, otherwise nil
	ProcessToken([]byte) error // RFC 2743 § 2.2.4

	// ExpiresAt returns the lifetime information for the security context, implementing
	// GSS_Context_time from RFC 2743 § 2.2.5.
	//
	// Returns:
	//   - lifetime: Lifetime information including status and optional expiry time
	//   - err: Error if one occurred, otherwise nil
	ExpiresAt() (lifetime *GssLifetime, err error) // RFC 2743 § 2.2.5

	// Inquire returns information about the security context, implementing GSS_Inquire_context from
	// RFC 2743 § 2.2.6.
	//
	// The InitiatorName and AcceptorName fields represent MN (mechanism) names. The value of
	// Flags may change during the authentication process as more protection is added to the context.
	//
	// ExpiresAt is a structure with members indicating whether the context has expired or whether it
	// has indefinite validity, otherwise the time at which it expires. This replaces the integer value
	// specified in RFC 2743 and 2744, that uses magic values to represent expired and indefinite states;
	// these are not suitable for use with the Go time types.
	//
	// LocallyInitiated is true if the caller initiated the security context. FullyEstablished is true
	// once the context is fully established; otherwise, it is in the CONTINUE_NEEDED state.
	//
	// ProtectionReady indicates when per-message methods can be used to protect messages, constrained
	// to the values of ContextFlagDeleg, ContextFlagMutual, ContextFlagReplay, ContextFlagSequence,
	// ContextFlagConf, and ContextFlagInteg in the Flags field. If the context is not yet fully
	// established, these flag values may change as additional facilities are confirmed.
	//
	// Returns:
	//   - info: Information about the security context
	//   - err: Error if one occurred, otherwise nil
	Inquire() (info *SecContextInfo, err error) // RFC 2743 § 2.2.6

	// WrapSizeLimit returns the maximum unwrapped message size that, when wrapped, takes no more than
	// outSizeMax bytes. It implements GSS_Wrap_size_limit from RFC 2743 § 2.2.7.
	//
	// Parameters:
	//   - conf: Whether the wrapped message would include confidentiality
	//   - outSizeMax: Maximum allowed wrapped message size
	//   - qop: Quality of protection requested, zero for default (see RFC 2743 § 1.2.4 for details)
	//
	// Returns:
	//   - inSizeMax: Maximum unwrapped message size
	//   - err: Error if one occurred, otherwise nil
	WrapSizeLimit(bool, uint, QoP) (inSizeMax uint, err error) // RFC 2743 § 2.2.7

	// Export generates an inter-process token transferable to another process within the system,
	// implementing GSS_Export_sec_context from RFC 2743 § 2.2.8. The receiving process should call
	// Provider.ImportSecContext() to accept the transfer. Upon success, the original security context
	// is deactivated and no longer available for use.
	//
	// Returns:
	//   - tok: Opaque inter-process token
	//   - err: Error if one occurred, otherwise nil
	Export() (tok []byte, err error) // RFC 2743 § 2.2.8

	// GetMIC generates an integrity check token over the supplied message, corresponding to GSS_GetMIC
	// from RFC 2743 § 2.3.1.
	//
	// Detached integrity tokens generated by this method and verified by VerifyMIC can be used with
	// protocols that cannot accept wrapped messages, by transferring the message and integrity
	// information separately between peers.
	//
	// Parameters:
	//   - msg: Message to generate integrity token for
	//   - qop: Quality of protection requested, zero for default (see RFC 2743 § 1.2.4 for details)
	//
	// Returns:
	//   - tok: Integrity token
	//   - err: Error if one occurred, otherwise nil
	GetMIC([]byte, QoP) (tok []byte, err error) // RFC 2743 § 2.3.1

	// VerifyMIC verifies a message against an integrity token generated by GetMIC(), corresponding
	// to GSS_VerifyMIC from RFC 2743 § 2.3.2. Message replay and sequencing features are used if
	// supported by the underlying security context.
	//
	// Parameters:
	//   - msg: Message over which to validate the integrity
	//   - tok: Integrity token generated by the peer using GetMIC
	//
	// Returns:
	//   - qop: Quality of protection provided, zero for default (see RFC 2743 § 1.2.4 for details)
	//   - err: Error if one occurred, otherwise nil
	VerifyMIC([]byte, []byte) (qop QoP, err error) // RFC 2743 § 2.3.2

	// Wrap generates a new message that incorporates the input message and relevant protections as
	// a single set of bytes, implementing GSS_Wrap from RFC 2743 § 2.3.3.
	//
	// The wrapped message will be encrypted if confidentiality was requested and supported.
	//
	// Parameters:
	//   - msgIn: Input (unwrapped) message
	//   - confReq: Whether confidentiality is required
	//   - qop: Quality of protection requested, zero for default (see RFC 2743 § 1.2.4 for details)
	//
	// Returns:
	//   - msgOut: Wrapped message
	//   - confState: Whether confidentiality was applied to msgOut
	//   - err: Error if one occurred, otherwise nil
	Wrap([]byte, bool, QoP) (msgOut []byte, confState bool, err error) // RFC 2743 § 2.3.3

	// Unwrap takes a message generated by the peer's call to Wrap(), validates its protections, and
	// optionally decrypts its contents depending on whether confidentiality was applied in the Wrap() call.
	// It implements GSS_Unwrap from RFC 2743 § 2.3.4.
	//
	// Parameters:
	//   - msgIn: Input (wrapped) message from peer
	//
	// Returns:
	//   - msgOut: Unwrapped message
	//   - confState: Whether the wrapped message was confidential (encrypted)
	//   - qop: Quality of protection provided, zero for default (see RFC 2743 § 1.2.4 for details)
	//   - err: Error if one occurred, otherwise nil
	Unwrap([]byte) (msgOut []byte, confState bool, qop QoP, err error) // RFC 2743 § 2.3.4

	// ContinueNeeded indicates whether more context-initialization tokens need to be exchanged with
	// the peer to complete the security context. This call is equivalent to checking for the
	// GSS_S_CONTINUE_NEEDED status from GSS_Init_sec_context or GSS_Accept_sec_context.
	//
	// Returns:
	//   - Whether more message exchanges are required
	ContinueNeeded() bool

	// Continue is used by initiators and acceptors during the context-initialization loop
	// to process a token from the peer. It is equivalent to calling GSS_Init_sec_context or
	// GSS_Accept_sec_context on a partially open context.
	//
	// The caller should check the result of ContinueNeeded to determine whether the initialization
	// loop has completed.
	//
	// Parameters:
	//   - tokIn: Context initialization token received from the peer
	//
	// Returns:
	//   - tokOut: New token to send to the peer; zero length if no token should be sent
	//   - err: Error if one occurred, otherwise nil
	Continue([]byte) (tokOut []byte, err error)
}
