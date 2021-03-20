package gssapi

type ContextFlag uint32

// GSS-API context flags assigned numbers.
const (
	ContextFlagDeleg    ContextFlag = 1 << iota // delegate credentials, not currently supported
	ContextFlagMutual                           // request remote peer authenticates itself
	ContextFlagReplay                           // enable replay detection for signed/sealed messages
	ContextFlagSequence                         // enable detection of out of sequence signed/sealed messages
	ContextFlagConf                             // confidentiality available
	ContextFlagInteg                            // integrity available
)
