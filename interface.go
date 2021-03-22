package gssapi

type Mech interface {
	IsEstablished() bool
	ContextFlags() ContextFlag
	PeerName() string
	Initiate(serviceName string, flags ContextFlag) (err error)
	Accept(serviceName string) (err error)
	Continue(tokenIn []byte) (tokenOut []byte, err error)
	Wrap(tokenIn []byte, confidentiality bool) (tokenOut []byte, err error)
	Unwrap(tokenIn []byte) (tokenOut []byte, isSealed bool, err error)
}
