package gssapi

type Mech interface {
	IsEstablished() bool
	ContextFlags() ContextFlag
	Initiate(serviceName string, flags ContextFlag) (tokenOut []byte, err error)
	Continue(tokenIn []byte) (tokenOut []byte, err error)
	Wrap(tokenIn []byte, confidentiality bool) (tokenOut []byte, err error)
	Unwrap(tokenIn []byte) (tokenOut []byte, err error)
}
