module examples

go 1.22.4

replace github.com/golang-auth/go-gssapi/v3 => ../../v3

replace github.com/golang-auth/go-gssapi-c => ../../../go-gssapi-c

require (
	github.com/golang-auth/go-gssapi-c v0.0.0-00010101000000-000000000000
	github.com/golang-auth/go-gssapi/v3 v3.0.0-00010101000000-000000000000
)
