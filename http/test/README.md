# go-gssapi/http/tests

These tests for go-gssapi/http are in a separate Go module because they make use
of the go-gssapi-c provider which we do not want in the dependency list for
the main package.

Tests of private functions/methods can be placed into the parent module but
should take care with their imports.
