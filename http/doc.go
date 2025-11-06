// SPDX-License-Identifier: Apache-2.0

/*
Package http provides GSSAPI (Negotiate) enabled HTTP client and server
implementations.

	import (
		net/http
		ghttp "github.com/golang-auth/go-gssapi/v3/http"
		_ "github.com/golang-auth/go-gssapi-c"
	)

	p, err := gssapi.NewProvider("github.com/golang-auth/go-gssapi-c")
	...

# Clients and transorts

Create a client to use a default GSSAPI enabled transport.  The client can be used
anywhere a standard [http.Client] can be used.

	client, err := ghttp.NewClient(p, nil)
	...

	resp, err := client.Get("https://example.com")
	...

	req, err := http.NewRequest("GET", "http://example.com", nil)
	...
	req.Header.Add("If-None-Match", `W/"wyzzy"`)
	resp, err := client.Do(req)
	...

To control GSSAPI parameters, create a transport:

	transport := ghttp.NewTransport(p, http.WithOpportunistic(),
	    	                           http.WithCredential(cred))
	client := http.Client{Transport: transport}
	resp, err := client.Get("https://example.com")

The GSSAPI enabled transport wrapps a standard [http.RoundTripper] - by default it uses [http.DefaultTransport].
A custom round-tripper can be provided to the transport using [WithRoundTripper].

# "Expect: Continue" optimization

POST, PUT and other HTTP methods that include a request body, must send the full body to the server
regardless of the server's response code.  Go from version 1.8 includes the [http.Request.GetBody] method
which allows supported body types to be rewound and sent again if the server responds with a 401 status
code.  However, in cases where the request body is large, having to send the body multiple times is
inefficient.

Given the frequency of 401 responses when making use of challenge/response mechanisms like GSSAPI,
[http.GSSAPITransport] adds the "Expect: Continue" request header if the request body size exceeds
the configured threshold (default: 4kB).  This causes the server close the connection if it needs to send a
401 response, but avoids the need to send the body multiple times.  The optimum value for the threshold
will depend on network properties such as available bandwidth and MTU.  The header is also sent if the
request body is not rewindable and opportunistic authentication is not requested as the request will fail
otherwise.

Use of the "Expect: Continue" header can be disabled by setting the threshold to 0, and it is never sent
if opportunistic authentication is requested.

# Opportunistic authentication

# Opportunistic authentication

means that the client does not wait for the server to
respond with a 401 status code before sending an authentication token.  This
is a performance optimization that can be used to reduce the number of round trips
between the client and server, at the cost of initializing the GSSAPI context and
potentially exposing authentcation credentials to the server unnecessarily.

# Servers
<...>
*/
package http
