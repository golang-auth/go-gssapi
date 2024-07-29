# GSSAPI interace for Go

Upto this point there have been several GSSAPI implementations for Go,
either native or C bindings.  Developers needed to make a choice
of implementation because their interfaces were not unified.  This
contrasts to the C language, where the bindings are specified
[in RFC 2744](https://datatracker.ietf.org/doc/html/rfc2744).

The interface specified in this package aims to fill that gap, albeit
without an RFC.  The aim is to provide developers with a common, idomatic
programming interface, allowing users to switch out the actual implementation
depending on preference or local policy.


