// SPDX-License-Identifier: Apache-2.0

package gssapi

// Oid represents an Object Identifier as used throughout GSSAPI. Elements of the byte slice
// represent the DER encoding of the object identifier, excluding the ASN.1 header (two bytes:
// tag value 0x06 and length) as per the Microsoft documentation on object identifiers.
//
// The specification defines the Oid type to represent the OBJECT IDENTIFIER type from RFC 2743.
// Other GSSAPI language bindings provide constant OID values for supported mechanisms and names.
// This specification, however, calls for concrete types for mechanisms and names, along with methods
// for translating between those types and their associated OIDs. The empty or nil Oid value does
// not have any special meaning.
//
// In the Go bindings, OID sets are represented as slices of Oid types ([]Oid).
type Oid []byte
