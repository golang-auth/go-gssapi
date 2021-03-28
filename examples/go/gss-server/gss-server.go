// Copyright 2021 Jake Scott. All rights reserved.
// Use of this source code is governed by the Apache License
// version 2.0 that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/jake-scott/go-gssapi/v2"
	_ "github.com/jake-scott/go-gssapi/v2/krb5"
)

var _debug bool

func main() {
	port := flag.Int("port", 1234, "local port to listen on")
	flag.BoolVar(&_debug, "d", false, "enable debugging")
	flag.Parse()

	// Listen on port
	addr := fmt.Sprintf(":%d", *port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		go handleConn(conn)
	}
}

func sendToken(conn net.Conn, token []byte) error {
	szBuff := make([]byte, 4)
	binary.BigEndian.PutUint32(szBuff, uint32(len(token)))
	_, err := conn.Write(szBuff)
	if err != nil {
		return err
	}

	n, err := conn.Write(token)
	if err != nil {
		return err
	}
	debug("Wrote %d bytes to client", n)
	debug("Token bytes: [% x]", token)

	return nil
}

func recvToken(conn net.Conn) (token []byte, err error) {
	szBuff := make([]byte, 4)
	_, err = conn.Read(szBuff)
	if err != nil {
		return
	}

	buf := bytes.NewBuffer(szBuff)
	var tokenSize uint32
	binary.Read(buf, binary.BigEndian, &tokenSize)

	token = make([]byte, tokenSize)
	n, err := conn.Read(token)
	if err != nil {
		return
	}
	debug("Read %d byte token from client", n)
	debug("Token bytes: [% x]", token)

	return
}

func debug(format string, args ...interface{}) {
	if !_debug {
		return
	}

	fmt.Printf(format+"\n", args...)
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	debug("Accepted connection from %s", conn.RemoteAddr())

	server := gssapi.NewMech("kerberos_v5")
	err := server.Accept("")

	var inToken, outToken []byte

	for !server.IsEstablished() {
		inToken, err = recvToken(conn)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			break
		}

		outToken, err = server.Continue(inToken)
		if len(outToken) > 0 {
			if sendErr := sendToken(conn, outToken); sendErr != nil {
				err = sendErr
				break
			}
		}
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	debug("Context established, client: %s", server.PeerName())
	flags := gssapi.FlagList(server.ContextFlags())
	for _, f := range flags {
		debug("  context flag: 0x%02x: %s", f, gssapi.FlagName(f))
	}

	inToken, err = recvToken(conn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	msg, isSealed, err := server.Unwrap(inToken)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	protStr := "signed"
	if isSealed {
		protStr = "sealed"
	}
	fmt.Printf(`Received %s message: "%s"`+"\n", protStr, msg)

	// generate a MIC token to send back
	if outToken, err = server.MakeSignature(msg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if err = sendToken(conn, outToken); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
