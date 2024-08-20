// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	_ "github.com/golang-auth/go-gssapi-c"
	"github.com/golang-auth/go-gssapi/v3"
)

var _debug bool

var provider string = "GSSAPI-C"
var gss = gssapi.NewProvider(provider)

func main() {
	port := flag.Int("port", 1234, "local port to listen on")
	flag.BoolVar(&_debug, "debug", false, "enable debugging")
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

	_, err = conn.Write(token)
	if err != nil {
		return err
	}

	return nil
}

func formatToken(tok []byte) string {
	b := &strings.Builder{}

	bd := hex.Dumper(b)
	defer bd.Close()

	bd.Write(tok)
	return b.String()
}

func recvToken(conn net.Conn) (token []byte, err error) {
	szBuff := make([]byte, 4)
	_, err = io.ReadFull(conn, szBuff)
	if err != nil {
		return
	}

	buf := bytes.NewBuffer(szBuff)
	var tokenSize uint32
	binary.Read(buf, binary.BigEndian, &tokenSize)

	token = make([]byte, tokenSize)
	_, err = io.ReadFull(conn, token)
	if err != nil {
		return
	}

	return
}

func debug(format string, args ...interface{}) {
	if !_debug {
		return
	}

	fmt.Printf(format+"\n", args...)
}

func handleConn(conn net.Conn) error {
	defer conn.Close()

	debug("Accepted connection from %s", conn.RemoteAddr())

	inToken, err := recvToken(conn)
	if err != nil {
		return showErr(err)
	}
	debug("Read context token (%d bytes:", len(inToken))
	debug("%s", formatToken(inToken))

	secctx, outToken, err := gss.AcceptSecContext(nil, inToken)
	if err != nil {
		return showErr(err)
	}

	defer secctx.Delete()

	if len(outToken) > 0 {
		if err := sendToken(conn, outToken); err != nil {
			return showErr(err)
		}
		debug("Sent context token (%d bytes):", len(outToken))
		debug("%s", formatToken(outToken))
	}

	for secctx.ContinueNeeded() {
		if inToken, err = recvToken(conn); err != nil {
			return showErr(err)
		}
		debug("Read context token (%d bytes:", len(inToken))
		debug("%s", formatToken(inToken))

		outToken, err = secctx.Continue(inToken)

		if len(outToken) > 0 {
			if err := sendToken(conn, outToken); err != nil {
				return showErr(err)
			}
			debug("Sent context token (%d bytes):", len(outToken))
			debug("%s", formatToken(outToken))
		}

		if err != nil {
			log.Fatal(err)
		}
	}

	info, err := secctx.Inquire()
	if err != nil {
		return showErr(err)
	}
	printContextInfo(info)

	inMsg, err := recvToken(conn)
	if err != nil {
		return showErr(err)
	}
	debug("Received wrap message (%d bytes):\n%s", len(inMsg), formatToken(inMsg))

	origMsg, conf, err := secctx.Unwrap(inMsg)
	if err != nil {
		return showErr(err)
	}

	protStr := "signed"
	if conf {
		protStr = "sealed"
	}
	fmt.Printf(`Received %s message: "%s"`+"\n", protStr, origMsg)

	// generate a MIC token to send back
	if outToken, err = secctx.GetMIC(origMsg); err != nil {
		return showErr(err)
	}

	if err = sendToken(conn, outToken); err != nil {
		return showErr(err)
	}
	debug("Sent MIC message (%d bytes):\n%s", len(outToken), formatToken(outToken))

	return nil
}

func showErr(err error) error {
	log.Printf("ERROR: %s", err)
	return err
}

func printContextInfo(info *gssapi.SecContextInfo) {
	local := "remotely initiated"
	open := "closed"

	if info.LocallyInitiated {
		local = "locally initiated"
	}
	if info.FullyEstablished {
		open = "open"
	}

	debug("Context flags: %s", info.Flags)
	debug("\"%s\" to \"%s\", expires: %s, %s, %s",
		info.InitiatorName, info.AcceptorName,
		info.ExpiresAt.Round(time.Second),
		local,
		open)

	debug("Name type of source is %s (%s)", info.AcceptorNameType, info.AcceptorNameType.OidString())
	debug("Name type of destination is %s (%s)", info.InitiatorNameType, info.InitiatorNameType.OidString())
	debug("Mechanism: %s (%s)", info.Mech, info.Mech.OidString())
}
