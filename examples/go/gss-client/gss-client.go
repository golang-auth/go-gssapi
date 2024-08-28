// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/golang-auth/go-gssapi-c"
	"github.com/golang-auth/go-gssapi/v3"
)

var _debug bool

var provider string = "GSSAPI-C"
var gss = gssapi.NewProvider(provider)

func main() {
	port := flag.Int("port", 1234, "remote port to connect to")
	mech := flag.String("mech", "", "use specific mech OID")
	deleg := flag.Bool("d", false, "request delegation")
	file := flag.Bool("f", false, "use file")
	confReq := flag.Bool("seal", false, "seal (encrypt) the message")
	mutual := flag.Bool("mutual", false, "request mutual authentication")
	flag.BoolVar(&_debug, "debug", false, "enable debugging")
	flag.Parse()

	if flag.NArg() != 3 {
		log.Fatalf("Usage: %s [-port <int>] [-mech <OID>] [-d] [-f] [-seal] [-mutual] [-debug] host service msg\n", os.Args[0])
	}

	host := flag.Arg(0)
	service := flag.Arg(1)
	msg := flag.Arg(2)

	// Connect to the host
	addr := fmt.Sprintf("%s:%d", host, *port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	debug("Connected to %s", addr)

	var flags gssapi.ContextFlag
	if *mutual {
		flags |= gssapi.ContextFlagMutual
	}
	if *deleg {
		flags |= gssapi.ContextFlagDeleg
	}

	opts := []gssapi.InitSecContextOption{
		gssapi.WithInitiatorFlags(flags),
	}
	if *mech != "" {
		oid, err := parseOid(*mech)
		if err != nil {
			log.Fatal(err)
		}
		gssMech, err := gssapi.MechFromOid(oid)
		if err != nil {
			log.Fatal(err)
		}
		opts = append(opts, gssapi.WithInitatorMech(gssMech))
	}

	serviceName, err := gss.ImportName(service, gssapi.GSS_NT_HOSTBASED_SERVICE)
	if err != nil {
		log.Fatal(err)
	}
	defer serviceName.Release()

	debug("Requested flags: %s", flags)

	secctx, outToken, err := gss.InitSecContext(serviceName, opts...)
	if err != nil {
		log.Fatal(err)
	}

	defer secctx.Delete()

	if sendErr := sendToken(conn, outToken); sendErr != nil {
		log.Fatal(err)
	}
	debug("Sent context token (%d bytes):", len(outToken))
	debug("%s", formatToken(outToken))

	for secctx.ContinueNeeded() {

		inToken, err := recvToken(conn)
		if err != nil {
			log.Fatal(err)
		}
		debug("Read context token (%d bytes:", len(inToken))
		debug("%s", formatToken(inToken))

		outToken, err = secctx.Continue(inToken)

		if len(outToken) > 0 {
			if err := sendToken(conn, outToken); err != nil {
				log.Fatal(err)
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
		log.Fatal(err)
	}
	printContextInfo(info)

	ntypes, err := gss.InquireNamesForMech(info.Mech)
	if err != nil {
		log.Fatal(err)
	}

	debug("Name types supported by mech:")
	for _, nt := range ntypes {
		debug("  %-30s (%s)", nt, nt.OidString())
	}

	var msgBuf []byte
	if *file {
		msgBuf, err = os.ReadFile(msg)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		msgBuf = []byte(msg)
	}

	// Wrap the message
	outMsg, hasConf, err := secctx.Wrap(msgBuf, *confReq, 0)
	if err != nil {
		log.Fatal(err)
	}

	if !hasConf {
		debug("Warning!  Message not encrypted.")
	}

	if err = sendToken(conn, outMsg); err != nil {
		log.Fatal(err)
	}
	debug("Sent wrap message (%d bytes):\n%s", len(outMsg), formatToken(outMsg))

	// Receive a wrapped token from the server
	msgMIC, err := recvToken(conn)
	if err != nil {
		log.Fatal(err)
	}
	debug("Received MIC message (%d bytes):\n%s", len(msgMIC), formatToken(msgMIC))

	if _, err = secctx.VerifyMIC(msgBuf, msgMIC); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Successfully verified message signature (MIC) from server")

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

func parseOid(s string) (gssapi.Oid, error) {
	// split string into components
	elms := strings.Split(s, ".")

	oid := make(asn1.ObjectIdentifier, len(elms))

	for i, elm := range elms {
		j, err := strconv.ParseUint(elm, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("non-number in OID: %w", err)
		}

		oid[i] = int(j)
	}

	enc, err := asn1.Marshal(oid)
	if err != nil {
		return nil, fmt.Errorf("parsing OID: %w", err)
	}

	return enc[2:], nil
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
	_, err = conn.Read(szBuff)
	if err != nil {
		return
	}

	buf := bytes.NewBuffer(szBuff)
	var tokenSize uint32
	binary.Read(buf, binary.BigEndian, &tokenSize)

	token = make([]byte, tokenSize)
	_, err = conn.Read(token)
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
