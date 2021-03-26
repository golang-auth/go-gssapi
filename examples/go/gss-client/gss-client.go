package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/jake-scott/go-gssapi"
	_ "github.com/jake-scott/go-gssapi/krb5"
)

var _debug bool

func main() {
	port := flag.Int("port", 1234, "remote port to connect to")
	mutual := flag.Bool("mutual", false, "request mutual authentication")
	seal := flag.Bool("seal", false, "seal (encrypt) the message")
	flag.BoolVar(&_debug, "d", false, "enable debugging")
	flag.Parse()

	if flag.NArg() != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-port <int>] [-mutual] [-seal] [-d] host service msg\n", os.Args[0])
		os.Exit(1)
	}

	host := flag.Arg(0)
	service := flag.Arg(1)
	msg := flag.Arg(2)

	// Connect to the host
	addr := fmt.Sprintf("%s:%d", host, *port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	debug("Connected to %s", addr)

	client := gssapi.NewMech("kerberos_v5")

	var flags gssapi.ContextFlag = gssapi.ContextFlagInteg | gssapi.ContextFlagConf | gssapi.ContextFlagReplay | gssapi.ContextFlagSequence
	if *mutual {
		flags |= gssapi.ContextFlagMutual
	}
	if err := client.Initiate(service, flags); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var inToken, outToken []byte

	for !client.IsEstablished() {
		outToken, err = client.Continue(inToken)
		if err != nil {
			break
		}

		if len(outToken) > 0 {
			if sendErr := sendToken(conn, outToken); sendErr != nil {
				err = sendErr
				break
			}
		}

		if !client.IsEstablished() {
			inToken, err = recvToken(conn)
			if err != nil {
				break
			}
		}
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	debug("Context established, sever: %s", client.PeerName())
	gotFlags := gssapi.FlagList(client.ContextFlags())
	for _, f := range gotFlags {
		debug("  context flag: 0x%02x: %s", f, gssapi.FlagName(f))
	}

	// Wrap the message
	outToken, err = client.Wrap([]byte(msg), *seal)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = sendToken(conn, outToken); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Receive a MIC token from the server
	inToken, err = recvToken(conn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err = client.VerifySignature([]byte(msg), inToken); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Successfully verified message signature (MIC) from server")

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
	debug("Wrote %d bytes to server", n)
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
	debug("Read %d byte token from server", n)
	debug("Token bytes: [% x]", token)

	return
}

func debug(format string, args ...interface{}) {
	if !_debug {
		return
	}

	fmt.Printf(format+"\n", args...)
}
