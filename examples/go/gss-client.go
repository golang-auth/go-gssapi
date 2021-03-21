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
		fmt.Fprintf(os.Stderr, "Usage: %s [-port <int>] [-mutual] [-seal] host service msg\n", os.Args[0])
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

	var flags gssapi.ContextFlag
	if *mutual {
		flags |= gssapi.ContextFlagMutual
	}
	outToken, err := client.Initiate(service, flags)

	for {
		if len(outToken) > 0 {
			if sendErr := sendToken(conn, outToken); sendErr != nil {
				err = sendErr
			}
		}

		if err != gssapi.ContinueNeeded {
			break
		}

		var inToken []byte
		inToken, err = recvToken(conn)
		if err != nil {
			break
		}

		outToken, err = client.Continue(inToken)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Wrap the message
	outToken, err = client.Wrap([]byte(msg), *seal)
	sendToken(conn, outToken)
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

	return
}

func debug(format string, args ...interface{}) {
	if !_debug {
		return
	}

	fmt.Printf(format+"\n", args...)
}
