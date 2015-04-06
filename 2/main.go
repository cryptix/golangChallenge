package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	// use a pipe to write the deciphered messages to our returned reader
	pr, pw := io.Pipe()

	var shared [32]byte
	box.Precompute(&shared, pub, priv)

	go func(r io.Reader, pw *io.PipeWriter) {
		for { // until an error occurs
			// read next ciphered message from the passed reader
			msg := make([]byte, 32*1024)
			n, err := io.ReadAtLeast(r, msg, 25)
			if err != nil {
				// the closed conn check could be nicer but there is no way to access the abstracted TCPConn cleanly with the pipes involved
				if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
					if err = pw.Close(); err != nil {
						log.Println("close pipe writer failed:", err)
					}
					return
				}
				log.Println("secReader read(msg) failed", err)
				if err2 := pw.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}

			// slice of the unused rest of the buffer
			msg = msg[:n]

			// copy the nonce from the message
			var nonce [24]byte
			copy(nonce[:], msg[:24])

			// cut of the nonce
			msg = msg[24:]

			// decrypt message
			clearMsg, ok := box.OpenAfterPrecomputation([]byte{}, msg, &nonce, &shared)
			if !ok {
				log.Println("Open not ok")
				if err2 := pw.CloseWithError(errors.New("open failed")); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}

			// copy the decrypted message to our pipe
			_, err = io.Copy(pw, bytes.NewReader(clearMsg))
			if err != nil {
				log.Println("io.Write(w, clearMsg) failed", err)
				if err2 := pw.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}
		}
	}(r, pw)
	return pr
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	// use a pipe to read whats written to our returned writer
	pr, pw := io.Pipe()

	var shared [32]byte
	box.Precompute(&shared, pub, priv)

	go func(w io.Writer, pr *io.PipeReader) {
		for { // until an error occurs
			// read the clear message from our pipe
			msg := make([]byte, 1024)
			n, err := pr.Read(msg)
			if err != nil {
				log.Println("pr.Read(msg) failed", err)
				if err2 := pr.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}

			// cut of the unused bytes
			msg = msg[:n]

			// read 24 bytes of random for our nonce
			var nonce [24]byte
			_, err = io.ReadFull(rand.Reader, nonce[:])
			if err != nil {
				log.Println("rand.Read(nonce) failed", err)
				if err2 := pr.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}

			// encrypt and sign our message with the prepended nonce
			buf := box.SealAfterPrecomputation(nonce[:], msg, &nonce, &shared)

			// copy the sealed message with our passed writer
			_, err = io.Copy(w, bytes.NewReader(buf))
			if err != nil {
				log.Println("w.Write(buf) failed", err)
				if err2 := pr.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}
		}
	}(w, pr)
	return pw
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	// open a tcp socket
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// get their public key
	var theirPub [32]byte
	_, err = io.ReadFull(conn, theirPub[:])
	if err != nil {
		return nil, err
	}

	// generate us a new key
	myPub, myPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// our public key is sent to the other party
	_, err = io.Copy(conn, bytes.NewReader(myPub[:]))
	if err != nil {
		return nil, err
	}

	// their public key is used to verify the signature of what we receive
	secR := NewSecureReader(conn, myPriv, &theirPub)

	// our private key is used to sign our messages
	// their public key is used to encrypt the messages that we send
	secW := NewSecureWriter(conn, myPriv, &theirPub)

	return struct {
		io.Reader
		io.Writer
		io.Closer
	}{secR, secW, conn}, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {

			// generate us a new key
			myPub, myPriv, err := box.GenerateKey(rand.Reader)
			if err != nil {
				log.Fatal(err)
			}

			// our public key is sent to the other party
			_, err = io.Copy(c, bytes.NewReader(myPub[:]))
			if err != nil {
				log.Fatal(err)
			}

			// get their public key
			var theirPub [32]byte
			_, err = io.ReadFull(c, theirPub[:])
			if err != nil {
				log.Fatal(err)
			}

			// their public key is used to verify the signature of what we receive
			secR := NewSecureReader(c, myPriv, &theirPub)

			// our private key is used to sign our messages
			// their public key is used to encrypt the messages that we send
			secW := NewSecureWriter(c, myPriv, &theirPub)

			_, err = io.Copy(secW, secR)
			if err != nil {
				log.Fatal(err)
			}

		}(conn)
	}
	panic("unreached")
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
