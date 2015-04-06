package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

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
				if err == io.EOF {
					pw.Close()
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

			log.Println("[DBG] secReader cipher msg:", n)
			fmt.Print(hex.Dump(msg))

			// copy the nonce from the message
			var nonce [24]byte
			copy(nonce[:], msg[:24])

			log.Println("[DBG] nonce:")
			fmt.Print(hex.Dump(nonce[:]))

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

			log.Println("[DBG] Opened:")
			fmt.Print(hex.Dump(clearMsg))

			// write decrypted message to our pipe
			n, err = pw.Write(clearMsg)
			if err != nil {
				log.Println("io.Write(w, clearMsg) failed", err)
				if err2 := pw.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}

			if n < len(clearMsg) {
				log.Println("write fell short")
				if err2 := pw.CloseWithError(errors.New("short write")); err2 != nil {
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

			log.Println("[DBG] SecW Write:", n)
			fmt.Print(hex.Dump(msg))

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

			log.Println("[DBG] nonce:", len(nonce))
			fmt.Print(hex.Dump(nonce[:]))

			// encrypt and sign our message with the prepended nonce
			buf := box.SealAfterPrecomputation(nonce[:], msg, &nonce, &shared)

			log.Println("[DBG] sealed:", len(buf))
			fmt.Print(hex.Dump(buf))

			// send the sealed message with our passed writer
			n, err = w.Write(buf)
			if err != nil {
				log.Println("w.Write(buf) failed", err)
				if err2 := pr.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}

			// we didn't write everything..!
			if n < len(buf) {
				log.Println("failed writing buf to w")
				if err2 := pr.CloseWithError(errors.New("short write")); err2 != nil {
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
	log.Println("[DBG] Dialing", addr)
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

	log.Println("[DBG] got pub key")
	fmt.Println(hex.Dump(theirPub[:]))

	// generate us a new key
	myPub, myPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	log.Println("[DBG] generated privkey")
	fmt.Println(hex.Dump(myPriv[:]))

	log.Println("[DBG] generated pubkey")
	fmt.Println(hex.Dump(myPub[:]))

	// our public key is sent to the other party
	_, err = io.Copy(conn, bytes.NewReader(myPub[:]))
	if err != nil {
		return nil, err
	}

	log.Println("[DBG] pubkey sent")

	// their public key is used to verify the signature of what we receive
	secR := NewSecureReader(conn, myPriv, &theirPub)

	// our private key is used to sign our messages
	// their public key is used to encrypt the messages that we send
	secW := NewSecureWriter(conn, myPriv, &theirPub)

	log.Println("[DBG] conn wrapped")

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

			log.Println("[DBG] generated privkey")
			fmt.Println(hex.Dump(myPriv[:]))

			log.Println("[DBG] generated pubkey")
			fmt.Println(hex.Dump(myPub[:]))

			// our public key is sent to the other party
			_, err = io.Copy(c, bytes.NewReader(myPub[:]))
			if err != nil {
				log.Fatal(err)
			}

			log.Println("[DBG] pubkey sent")

			// get their public key
			var theirPub [32]byte
			_, err = io.ReadFull(c, theirPub[:])
			if err != nil {
				log.Fatal(err)
			}

			log.Println("[DBG] got pub key")
			fmt.Println(hex.Dump(theirPub[:]))

			// their public key is used to verify the signature of what we receive
			secR := NewSecureReader(c, myPriv, &theirPub)

			// our private key is used to sign our messages
			// their public key is used to encrypt the messages that we send
			secW := NewSecureWriter(c, myPriv, &theirPub)

			log.Println("[DBG] c wrapped")

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
