package main

import (
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
			clearMsg, ok := box.Open([]byte{}, msg, &nonce, pub, priv)
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
			buf := box.Seal(nonce[:], msg, &nonce, pub, priv)

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
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
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
