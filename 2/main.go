package main

import (
	"encoding/binary"
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
	pr, pw := io.Pipe()
	var non uint32 = 420
	go func() {
		for {
			// read next ciphered message
			ciph := make([]byte, 32*1024)
			n, err := r.Read(ciph)
			if err != nil {
				if err == io.EOF {
					pr.Close()
					return
				}
				log.Println("secReader read(ciph) failed", err)
				if err2 := pr.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}
			ciph = ciph[:n]
			log.Println("SecR Read:", n)
			fmt.Print(hex.Dump(ciph))

			var nonceBytes [24]byte
			binary.BigEndian.PutUint32(nonceBytes[:], non)

			log.Println("nonce:", non)
			fmt.Print(hex.Dump(nonceBytes[:]))
			non++

			// decrypt message
			outBuf, ok := box.Open([]byte{}, ciph, &nonceBytes, pub, priv)
			if !ok {
				log.Println("Open not ok")
				if err2 := pw.CloseWithError(errors.New("open failed")); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}

			log.Println("Opened:")
			fmt.Print(hex.Dump(outBuf))

			n, err = pw.Write(outBuf)
			if err != nil {
				log.Println("io.Write(w, outBuf) failed", err)
				if err2 := pr.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}

			if n < len(outBuf) {
				log.Println("write fell short")
				if err2 := pw.CloseWithError(errors.New("short write")); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}
		}
	}()
	return pr
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	pr, pw := io.Pipe()
	var non uint32 = 420
	go func() {
		for {
			msg := make([]byte, 1024)
			n, err := pr.Read(msg)
			if err != nil {
				log.Println("pr.Read(msg) failed", err)
				if err2 := pw.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}
			msg = msg[:n]
			log.Println("SecW Write:", n)
			fmt.Print(hex.Dump(msg))

			var nonceBytes [24]byte
			binary.BigEndian.PutUint32(nonceBytes[:], non)
			log.Println("nonce:", non)
			fmt.Print(hex.Dump(nonceBytes[:]))
			non++

			buf := box.Seal([]byte{}, msg, &nonceBytes, pub, priv)

			log.Println("sealed:")
			fmt.Print(hex.Dump(buf))

			n, err = w.Write(buf)
			if err != nil {
				log.Println("w.Write(buf) failed", err)
				if err2 := pw.CloseWithError(err); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}

			if n < len(buf) {
				log.Println("write fell short")
				if err2 := pw.CloseWithError(errors.New("short write")); err2 != nil {
					log.Println("CloseWithError failed", err2)
				}
				return
			}
		}
	}()
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
