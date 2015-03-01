// Package drum is supposed to implement the decoding of .splice drum machine files.
// See golang-challenge.com/go-challenge1/ for more information
package drum

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// custom errors that might be returned by this drum package
var (
	ErrIllegalFtype = errors.New("Illegal Filetype")
)

var (
	ftype = [6]byte{'S', 'P', 'L', 'I', 'C', 'E'}
)

type header struct {
	// first 6 bytes should be "SPLICE"
	Ftype [6]byte

	//FileLen: wc -c $spiliceFile == FileLen+6 (Ftype)
	_ [8]byte

	// what device this is for - might be longer, lots of zero afterwards
	Version [11]byte
}

func decode(in io.Reader) (*Pattern, error) {
	var p Pattern
	var h header
	if err := binary.Read(in, binary.LittleEndian, &h); err != nil {
		return nil, err
	}

	if bytes.Compare(h.Ftype[:], ftype[:]) != 0 {
		return nil, ErrIllegalFtype
	}

	p.Version = string(h.Version[:])

	return &p, nil
}
