// Package drum is supposed to implement the decoding of .splice drum machine files.
// See golang-challenge.com/go-challenge1/ for more information
package drum

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// custom errors that might be returned by this drum package
var (
	ErrIllegalFtype  = errors.New("Illegal Filetype")
	ErrShortStepRead = errors.New("Could not read enough steps")
)

var (
	ftype = [6]byte{'S', 'P', 'L', 'I', 'C', 'E'}
)

type header struct {
	// first 6 bytes should be "SPLICE"
	Ftype [6]byte

	//FileLen: wc -c $spiliceFile == FileLen+6 (Ftype)
	// big endian.. challenge didn't include malformed examples so i wont test them
	FileLen [8]byte

	// what device this is for - might be longer, lots of zero afterwards
	Version [11]byte

	// padding - tempo must be somewhere in here
	_ [25]byte
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

	// how many bytes in the header after filetype header
	n := binary.BigEndian.Uint16(h.FileLen[6:])

	n -= 50 // sizeof(header)

	// fmt.Println(hex.Dump(h.FileLen[6:]))
	fmt.Println("Len:", n)

	for n > 0 {
		var t Track

		fmt.Println("bytes left:", n)

		var trackID int8
		if err := binary.Read(in, binary.BigEndian, &trackID); err != nil {
			return nil, err
		}
		n--
		t.ID = int(trackID)

		// discard three bytes in between
		var discard [3]byte
		if _, err := in.Read(discard[:]); err != nil {
			return nil, err
		}
		n -= 3

		// read length of Track name
		var nameLen int8
		if err := binary.Read(in, binary.BigEndian, &nameLen); err != nil {
			return nil, err
		}
		n--

		// fmt.Println("nameLen", nameLen)

		// read n bytes of track name
		var nameBuf bytes.Buffer
		if _, err := io.CopyN(&nameBuf, in, int64(nameLen)); err != nil {
			return nil, err
		}
		n -= uint16(nameLen)

		t.Name = nameBuf.String()
		// fmt.Println("name:", t.Name)

		// read stepCnt bytes of steps
		var steps [stepCnt]byte
		stepN, err := in.Read(steps[:])
		if err != nil {
			return nil, err
		}
		if stepN < stepCnt {
			return nil, ErrShortStepRead
		}
		n -= stepCnt

		t.Steps = newSteps(steps)

		p.Tracks = append(p.Tracks, t)
	}
	fmt.Println(p)
	return &p, nil
}
