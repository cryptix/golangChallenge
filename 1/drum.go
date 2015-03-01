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

	// read header bytes
	var h header
	if err := binary.Read(in, binary.LittleEndian, &h); err != nil {
		return nil, err
	}

	// check filetype
	if bytes.Compare(h.Ftype[:], ftype[:]) != 0 {
		return nil, ErrIllegalFtype
	}

	// take HW Version from header
	p.Version = string(h.Version[:])

	// TODO: find temp
	p.Tempo = 120

	// how many bytes in the header after filetype header
	n := int(binary.BigEndian.Uint16(h.FileLen[6:]))
	n -= 50 // sizeof(header)

	// iterate until all bytes are consumed
	for n > 0 {
		var t Track

		// read trackID from first byte after header
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

		// read nameLen bytes of track name
		var nameBuf bytes.Buffer
		if _, err := io.CopyN(&nameBuf, in, int64(nameLen)); err != nil {
			return nil, err
		}
		n -= int(nameLen)
		t.Name = nameBuf.String()

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
		t.Steps = Steps(steps)

		p.Tracks = append(p.Tracks, t)
	}
	return &p, nil
}
