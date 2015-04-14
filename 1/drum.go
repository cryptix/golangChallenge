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

type header struct {
	// first 6 bytes should be "SPLICE"
	Ftype [6]byte

	//FileLen: wc -c $spiliceFile == FileLen+6 (Ftype)
	// big endian.. challenge didn't include malformed examples so i wont test them
	FileLen [8]byte

	// what device this is for - might be longer, lots of zero afterwards
	Version [11]byte

	// padding
	_ [21]byte

	// which tempo to play this pattern at
	Tempo float32
}

// decodes the data from the passed Reader into a Pattern with multiple tracks
func decode(in io.Reader) (*Pattern, error) {
	var p Pattern

	// read header bytes
	var h header
	if err := binary.Read(in, binary.LittleEndian, &h); err != nil {
		return nil, err
	}

	// check filetype
	if bytes.Compare(h.Ftype[:], []byte{'S', 'P', 'L', 'I', 'C', 'E'}) != 0 {
		return nil, ErrIllegalFtype
	}

	// take HW Version from header
	p.Version = string(h.Version[:])
	//split of trailing zeros
	if i := bytes.IndexByte(h.Version[:], 0); i != -1 {
		p.Version = p.Version[:i]
	}

	// copy tempo to Pattern
	p.Tempo = h.Tempo

	// how many bytes in the header after filetype header
	in = io.LimitReader(in, int64(binary.BigEndian.Uint16(h.FileLen[6:])))

	// wrap the reader so that we only check err once at the end
	sr := &stickyReader{r: in}

	for sr.err == nil {
		var t Track

		// read trackID from first byte after header
		var trackID uint8
		binary.Read(sr, binary.BigEndian, &trackID)
		t.ID = int(trackID)

		// discard three bytes in between
		var discard [3]byte
		sr.Read(discard[:])

		// read length of Track name
		var nameLen int8
		binary.Read(sr, binary.BigEndian, &nameLen)

		// read nameLen bytes of track name
		var nameBuf bytes.Buffer
		io.CopyN(&nameBuf, sr, int64(nameLen))
		t.Name = nameBuf.String()

		// read stepCnt bytes of steps
		var steps [stepCnt]byte
		stepN, err := sr.Read(steps[:])
		// one explicit check because we will append an empty track otherwise
		if err != nil {
			break
		}
		if stepN < stepCnt {
			return nil, ErrShortStepRead
		}
		t.Steps = Steps(steps)

		p.Tracks = append(p.Tracks, t)

	}

	return &p, sr.err
}

type stickyReader struct {
	r   io.Reader
	err error
}

func (sr *stickyReader) Read(p []byte) (int, error) {
	if sr.err != nil {
		return -1, sr.err
	}
	n, err := sr.r.Read(p)
	if err != nil {
		sr.err = err
		return n, err
	}
	return n, nil
}
