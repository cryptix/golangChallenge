// Package drum is supposed to implement the decoding of .splice drum machine files.
// See golang-challenge.com/go-challenge1/ for more information
package drum

import (
	"errors"
	"io"
)

func decode(in io.Reader) (*Pattern, error) {
	return nil, errors.New("TODO Header")
}
