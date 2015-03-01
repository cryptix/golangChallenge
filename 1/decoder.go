package drum

import (
	"fmt"
	"os"
)

// DecodeFile decodes the drum machine file found at the provided path
// and returns a pointer to a parsed pattern which is the entry point to the
// rest of the data.
func DecodeFile(path string) (*Pattern, error) {
	var p *Pattern
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	if p, err = decode(f); err != nil {
		return nil, err
	}

	return p, f.Close()
}

// Pattern is the high level representation of the
// drum pattern contained in a .splice file.
type Pattern struct {
	Version string
	// Len     int
	Tempo  float64
	Tracks []Track
}

func (p Pattern) String() string {
	s := fmt.Sprintln("Saved with HW Version:", p.Version)
	// s += fmt.Sprintln("Len:", p.Len)
	s += fmt.Sprintln("Tempo:", p.Tempo)
	for _, t := range p.Tracks {
		s += fmt.Sprint(t)
	}
	return s
}
