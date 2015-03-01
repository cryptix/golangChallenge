package drum

import "fmt"

// Track represents an ID, Name and the pattern for a single track
type Track struct {
	ID    int
	Name  string
	Steps Steps
}

func (t Track) String() string {
	return fmt.Sprintf("(%d) %s %s\n", t.ID, t.Name, t.Steps)
}

const stepCnt = 16

// Steps holds stepCnt bools (one step is a bool) and can print them as ascii
type Steps [stepCnt]bool

func newSteps(in [stepCnt]byte) Steps {
	var out Steps
	for i := 0; i < stepCnt; i++ {
		if in[i] == 1 {
			out[i] = true
		}
	}
	return out
}

// String implements stringer
func (s Steps) String() string {
	var o string
	for i := 0; i < stepCnt; i++ {
		if i%4 == 0 {
			o += "|"
		}
		if s[i] {
			o += "x"
		} else {
			o += "-"
		}
	}
	o += "|"
	return o
}
