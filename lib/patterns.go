package noise

type step byte

const (
	e step = iota + 1
	s
	ee
	es
	se
	ss
)

type PatternType string

const (
	xk PatternType = "XK"
)

var (
	XK = Pattern{
		PreMessages: []step{s},
		Steps: [][]step{
			{e, es},
			{e, ee},
			{s, se},
		},
	}
)

type Pattern struct {
	PreMessages []step
	Steps       [][]step
}

func (p Pattern) Len() int {
	return len(p.Steps)
}

func GetPattern(pattern PatternType) Pattern {
	switch pattern {
	case xk:
		return XK
	default:
		panic("unknown pattern")
	}
}