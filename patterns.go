package noise

type step byte

const (
	e step = iota + 1
	s
	ee
	es
	se
	ss
	psk
	sig
)

type PatternType string

const (
	XK     PatternType = "XK"
	XKpsk3 PatternType = "XKpsk3"
	XXsig  PatternType = "XXSig"
)

var (
	xk = Pattern{
		PreMessages: []step{s},
		Steps: [][]step{
			{e, es},
			{e, ee},
			{s, se},
		},
	}
	xkpsk3 = Pattern{
		PreMessages: []step{s},
		Steps: [][]step{
			{e, es},
			{e, ee},
			{s, se, psk},
		},
	}
	xxsig = Pattern{
		Steps: [][]step{
			{e},
			{e, ee, sig},
			{sig},
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
	case XK:
		return xk
	case XKpsk3:
		return xkpsk3
	default:
		panic("unknown pattern")
	}
}
