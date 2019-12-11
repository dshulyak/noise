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
	xk     PatternType = "XK"
	xkpsk3 PatternType = "XKpsk3"
	xxsig  PatternType = "XXSig"
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
	XKpsk3 = Pattern{
		PreMessages: []step{s},
		Steps: [][]step{
			{e, es},
			{e, ee},
			{s, se, psk},
		},
	}
	XXSig = Pattern{
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
	case xk:
		return XK
	case xkpsk3:
		return XKpsk3
	default:
		panic("unknown pattern")
	}
}
