package header

// SeqValue is a minimal stub for fuzzing — matches gvisor's seqnum.Value uint32 alias
type SeqValue uint32
type SACKBlock struct {
	Start SeqValue
	End   SeqValue
}
