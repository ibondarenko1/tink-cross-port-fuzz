package header

import "encoding/binary"

const (
	TCPOptionEOL       = 0
	TCPOptionNOP       = 1
	TCPOptionMSS       = 2
	TCPOptionWS        = 3
	TCPOptionTS        = 8
	TCPOptionSACKPermitted = 4
	TCPOptionSACK      = 5
)

// TCPOptions holds parsed TCP options.
type TCPOptions struct {
	TS          bool
	TSVal       uint32
	TSEcr       uint32
	SACKBlocks  []SACKBlock
}

// ParseTCPOptions: copy of gvisor pkg/tcpip/header/tcp.go ParseTCPOptions
// HEAD 478925c (2026-04-28). Minimal vendored copy for fuzzing.
func ParseTCPOptions(b []byte) TCPOptions {
	opts := TCPOptions{}
	limit := len(b)
	for i := 0; i < limit; {
		switch b[i] {
		case TCPOptionEOL:
			i = limit
		case TCPOptionNOP:
			i++
		case TCPOptionTS:
			if i+10 > limit || (b[i+1] != 10) {
				return opts
			}
			opts.TS = true
			opts.TSVal = binary.BigEndian.Uint32(b[i+2:])
			opts.TSEcr = binary.BigEndian.Uint32(b[i+6:])
			i += 10
		case TCPOptionSACK:
			if i+2 > limit {
				return opts
			}
			sackOptionLen := int(b[i+1])
			if i+sackOptionLen > limit || (sackOptionLen-2)%8 != 0 {
				return opts
			}
			numBlocks := (sackOptionLen - 2) / 8
			opts.SACKBlocks = []SACKBlock{}
			for j := 0; j < numBlocks; j++ {
				start := binary.BigEndian.Uint32(b[i+2+j*8:])
				end := binary.BigEndian.Uint32(b[i+2+j*8+4:])
				opts.SACKBlocks = append(opts.SACKBlocks, SACKBlock{
					Start: SeqValue(start),
					End:   SeqValue(end),
				})
			}
			i += sackOptionLen
		default:
			if i+2 > limit {
				return opts
			}
			l := int(b[i+1])
			if l < 2 || i+l > limit {
				return opts
			}
			i += l
		}
	}
	return opts
}
