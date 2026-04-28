package header

import (
	"bytes"
	"testing"
)

func FuzzParseTCPOptions(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x01, 0x01, 0x01})
	f.Add([]byte{0x02, 0x04, 0x05, 0xb4})
	f.Add([]byte{0x08, 0x0a, 0, 0, 0, 1, 0, 0, 0, 1})
	f.Add([]byte{0x05, 0x0a, 0, 0, 0, 1, 0, 0, 0, 2})
	f.Add([]byte{0x05, 0x01})
	f.Add([]byte{0x05, 0xff})
	f.Add([]byte{0xff, 0x00})
	f.Add([]byte{0xff, 0x01})
	f.Add(bytes.Repeat([]byte{0x01}, 40))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseTCPOptions(data)
	})
}
