// go-runner reads a JWK Set from stdin, calls
// github.com/tink-crypto/tink-go/v2/jwt.JWKSetToPublicKeysetHandle,
// and emits a single JSON line describing the verdict.
//
// Output schema:
//   {"verdict":"ACCEPT|REJECT_TINK|REJECT_OTHER",
//    "error_class":"<go-error-type-name>",
//    "error_msg":"<truncated>",
//    "keyset_shape":"<opaque>"}
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

type result struct {
	Verdict     string `json:"verdict"`
	ErrorClass  string `json:"error_class,omitempty"`
	ErrorMsg    string `json:"error_msg,omitempty"`
	KeysetShape string `json:"keyset_shape,omitempty"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func runOne(input []byte) (r result) {
	defer func() {
		if rec := recover(); rec != nil {
			// Go panics are the equivalent of Python uncaught: REJECT_OTHER
			r = result{
				Verdict:    "REJECT_OTHER",
				ErrorClass: "panic",
				ErrorMsg:   truncate(fmt.Sprintf("%v\n%s", rec, debug.Stack()), 400),
			}
		}
	}()

	_, err := jwt.JWKSetToPublicKeysetHandle(input)
	if err != nil {
		// Tink-go returns errors via standard error interface; treat any
		// non-nil err as REJECT_TINK. We only see REJECT_OTHER on panic.
		return result{
			Verdict:    "REJECT_TINK",
			ErrorClass: fmt.Sprintf("%T", err),
			ErrorMsg:   truncate(err.Error(), 200),
		}
	}
	return result{Verdict: "ACCEPT", KeysetShape: "<opaque>"}
}

func main() {
	buf := bytes.Buffer{}
	if _, err := io.Copy(&buf, os.Stdin); err != nil {
		out, _ := json.Marshal(result{
			Verdict:    "REJECT_OTHER",
			ErrorClass: "stdin-read",
			ErrorMsg:   err.Error(),
		})
		fmt.Println(string(out))
		os.Exit(1)
	}

	r := runOne(buf.Bytes())
	out, _ := json.Marshal(r)
	fmt.Println(string(out))
}
