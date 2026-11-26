// Command compat is the bounded Go consumer for the release compatibility
// matrix.  It is intentionally separate from the historical fuzzing runner
// in runners/go-runner/main.go.
//
// The process reads one JSON request from stdin and writes one JSON response
// to stdout.  Only the verify operation is implemented here; Python is the
// publisher because Tink's Python public API exposes the JWK export helper.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

type request struct {
	Operation string  `json:"operation"`
	Checks    []check `json:"checks"`
}

type check struct {
	ID      string          `json:"id"`
	JWKS    json.RawMessage `json:"jwks"`
	Compact string          `json:"compact"`
	Issuer  string          `json:"issuer"`
	Now     int64           `json:"now"`
}

type result struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

type response struct {
	Version string   `json:"version"`
	Runtime string   `json:"runtime"`
	Results []result `json:"results"`
}

type protocolError struct {
	Error string `json:"error"`
}

func tinkVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep == nil || dep.Path != "github.com/tink-crypto/tink-go/v2" {
			continue
		}
		if dep.Replace != nil && dep.Replace.Version != "" {
			return cleanVersion(dep.Replace.Version)
		}
		if dep.Version != "" {
			return cleanVersion(dep.Version)
		}
	}
	return "unknown"
}

func cleanVersion(version string) string {
	version = strings.TrimPrefix(version, "v")
	if at := strings.IndexByte(version, '+'); at >= 0 {
		version = version[:at]
	}
	return version
}

func runtimeName() string {
	return fmt.Sprintf("go %s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func invalidRequest(message string) error {
	return fmt.Errorf("invalid compatibility request: %s", message)
}

func verifyCheck(item check) (out result) {
	out.ID = item.ID
	defer func() {
		if recovered := recover(); recovered != nil {
			out.Outcome = "error"
			out.Detail = "verification runtime failure"
		}
	}()

	// Import and primitive construction are setup failures.  They must not be
	// reported as rejected signatures: the matrix treats those outcomes as a
	// broken adapter rather than a valid negative vector.
	if len(item.JWKS) == 0 || !json.Valid(item.JWKS) {
		return result{ID: item.ID, Outcome: "error", Detail: "key setup failed"}
	}
	handle, err := jwt.JWKSetToPublicKeysetHandle(item.JWKS)
	if err != nil {
		return result{ID: item.ID, Outcome: "error", Detail: "key setup failed"}
	}
	verifier, err := jwt.NewVerifier(handle)
	if err != nil {
		return result{ID: item.ID, Outcome: "error", Detail: "verifier setup failed"}
	}
	issuer := item.Issuer
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer: &issuer,
		FixedNow:       time.Unix(item.Now, 0).UTC(),
	})
	if err != nil {
		return result{ID: item.ID, Outcome: "error", Detail: "validator setup failed"}
	}

	// Tink's verifier deliberately reports malformed, expired, wrong-issuer,
	// and bad-signature tokens through the same verification error channel.
	// They are all expected negative vectors for this consumer contract.
	if _, err := verifier.VerifyAndDecode(item.Compact, validator); err != nil {
		return result{ID: item.ID, Outcome: "rejected"}
	}
	return result{ID: item.ID, Outcome: "verified"}
}

func run(input []byte) ([]byte, int) {
	var payload request
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return marshalError(invalidRequest("request is not valid JSON"))
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return marshalError(invalidRequest("request must contain one JSON object"))
	}
	if payload.Operation != "verify" {
		return marshalError(invalidRequest("operation must be verify"))
	}
	if payload.Checks == nil {
		return marshalError(invalidRequest("checks must be an array"))
	}
	for _, item := range payload.Checks {
		if item.ID == "" {
			return marshalError(invalidRequest("each check requires a non-empty id"))
		}
		if item.Compact == "" {
			return marshalError(invalidRequest("each check requires a compact JWT"))
		}
		if item.Issuer == "" {
			return marshalError(invalidRequest("each check requires an issuer"))
		}
	}

	results := make([]result, 0, len(payload.Checks))
	for _, item := range payload.Checks {
		results = append(results, verifyCheck(item))
	}
	out := response{Version: tinkVersion(), Runtime: runtimeName(), Results: results}
	encoded, err := json.Marshal(out)
	if err != nil {
		return marshalError(fmt.Errorf("encoding response: %w", err))
	}
	return encoded, 0
}

func marshalError(err error) ([]byte, int) {
	encoded, marshalErr := json.Marshal(protocolError{Error: err.Error()})
	if marshalErr != nil {
		return []byte(`{"error":"protocol failure"}`), 2
	}
	return encoded, 2
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		encoded, code := marshalError(fmt.Errorf("reading request: %w", err))
		_, _ = os.Stdout.Write(append(encoded, '\n'))
		os.Exit(code)
	}
	encoded, code := run(input)
	_, _ = os.Stdout.Write(append(encoded, '\n'))
	os.Exit(code)
}
