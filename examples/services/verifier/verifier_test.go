package verifier

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestBillingMessage(t *testing.T) {
	data, err := os.ReadFile("../../../tink_compat/data/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RSA struct {
			State         json.RawMessage
			Token, Issuer string
			Now           int64
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if err := Verify(fixture.RSA.State, fixture.RSA.Token, fixture.RSA.Issuer, time.Unix(fixture.RSA.Now, 0)); err != nil {
		t.Fatal(err)
	}
}
