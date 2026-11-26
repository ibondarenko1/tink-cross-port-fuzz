// Package verifier checks tokens addressed to the example billing service.
package verifier

import (
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

// Verify checks a signed message using the published keys and the service clock.
func Verify(jwks []byte, compact, issuer string, now time.Time) error {
	handle, err := jwt.JWKSetToPublicKeysetHandle(jwks)
	if err != nil {
		return err
	}
	verifier, err := jwt.NewVerifier(handle)
	if err != nil {
		return err
	}
	audience := "billing-api"
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer: &issuer, ExpectedAudience: &audience, FixedNow: now,
	})
	if err != nil {
		return err
	}
	_, err = verifier.VerifyAndDecode(compact, validator)
	return err
}
