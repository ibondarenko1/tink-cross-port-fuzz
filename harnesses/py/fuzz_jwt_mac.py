"""Atheris fuzzer for tink-py JWT MAC verify_and_decode.

Sets up a fixed HMAC keyset once, then for each fuzz input feeds it as a
JWT compact token to verify_mac_and_decode. Uncaught exceptions
(non-TinkError, non-JwtInvalidError) are flagged as contract violations.
"""
import sys
import atheris

with atheris.instrument_imports():
    import tink
    from tink import jwt

    # One-time setup: a fresh HMAC keyset for verification.
    jwt.register_jwt_mac()
    handle = tink.new_keyset_handle(jwt.jwt_hs256_template())
    primitive = handle.primitive(jwt.JwtMac)
    validator = jwt.new_validator(allow_missing_expiration=True)


def TestOneInput(data: bytes) -> None:
    try:
        token = data.decode("utf-8", errors="replace")
        primitive.verify_mac_and_decode(token, validator)
    except (tink.TinkError, jwt.JwtInvalidError, ValueError, UnicodeDecodeError, KeyError, TypeError):
        return
    except Exception as e:
        # Anything else = uncaught contract violation
        sys.stderr.write(f"UNCAUGHT {type(e).__name__}: {e!r} input_len={len(data)}\n")
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
