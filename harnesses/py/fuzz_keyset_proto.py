"""Atheris fuzzer for tink-py proto_keyset_format.parse_without_secret.

Feeds arbitrary bytes as a binary Tink Keyset proto to the public-keyset
parser. This is the deserialization path used by every JWT verifier
that loads an external public-key keyset.
"""
import sys
import atheris

with atheris.instrument_imports():
    import tink
    from tink import proto_keyset_format

    # Register at least one key type so the registry isn't empty
    from tink import jwt as _jwt
    _jwt.register_jwt_signature()


def TestOneInput(data: bytes) -> None:
    try:
        proto_keyset_format.parse_without_secret(bytes(data))
    except (tink.TinkError, ValueError, KeyError, TypeError, RuntimeError):
        return
    except Exception as e:
        sys.stderr.write(f"UNCAUGHT {type(e).__name__}: {e!r} input_len={len(data)}\n")
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
