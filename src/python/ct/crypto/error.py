"""Status codes are bad, but True/False is not expressive enough.

Consider a cryptographic signature verification method verify(data, sig) that
returns 1 for valid signatures, 0 for invalid signatures, and -1 to signal some
specific error. This can easily lead to insecure usage such as
if verify(data, sig):
    # do stuff on success

Or, here's another example, borrowed from real code:
r, s = asn1_decode(sig)  # raises ASN1Error
return verify_sig(data, r, s) # returns True/False

A caller may obviously be interested in distinguishing a decoding error from a
signature computation error - but why is a computation error False while a
decoding error is an exception? What other exceptions might this code raise?
This is a nightmare for the caller to handle.

Therefore, methods in the crypto package that verify a property return True
when verification succeeds and raise an exception on any error. This minimises
the risk of uncaught errors, allows to provide information for callers that care
about the specific failure reason, and makes failure handling easy for callers
that do not care:

try:
    verify(myargs)
except MyError:
    # handle specific error here
    return
except VerifyError:
    # verify failed, we don't care why
    return
# do more stuff on success here

Returning True is strictly speaking not needed but simplifies testing.
We provide a defensive returns_true_or_raises wrapper for ensuring this
behaviour: callers of methods decorated with @returns_true_or_raises can be
certain that the _only_ value the method returns is True - it never returns
None, or False, or [], or anything else.
"""

import functools

class Error(Exception):
    """Exceptions raised by the crypto subpackage."""
    pass

class UnsupportedAlgorithmError(Error):
    """Raised when an algorithm is not implemented or supported."""
    pass

class VerifyError(Error):
    """Exceptions raised when some expected property of the input either
    verifiably does not hold, or cannot be conclusively verified.
    Domain-specific verification errors inherit from this class."""
    pass

class ConsistencyError(VerifyError):
    """Raised when there is a (cryptographic) inconsistency in the data."""
    pass

class ProofError(VerifyError):
    """Raised when a cryptographic proof is not valid. This does not necessarily
    indicate that the sought property does not hold but rather that the given
    proof is insufficient for verifying the desired property."""

# TODO(ekasper): TBD if this hierarchy is appropriate.
class EncodingError(Error):
    """Encoding/decoding error: raised when inputs cannot be serialized, or
    serialized data cannot be parsed."""
    pass

class ASN1Error(EncodingError):
    """Raised when an ASN1 object cannot be encoded or decoded."""
    pass

class UnknownASN1AttributeTypeError(ASN1Error):
    """Raised when an ASN1 AttributeType OID is not known."""
    pass

class SignatureError(VerifyError):
    """Raised when a public-key signature does not verify."""
    pass

def returns_true_or_raises(f):
    """A safety net for functions that are only allowed to return True or raise
    an exception."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        ret = f(*args, **kwargs)
        if ret is not True:
            raise RuntimeError("Unexpected return value %r" % ret)
        return True
    return wrapped
