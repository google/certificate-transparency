"""X509v3 extensions."""
from ct.crypto import error
from ct.crypto.asn1 import oid
from ct.crypto.asn1 import types

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import constraint
from pyasn1.type import namedtype


class ExtensionID(oid.ValueTypeIdentifier):
    """Extension identifier OIDs."""

    def value_type(self):
        """Get the ASN.1 type object corresponding to the OID.

        Returns:
            an ASN.1 type object.

        Raises:
            ct.crypto.error.UnknownASN1TypeError.
        """
        try:
            return _EXTENSION_VALUE_TYPE_DICT[self]
        except KeyError:
            raise error.UnknownASN1TypeError("Unknown extension ID: %s"
                                             % self.human_readable())


class DecodedExtension(types.Sequence):
    """X509v3 extension with decoded value."""
    PRINT_DELIMITER = ", "
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("extnID", ExtensionID()),
        namedtype.DefaultedNamedType("critical", types.Boolean("False")),
        namedtype.NamedType("extnValue", oid.DecodableAny())
        )


class Extension(types.Sequence):
    """X509v3 extension."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("extnID", ExtensionID()),
        namedtype.DefaultedNamedType("critical", types.Boolean("False")),
        namedtype.NamedType("extnValue", types.OctetString())
        )

    def human_readable_lines(self, wrap=80, label=""):
        """Human-readable output."""
        # We can't cache the decoded value here because we can't control when
        # the value is modified.
        decoded = DecodedExtension()
        decoded.setComponentByName("extnID", self.getComponentByName("extnID"))
        decoded.setComponentByName("critical",
                                   self.getComponentByName("critical"))
        try:
            extn_value = self.get_decoded_value()
        except error.ASN1Error:
            extn_value = self.getComponentByName("extnValue")
        decoded.setComponentByName("extnValue", extn_value)
        return decoded.human_readable_lines(wrap=wrap, label=label)

    def get_decoded_value(self):
        """Decode the "extnValue" according to the decoded "extnID" component.

        Returns:
            an ASN1 object whose type is specified by "extnID".
        Raises:
            UnknownASN1TypeError: "extnID" does not have a known value type.
            ASN1Error: object is not a proper ASN.1 value object, or "extnValue"
                is not a valid encoding of the anticipated type.
        """
        extn_type = self.getComponentByName("extnID")
        extn_value = self.getComponentByName("extnValue")
        if extn_type is None or extn_value is None:
            raise error.ASN1Error("Attempting to decode an incomplete object %s"
                                  % self.human_readable())

        # An extension is a DER-encoded ASN.1 object wrapped in an OctetString
        # (rather than a raw ASN.1 object).
        decodable_value = oid.DecodableAny(extn_value)
        return decodable_value.get_decoded_value(extn_type, der_decoder.decode)

# In ASN.1, MAX indicates no upper bound, but pyasn1 doesn"t have one-sided
# range constraints, so just make it something really big.
_MAX = 1 << 64


class Extensions(types.SequenceOf):
    componentType = Extension()
    sizeSpec = (types.SequenceOf.sizeSpec +
                constraint.ValueSizeConstraint(1, _MAX))


class BasicConstraints(types.Sequence):
    PRINT_DELIMITER = ", "
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType("cA", types.Boolean("False")),
        namedtype.OptionalNamedType(
            "pathLenConstraint", types.Integer().subtype(
                subtypeSpec=constraint.ValueRangeConstraint(0, _MAX)))
        )

ID_CE_BASIC_CONSTRAINTS = ExtensionID(oid.ID_CE_BASIC_CONSTRAINTS)

_EXTENSION_VALUE_TYPE_DICT = {
    ID_CE_BASIC_CONSTRAINTS: BasicConstraints,
}
