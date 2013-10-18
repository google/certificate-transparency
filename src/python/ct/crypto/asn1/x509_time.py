"""ASN.1 UTCTime and GeneralizedTime, as understood by RFC 5280."""
import abc
import time

from ct.crypto import error
from ct.crypto.asn1 import types
from pyasn1.type import useful


class BaseTime(types.SimpleBaseType):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def gmtime(self):
        pass

    def string_value(self):
        try:
            gmt = self.gmtime()
        except error.ASN1Error:
            return self._str_or_no_value()
        else:
            return time.strftime("%c GMT", gmt)


class UTCTime(useful.UTCTime, BaseTime):
    """UTCTime, as understood by RFC 5280."""
    # YYMMDDHHMMSSZ
    _ASN1_LENGTH = 13

    # YYMMDDHHMMZ
    _UTC_NO_SECONDS_LENGTH = 11

    # YYMMDDHHMMSS+HHMM
    _UTC_TZ_OFFSET_LENGTH = 17

    # YYMMDDHHMMSS
    _UTC_NO_Z_LENGTH = 12

    def gmtime(self):
        """GMT time.

        Returns:
            a time.struct_time struct.
        Raises:
            error.ASN1Error: the ASN.1 string does not represent a valid time.
        """
        # This may return "<no value>" or similar; or (since pyasn1 time is
        # simply a string) arbitrary garbage, in which case we'll bail with
        # an ASN.1 error.
        string_time = self._str_or_no_value()

        # From RFC 5280:
        # For the purposes of this profile, UTCTime values MUST be expressed in
        # Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
        # YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
        # systems MUST interpret the year field (YY) as follows:
        #
        # Where YY is greater than or equal to 50, the year SHALL be
        # interpreted as 19YY; and
        #
        # Where YY is less than 50, the year SHALL be interpreted as 20YY.
        #
        # In addition, there are a number of older certificates
        # that exclude the seconds, e.g. 0001010000Z and others than use
        # an alternative timezone format 360526194526+0000
        if len(string_time) == self._ASN1_LENGTH and string_time[-1] == "Z":
            format = "%Y%m%d%H%M%S%Z"
        elif (len(string_time) == self._UTC_NO_SECONDS_LENGTH and
              string_time[-1] == "Z"):
            format = "%Y%m%d%H%M%Z"
        elif (len(string_time) == self._UTC_TZ_OFFSET_LENGTH and
              string_time[self._UTC_NO_Z_LENGTH] in ('+','-')):
            # note according to http://docs.python.org/2/library/time.html
            # "%z" is not supported on all platforms.
            #
            # TBD: in next patch, parse this correctly
            #
            # Given that it's very infrequent and non-standard,
            # we'll ignore time zone for now.
            #
            # convert the +HHMM to a timedelta and add to timestruct
            # One could also special case the "+0000" which should be the same
            # as GMT (without DST).
            #
            format = "%Y%m%d%H%M%S%Z"
            string_time = string_time[0:self._ASN1_LENGTH]
        else:
            raise error.ASN1Error("Invalid time representation: %s" %
                                  string_time)

        try:
            year = int(string_time[:2])
        except ValueError:
            raise error.ASN1Error("Invalid time representation: %s" %
                                  string_time)

        if 0 <= year < 50:
            century = "20"
        elif 50 <= year <= 99:
            century = "19"
        else:
            raise error.ASN1Error("Invalid time representation: %s" %
                                  string_time)

        try:
            # Adding GMT clears the daylight saving flag.
            return time.strptime(century + string_time[:-1] + "GMT", format)
        except ValueError:
            raise error.ASN1Error("Invalid time representation: %s" %
                                  string_time)


class GeneralizedTime(useful.GeneralizedTime, BaseTime):
    """Generalized time, as understood by RFC 5280."""
    # YYYYMMDDHHMMSSZ
    _ASN1_LENGTH = 15

    def gmtime(self):
        """GMT time.

        Returns:
            a time.struct_time struct.
        Raises:
            error.ASN1Error: the ASN.1 string does not represent a valid time.
        """
        # This may return "<no value>" or similar; or (since pyasn1 time is
        # simply a string) arbitrary garbage, in which case we'll bail with
        # an ASN.1 error.
        string_time = self._str_or_no_value()

        # From RFC 5280:
        # For the purposes of this profile, GeneralizedTime values MUST be
        # expressed in Greenwich Mean Time (Zulu) and MUST include seconds
        # (i.e., times are YYYYMMDDHHMMSSZ), even where the number of seconds
        # is zero.  GeneralizedTime values MUST NOT include fractional seconds.
        if len(string_time) != self._ASN1_LENGTH or string_time[-1] != "Z":
            raise error.ASN1Error("Invalid time representation: %s" %
                                  string_time)
        try:
            # Adding GMT clears the daylight saving flag.
            return time.strptime(string_time[:-1] + "GMT", "%Y%m%d%H%M%S%Z")
        except ValueError:
            raise error.ASN1Error("Invalid time representation: %s" %
                                  string_time)
