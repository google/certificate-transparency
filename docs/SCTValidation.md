# Signed Certificate Timestamp (SCT) Validation

 - [SCT Concepts](#sct-concepts)
 - [SCT Contents](#sct-contents)
 - [SCT Delivery Mechanism](#sct-delivery-mechanism)
 - [Precertificates](#precertificates)
   - [Pre-Issued Precertificates](#pre-issued-precertificates)
 - [SCT Validation Steps](#sct-validation-steps)
   - [Embedded SCTs](#embedded-scts)
   - [Inclusion Checking](#inclusion-checking)

## SCT Concepts

Certificate Transparency (CT) involves recording X.509 certificates in a CT Log.
Because the Log might not be able to incorporate a certificate into its data
store right away, it returns a **Signed Certificate Timestamp** (SCT), which is
a promise to incorporate that certificate soon.

That description included a couple of
[weasel words](https://en.wikipedia.org/wiki/Weasel_word):

 - "**Soon**": A CT Log publishes its *maximum merge delay* (often 24 hours),
   which says how soon.  If a Log hasn't incorporated a certificate within that
   period, it is misbehaving and may be punished.  A "signed certificate
   timestamp" includes a "timestamp" to allow this to be checked.
 - "**Promise**": A CT Log includes a cryptographic signature in the contents of
   the SCT; this means that the Log cannot later claim that it never saw the
   original certificate.  This is the origin of the "signed" part of "signed
   certificate timestamp".


## SCT Contents

As described above, a signed certificate timestamp includes some key components:
 - "**signed**": a cryptographic signature over the data, which proves that the
   Log definitely saw the submitted certificate.
 - "**certificate**": some way of confirming that the SCT applies to a
   particular X.509 certificate.
 - "**timestamp**": something that gives a limit on when the certificate must be
   visible in the Log.

The precise contents of the SCT are defined by
[RFC 6962](https://tools.ietf.org/html/rfc6962#section-3.2) (and shown in
[this diagram](images/RFC6962Structures.png)), but there are a couple of
features that are worth pointing out.

First, the SCT includes a signature *over* the timestamp and certificate details
(among other things), but doesn't include the certificate data.  This means that
you can't verify the SCT on its own &ndash; you also need to have the
certificate that it corresponds to.

Secondly, the SCT structure has two variants: one for certificates, and one for
*precertificates*.  That's the subject of a [later section](#precertificates),
once we've touched on how SCTs get to users.


## SCT Delivery Mechanisms

We've seen that an SCT is a promise that a certificate has been logged, so it
also shows that the certificate issuance was public.  If an HTTPS client gets a
certificate that has one or more SCTs associated with it, that's a pretty good
sign that the certificate was publicly issued &ndash; but only if the
client:
 * gets the SCTs
 * validates the SCTs.

(Of course, *publicly issued* isn't necessarily the same as *legitimately
issued*, but that's a
[different topic](https://tools.ietf.org/html/rfc6962#section-5.3).)

[RFC 6962](https://tools.ietf.org/html/rfc6962#section-3.3) describes three ways
for SCTs to make their way to users:
 - The TLS server can include the SCT(s) as an extension in the TLS handshake.
 - The TLS server can include the SCT(s) as an extension in a
   [stapled OCSP response](https://tools.ietf.org/html/rfc6066).
 - The X.509 certificate itself can include the SCT(s) as a certificate
   extension.

The last of these obviously poses a
[chicken-and-egg problem](https://en.wikipedia.org/wiki/Chicken_or_the_egg): if
the SCT includes a signature over the certificate, and the certificate includes
the SCT, which came first?

The answer to this question involves *precertificates*, discussed next.

## Precertificates

If a Certificate Authority (CA) wants to embed SCTs within the certificates it
issues (which provides a simple delivery mechanism for those SCTs), it needs to
get an SCT which covers a precursor version of the certificate, known as a
**precertificate**.

This is conceptually just the final certificate without the embedded SCT list,
but there's a technical difficulty: CAs are supposed to ensure that valid
certificates have a serial number that is unique for a given issuing key.  If a
CA signed the same certificate both with and without the embedded SCT
list, some felt that this might be in violation of this rule &ndash; there would
be two different valid certificates that shared the same issuer and serial number.

Precertificates take advantage of the weasel word "valid" in the previous
description: the precertificate version of the certificate (which the CA signs
and the Log registers) includes an X.509 extension that is marked as critical,
but which is deliberately non-standard &ndash; the so-called *poison extension*.
According to the rules of
[RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.2), a
"certificate-using system MUST reject the certificate if it encounters a
critical extension it does not recognize" &ndash; so the precertificate is not a
*valid* X.509 certificate.

Unfortunately, that's got some knock-on effects on how SCTs for precertificates
work, which makes life complicated.

First, the "certificate" part of "signed certificate timestamp" can no longer be
over the whole certificate, because what the "certificate" is keeps changing:
 - On submission, the "certificate" is a whole X.509 certificate that includes
   the poison extension, and has a signature from the cert issuer over the whole
   cert (including the poison).
 - On embedded SCT validation, the "certificate" is a whole X.509 certificate
   that includes the SCT list extension, and has a signature from the cert
   issuer over the whole cert (including the SCT list).

To allow these "certificates" to be compared, the SCT signature for a
precertificate is defined to only cover the inner part of the X.509 certificate,
without the issuer's signature; this is known as the `tbsCertificate`, where
`tbs` stands for "to-be-signed".  This makes the two versions comparable: in
either case, dropping the certificate signature and any embedded CT-related
extension (poison or SCT list) should give the same bytes.

<a name="cert-order"></a>
**Note**: this has an important corollary: to make sure this is true, any code
that manipulates [pre]certificates has to make sure that *nothing else* changes
in the certificate.  In particular:
 - the [extensions](https://tools.ietf.org/html/rfc5280#section-4.2) have to
   stay in the same order
 - extension contents have to stay in the same order (e.g. for the
   [SAN](https://tools.ietf.org/html/rfc5280#section-4.2.1.6))
 - all ASN.1 types have to stay the same (e.g. no switching from `UTF8String`
   to `PrintableString`).

That leaves one more complication: if the SCT only covers the `tbsCertificate`,
what guarantee do we have that the issuer of the final certificate matches the
one that logged the precertificate?  To cover this concern, the SCT for a
precertificate also signs over the hash of the issuer's public key.

So to sum up precertificates:
 - The CA builds and signs a version of the certificate that includes the
   poison extension, and submits this to the log.
 - The Log removes the poison and extracts the inner `tbsCertificate`. This is
   combined with the hash of the issuer's key, to form the core `PreCert` data
   that the Log deals with.
 - The Log sends an SCT back to the CA, which includes a timestamp as usual but
   has a signature over data including the `PreCert` bundle of `tbsCertificate`
   and issuer key hash.
 - The CA builds an SCT list extension that includes this SCT, attaches it to
   the original (un-poisoned) certificate, and signs the whole thing.


### Pre-Issued Precertificates

But wait, it (optionally) gets more complicated!

(Feel free to skip this section &ndash; in practice, this mechanism is rarely
used in the wild, i.e. other than by explicit CT testing/monitoring systems.)

To allow for the possibility that the "valid" certificate loophole might not be
enough, RFC 6962 also allows an extra level of indirection: the pre-certificate
can be signed by a different key than the key that the final certificate will be
signed by.  This means that the "true issuer" key only ever signs one version of
the leaf certificate: the final certificate with embedded SCT list.

The extra level of indirection comes in the form of a "pre-issuer": the key used
to sign (just) the precertificate is embedded in a CA cert of its own, and this
pre-issuer cert is signed by the true issuer.  To make it clear that this is a
special case, this pre-issuer cert needs to have the Certificate Transparency
extended key usage (EKU).

However, this involves yet more modifications to the submitted precertificate:
as it is now issued by a different intermediate, those parts of the certificate
that refer to the issuer have to be updated to match:
 - The Issuer field needs to be updated to match the pre-issuer Subject name.
 - The Authority Key Identifier extension (if present) needs to be updated to
   identify the pre-issuer's key.

These modifications won't be present in the final version of the certificate
that the true issuer signs, so the Log has to reverse these modifications before
storing and signing over the precertificate.

The extra pre-issuer certificate also makes the Log's job more complicated when
verifying the submitted certificate chain.  The chain of signatures has to be
verified using the full chain, including the pre-issuer, but other validity
checks need to be done as if the pre-issuer were not present.  For example:
 - The pre-issuer has the CT EKU, but the leaf cert does not, so any check that
   the leaf's EKUs are a subset of its issuer's EKUs will incorrectly fail.
 - Any path length constraint (in a
   [Basic Constraints](https://tools.ietf.org/html/rfc5280#section-4.2.1.9)
   extension) for a CA certificate in the chain may be off by one (and so
   theoretically not allow the pre-issuer to be a CA certificate).

So to sum up *pre-issued* precertificates:
 - The CA:
     - builds a precertificate version of the certificate that includes the
       poison
     - modifies the Issuer and (optional) Authority Key Identifier extension in
       the precertificate to match the pre-issuer rather than the true issuer.
     - signs the resulting precertificate using the pre-issuer's key
     - submits the whole chain (precert, pre-issuer, true-issuer, ... root) to
       the Log.
 - The Log:
     - adjusts its validation of the submitted chain to allow for the extra
       ephemeral pre-issuer certificate (e.g. for EKU and path length checking)
     - removes the poison and extracts the inner `tbsCertificate`
     - notices that the direct issuer has the Certificate Transparency extended
       key usage, so treats the next entry in the chain as the true issuer
     - updates the certificate's Issuer and (optional) Authority Key Identifier
       extension to match the true issuer rather than the pre-issuer
     - combines the resulting inner `tbsCertificate` with the hash of the (true)
       issuer's key, to form the core `PreCert` data that the Log deals with
     - sends an SCT back to the CA, which includes a timestamp as usual but has
       a signature over data including the `PreCert` bundle of `tbsCertificate`
       and issuer key hash.
 - The CA builds an SCT list extension that includes this SCT, attaches it to
   the original (un-poisoned) certificate, and signs the whole thing with the
   true issuer's key.

This is complicated, but it's worth pointing out that only the CA and the Log
need to deal with all of this; the SCT (and the tree leaf it corresponds to)
only covers data that pertains to the final certificate.  This means that a
client who receives a certificate with an embedded SCT can just do the
[same checks](#embedded-scts) as for any other embedded SCT.


## SCT Validation Steps

There are two main aspects to validating an SCT:
 - **Signature Validation**: this requires the following (in addition to the SCT
     itself):
     - the Log's public key
     - the [pre]certificate data that the signature encompasses
     - (for a precertificate) the issuer's public key
 - **Inclusion Checking**: this requires the following (in addition to the SCT
   itself):
     - enough time to have passed (at most, the Log's MMD) for the certificate
       to be incorporated
     - the Log's URL (for accessing the `get-proof-by-hash`
       [entrypoint](https://tools.ietf.org/html/rfc6962#section-4.5))
     - the [pre]certificate data that the signature encompasses
     - (for a precertificate) the issuer's public key
     - a published tree size and root hash for the Log (via the `get-sth`
       [entrypoint](https://tools.ietf.org/html/rfc6962#section-4.1))
     - the Log's public key (to allow validation of the signed tree head (STH)
       that provided the tree size/root hash).


### Embedded SCTs

To check SCTs that are embedded in an X.509 certificate, a client needs to
rebuild the [precertificate](#precertificates) data that the SCT and the leaf
hash encompasses:

 - The SCT list extension must be removed.
 - The inner `tbsCertificate` data must be extracted, and combined with the hash
   of the issuer's public key,

### Inclusion Checking

To perform on-line inclusion checking for an SCT, the client needs to generate
the *leaf hash* for the submitted entry, to submit in the `get-proof-by-hash`
[entrypoint](https://tools.ietf.org/html/rfc6962#section-4.5).

This is the SHA-256 hash of a zero byte followed by the TLS encoding of a
`MerkleTreeLeaf` structure (shown in
[the diagram](images/RFC6962Structures.png)).  Building this structure
requires the same information as does validating the SCT signature, but
in a different order/structure.
