package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.serialization.CTConstants;
import org.certificatetransparency.ctlog.serialization.Serializer;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;


/**
 * Verifies signatures from a given CT Log.
 */
public class LogSignatureVerifier {
  private final LogInfo logInfo;

  /**
   * Creates a new LogSignatureVerifier which is associated with a single log.
   * @param logInfo information of the log this verifier is to be associated with.
   */
  public LogSignatureVerifier(LogInfo logInfo) {
    this.logInfo = logInfo;
  }

  /**
   * Verifies the CT Log's signature over the SCT and leaf certificate.
   * @param sct SignedCertificateTimestamp received from the log.
   * @param leafCert leaf certificate sent to the log.
   * @return true if the log's signature over this SCT can be verified, false otherwise.
   */
  public boolean verifySignature(Ct.SignedCertificateTimestamp sct, Certificate leafCert) {
    if (!logInfo.isSameLogId(sct.getId().getKeyId().toByteArray())) {
      throw new CertificateTransparencyException(String.format(
          "Log ID of SCT (%s) does not match this log's ID.", sct.getId().getKeyId()));
    }
    byte[] toVerify = serializeSignedSCTData(leafCert, sct);

    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");

      signature.initVerify(logInfo.getKey());
      signature.update(toVerify);
      return signature.verify(sct.getSignature().getSignature().toByteArray());
    } catch (SignatureException e) {
      throw new CertificateTransparencyException("Signature object not properly initialized or"
          + " signature from SCT is improperly encoded.", e);
    } catch (InvalidKeyException e) {
      throw new CertificateTransparencyException("Log's public key cannot be used", e);
    } catch (NoSuchAlgorithmException e) {
      throw new UnsupportedCryptoPrimitiveException("Sha-256 with ECDSA not supported by this JVM", e);
    }
  }

  static byte[] serializeSignedSCTData(Certificate certificate,
                                       Ct.SignedCertificateTimestamp sct) {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    Serializer.writeUint(bos, sct.getVersion().getNumber(), 1); // ct::V1
    Serializer.writeUint(bos, 0, 1); // ct::CERTIFICATE_TIMESTAMP
    Serializer.writeUint(bos, sct.getTimestamp(), 8); // Timestamp
    Serializer.writeUint(bos, 0, 2); // ct::X509_ENTRY
    try {
      Serializer.writeVariableLength(bos, certificate.getEncoded(), (1 << 24) - 1);
    } catch (CertificateEncodingException e) {
      throw new CertificateTransparencyException("Error encoding certificate", e);
    }
    Serializer.writeVariableLength(bos, sct.getExtensions().toByteArray(),
        CTConstants.MAX_EXTENSIONS_LENGTH);

    return bos.toByteArray();
  }

}
