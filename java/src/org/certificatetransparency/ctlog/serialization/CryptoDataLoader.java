package org.certificatetransparency.ctlog.serialization;

import com.google.common.base.Joiner;
import com.google.common.io.Files;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.certificatetransparency.ctlog.UnsupportedCryptoPrimitiveException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Class for reading various crypto structures off disk.
 */
public class CryptoDataLoader {
  /**
   * Returns a list of certificates from an input stream of PEM-encoded certs.
   * @param pemStream input stream with PEM bytes
   * @return A list of certificates in the PEM file.
   */
  static List<Certificate> parseCertificates(InputStream pemStream) {
    CertificateFactory factory;
    try {
      factory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new UnsupportedCryptoPrimitiveException("Failure getting X.509 factory", e);
    }

    try {
      Collection<? extends Certificate> certs = factory.generateCertificates(pemStream);
      Certificate[] toReturn = certs.toArray(new Certificate[]{});
      return Arrays.asList(toReturn);
    } catch (CertificateException e) {
      throw new InvalidInputException("Not a valid PEM stream", e);
    }
  }

  /**
   * Parses a PEM-encoded file containing a list of certificates.
   *
   * @param pemCertsFile File to parse.
   * @return A list of certificates from the certificates in the file.
   * @throws FileNotFoundException If the file is not present.
   */
  public static List<Certificate> certificatesFromFile(File pemCertsFile) {
    try {
      return parseCertificates(new BufferedInputStream(new FileInputStream(pemCertsFile)));
    } catch (FileNotFoundException e) {
      throw new InvalidInputException(
          String.format("Could not find certificate chain file %s.", pemCertsFile),
          e);
    }
  }

  static PublicKey parsePublicKey(List<String> pemLines) {
    //TODO(eranm): Filter out non PEM blocks.
    // Are the contents PEM-encoded?
    boolean correctHeader = pemLines.get(0).equals("-----BEGIN PUBLIC KEY-----");
    boolean correctFooter = pemLines.get(pemLines.size() - 1)
        .equals("-----END PUBLIC KEY-----");
    if (!correctHeader || !correctFooter) {
      throw new IllegalArgumentException(
          String.format("Input is not a PEM-encoded key file: " + pemLines));
    }

    // The contents are PEM encoded - first and last lines are header and footer.
    String b64string = Joiner.on("").join(pemLines.subList(1, pemLines.size() - 1));
    // Extract public key
    byte[] keyBytes = Base64.decodeBase64(b64string);
    String keyAlg = determineKeyAlg(keyBytes);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory kf;
    try {
      // Note: EC KeyFactory does not exist in openjdk, only Oracle's JDK.
      kf = KeyFactory.getInstance(keyAlg);
      return kf.generatePublic(spec);
    } catch (NoSuchAlgorithmException e) {
      // EC is known to be missing from openjdk; Oracle's JDK must be used.
      throw new UnsupportedCryptoPrimitiveException(keyAlg + " support missing", e);
    } catch (InvalidKeySpecException e) {
      throw new InvalidInputException("Log public key is invalid", e);
    }
  }
  
  /** Parses the beginning of a key, and determines the key algorithm (RSA or EC) based on the OID */
  private static String determineKeyAlg(byte[] keyBytes) {
      ASN1Sequence seq = ASN1Sequence.getInstance(keyBytes);
      DLSequence seq1 = (DLSequence) seq.getObjects().nextElement();
      ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) seq1.getObjects().nextElement();
      if (PKCSObjectIdentifiers.rsaEncryption.equals(oid)) {
          return "RSA";
      } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid)) {
          return "EC";
      } else {
          throw new IllegalArgumentException("Unsupported key type: " + oid);
      }
  }

  /**
   * Load EC or RSA public key from a PEM file.
   * @param pemFile File containing the key.
   * @return Public key represented by this file.
   */
  public static PublicKey keyFromFile(File pemFile) {
    try {
      return parsePublicKey(Files.readLines(pemFile, Charset.defaultCharset()));
    } catch (IOException e) {
      throw new InvalidInputException(
          String.format("Error reading input file %s", pemFile), e);
    }
  }
}
