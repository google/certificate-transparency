package org.certificatetransparency.ctlog.comm;

import com.google.protobuf.ByteString;
import org.certificatetransparency.ctlog.CertificateTransparencyException;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.serialization.Deserializer;

import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;


/**
 * A CT HTTP client. Abstracts away the json encoding necessary for the server.
 */
public class HttpLogClient {
  private final String logUrl;
  private final HttpPostInvoker postInvoker;

  /**
   * New HttpLogClient.
   * @param logUrl CT Log's full URL, e.g. "http://ct.googleapis.com/pilot/ct/v1/"
   */
  public HttpLogClient(String logUrl) {
    this(logUrl, new HttpPostInvoker());
  }

  /**
   * For testing specify an HttpPostInvoker
   * @param logUrl URL of the log.
   * @param postInvoker HttpPostInvoker instance to use.
   */
  public HttpLogClient(String logUrl, HttpPostInvoker postInvoker) {
    this.logUrl = logUrl;
    this.postInvoker = postInvoker;
  }

  /**
   * JSON-encodes the list of certificates into a JSON object.
   * @param certs Certificates to encode.
   * @return A JSON object with one field, "chain", holding a JSON array of base64-encoded certs.
   */
  @SuppressWarnings("unchecked") // Because JSONObject, JSONArray extend raw types.
  JSONObject encodeCertificates(List<Certificate> certs) {
    JSONArray retObject = new JSONArray();

    try {
      for (Certificate cert : certs) {
        retObject.add(Base64.encodeBase64String(cert.getEncoded()));
      }
    } catch (CertificateEncodingException e) {
      throw new CertificateTransparencyException("Error encoding certificate", e);
    }

    JSONObject jsonObject = new JSONObject();
    jsonObject.put("chain", retObject);
    return jsonObject;
  }

  /**
   * Parses the CT Log's json response into a proper proto.
   *
   * @param responseBody Response string to parse.
   * @return SCT filled from the JSON input.
   */
  static Ct.SignedCertificateTimestamp parseServerResponse(String responseBody) {
    if (responseBody == null) {
      return null;
    }

    JSONObject parsedResponse = (JSONObject) JSONValue.parse(responseBody);
    Ct.SignedCertificateTimestamp.Builder builder =
        Ct.SignedCertificateTimestamp.newBuilder();

    int numericVersion = ((Number) parsedResponse.get("sct_version")).intValue();
    Ct.Version version = Ct.Version.valueOf(numericVersion);
    if (version == null) {
      throw new IllegalArgumentException(String.format("Input JSON has an invalid version: %d",
          numericVersion));
    }
    builder.setVersion(version);
    Ct.LogID.Builder logIdBuilder = Ct.LogID.newBuilder();
    logIdBuilder.setKeyId(
        ByteString.copyFrom(Base64.decodeBase64((String) parsedResponse.get("id"))));
    builder.setId(logIdBuilder.build());
    builder.setTimestamp(((Number) parsedResponse.get("timestamp")).longValue());
    String extensions = (String) parsedResponse.get("extensions");
    if (!extensions.isEmpty()) {
      builder.setExtensions(ByteString.copyFrom(Base64.decodeBase64(extensions)));
    }

    String base64Signature = (String) parsedResponse.get("signature");
    builder.setSignature(
        Deserializer.parseDigitallySignedFromBinary(
            new ByteArrayInputStream(Base64.decodeBase64(base64Signature))));
    return builder.build();
  }

  /**
   * Adds a certificate to the log.
   * @param certificatesChain The certificate chain to add.
   * @return SignedCertificateTimestamp if the log added the chain successfully.
   */
  public Ct.SignedCertificateTimestamp addCertificate(List<Certificate> certificatesChain) {
    String jsonPayload = encodeCertificates(certificatesChain).toJSONString();

    String response = postInvoker.makePostRequest(logUrl + "add-chain", jsonPayload);
    return parseServerResponse(response);
  }
}
