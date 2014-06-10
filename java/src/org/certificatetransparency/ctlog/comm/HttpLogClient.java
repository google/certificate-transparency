package org.certificatetransparency.ctlog.comm;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.certificatetransparency.ctlog.CertificateInfo;
import org.certificatetransparency.ctlog.CertificateTransparencyException;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.serialization.Deserializer;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import com.google.common.base.Preconditions;
import com.google.protobuf.ByteString;


/**
 * A CT HTTP client. Abstracts away the json encoding necessary for the server.
 */
public class HttpLogClient {
  private static final String ADD_PRE_CHAIN_PATH = "add-pre-chain";
  private static final String ADD_CHAIN_PATH = "add-chain";
  private static final String GET_STH_PATH = "get-sth";
  private static final String GET_ROOTS_PATH = "get-roots";
  private static final String GET_ENTRIES_PATH = "get-entries";
  private static final String GET_STH_CONSISTENCY_PATH = "get-sth-consistency";
  private static final String GET_PROOF_BY_HASH_PATH = "get-proof-by-hash";
  private static final String GET_ENTRY_AND_PROOF_PATH = "get-entry-and-proof";
  
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
    Preconditions.checkArgument(!certificatesChain.isEmpty(),
        "Must have at least one certificate to submit.");

    boolean isPreCertificate = CertificateInfo.isPreCertificate(certificatesChain.get(0));
    if (isPreCertificate &&
        CertificateInfo.isPreCertificateSigningCert(certificatesChain.get(1))) {
      Preconditions.checkArgument(
          certificatesChain.size() >= 3,
          "When signing a PreCertificate with a PreCertificate Signing Cert," +
              " the issuer certificate must follow.");
    }

    return addCertificate(certificatesChain, isPreCertificate);
  }

  private Ct.SignedCertificateTimestamp addCertificate(
      List<Certificate> certificatesChain, boolean isPreCertificate) {
    String jsonPayload = encodeCertificates(certificatesChain).toJSONString();
    String methodPath;
    if (isPreCertificate) {
      methodPath = "add-pre-chain";
    } else {
      methodPath = "add-chain";
    }

    String response = postInvoker.makePostRequest(logUrl + methodPath, jsonPayload);
    return parseServerResponse(response);
  }
  
  /**
   * Retrieves Latest Signed Tree Head from the log.
   * @return latest STH
   */
  public Ct.SignedTreeHead getSTH() {
    String response = postInvoker.makeGetRequest(logUrl + GET_STH_PATH, null);
    return parseSTHResponse(response);
  }
  
  /**
   * Parses CT log's response for "get-sth" into a proto object.
   * @param sthResponse
   * @return a proto object of SignedTreeHead type.
   */
  private Ct.SignedTreeHead parseSTHResponse(String sthResponse) {
    if (sthResponse == null) {
      return null;
    }

    JSONObject response = (JSONObject) JSONValue.parse(sthResponse);
    long treeSize = (Long) response.get("tree_size");
    long timeStamp = (Long) response.get("timestamp");
    String base64Signature = (String) response.get("tree_head_signature");
    String sha256RootHash = (String) response.get("sha256_root_hash");

    Ct.SignedTreeHead.Builder builder =  Ct.SignedTreeHead.newBuilder();
    builder.setVersion(Ct.Version.V1);
    builder.setTreeSize(treeSize);
    builder.setTimestamp(timeStamp);
    builder.setSha256RootHash(ByteString.copyFrom(Base64.decodeBase64(sha256RootHash)));
    builder.setSignature(Deserializer.parseDigitallySignedFromBinary(
      new ByteArrayInputStream(Base64.decodeBase64(base64Signature))));

    return builder.build();
  }

  /**
   * Retrieves accepted Root Certificates.
   *
   * @return a list of root certificates.
   * @throws CertificateException
   */
  public List<Certificate> getLogRoots() throws CertificateException {
    String response = postInvoker.makeGetRequest(logUrl + GET_ROOTS_PATH, null);

    return parseRootCertsResponse(response);
  }

  /**
   * Parses the response from "get-roots" GET method.
   *
   * @param rootCerts JSONObject with certificates to parse.
   * @return a list of root certificates. 
   * @throws CertificateException
   */
  private List<Certificate> parseRootCertsResponse(String response) throws CertificateException {
    List<Certificate> certs = new ArrayList<Certificate>();
    
    JSONObject entries = (JSONObject) JSONValue.parse(response);
    JSONArray entriesArr = (JSONArray) entries.get("certificates");
    Iterator<?> iter = entriesArr.iterator();
    while (iter.hasNext()) {
      byte[] in = Base64.decodeBase64(iter.next().toString());
      Certificate cert = CertificateFactory.getInstance("X509").generateCertificate(
        new ByteArrayInputStream(in));
      certs.add(cert);
    }
    return certs;
  }
}
