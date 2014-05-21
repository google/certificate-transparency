package org.certificatetransparency.ctlog.comm;

import static org.certificatetransparency.ctlog.internal.Types.Length.CERTIFICATE;
import static org.certificatetransparency.ctlog.internal.Types.Length.CERTIFICATE_CHAIN;
import static org.certificatetransparency.ctlog.internal.Types.Length.EXTENSIONS;
import static org.certificatetransparency.ctlog.internal.Types.Length.KEY_ID;
import static org.certificatetransparency.ctlog.internal.Types.Length.LOG_ENTRY_TYPE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.certificatetransparency.ctlog.CertificateData;
import org.certificatetransparency.ctlog.CertificateDataSet;
import org.certificatetransparency.ctlog.CertificateInfo;
import org.certificatetransparency.ctlog.CertificateTransparencyException;
import org.certificatetransparency.ctlog.internal.Types.LogEntryType;
import org.certificatetransparency.ctlog.internal.Types.MerkleLeafType;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.proto.Ct.LogEntry;
import org.certificatetransparency.ctlog.serialization.Deserializer;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableList.Builder;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.common.primitives.Shorts;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedInputStream;

/**
 * A CT HTTP client. Abstracts away the json encoding necessary for the server.
 */
public class HttpLogClient {
  private static final Log LOG = LogFactory.getLog("CTLog");
  private static final int PAGE_SIZE = 1000;
  private final String logUrl;
  private final HttpInvoker postInvoker;

  /**
   * New HttpLogClient.
   *
   * @param logUrl CT Log's full URL, e.g. "http://ct.googleapis.com/pilot/ct/v1/"
   */
  public HttpLogClient(String logUrl) {
    this(logUrl, new HttpInvoker());
  }

  /**
   * For testing specify an HttpPostInvoker
   *
   * @param logUrl URL of the log.
   * @param postInvoker HttpPostInvoker instance to use.
   */
  public HttpLogClient(String logUrl, HttpInvoker postInvoker) {
    this.logUrl = logUrl;
    this.postInvoker = postInvoker;
  }

  /**
   * JSON-encodes the list of certificates into a JSON object.
   *
   * @param certs Certificates to encode.
   * @return A JSON object with one field, "chain", holding a JSON array of base64-encoded certs.
   */
  @SuppressWarnings("unchecked")
  // Because JSONObject, JSONArray extend raw types.
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
    Ct.SignedCertificateTimestamp.Builder builder = Ct.SignedCertificateTimestamp.newBuilder();

    int numericVersion = ((Number) parsedResponse.get("sct_version")).intValue();
    Ct.Version version = Ct.Version.valueOf(numericVersion);
    if (version == null) {
      throw new IllegalArgumentException(String.format("Input JSON has an invalid version: %d",
          numericVersion));
    }
    builder.setVersion(version);
    Ct.LogID.Builder logIdBuilder = Ct.LogID.newBuilder();
    logIdBuilder
        .setKeyId(ByteString.copyFrom(Base64.decodeBase64((String) parsedResponse.get("id"))));
    builder.setId(logIdBuilder.build());
    builder.setTimestamp(((Number) parsedResponse.get("timestamp")).longValue());
    String extensions = (String) parsedResponse.get("extensions");
    if (!extensions.isEmpty()) {
      builder.setExtensions(ByteString.copyFrom(Base64.decodeBase64(extensions)));
    }

    String base64Signature = (String) parsedResponse.get("signature");
    builder.setSignature(Deserializer.parseDigitallySignedFromBinary(new ByteArrayInputStream(
        Base64.decodeBase64(base64Signature))));
    return builder.build();
  }

  /**
   * Adds a certificate to the log.
   *
   * @param certificatesChain The certificate chain to add.
   * @return SignedCertificateTimestamp if the log added the chain successfully.
   */
  public Ct.SignedCertificateTimestamp addCertificate(List<Certificate> certificatesChain) {
    Preconditions.checkArgument(!certificatesChain.isEmpty(),
        "Must have at least one certificate to submit.");

    boolean isPreCertificate = CertificateInfo.isPreCertificate(certificatesChain.get(0));
    if (isPreCertificate && CertificateInfo.isPreCertificateSigningCert(certificatesChain.get(1))) {
      Preconditions.checkArgument(certificatesChain.size() >= 3,
          "When signing a PreCertificate with a PreCertificate Signing Cert,"
              + " the issuer certificate must follow.");
    }

    return addCertificate(certificatesChain, isPreCertificate);
  }

  private Ct.SignedCertificateTimestamp addCertificate(List<Certificate> certificatesChain,
      boolean isPreCertificate) {
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
   * @return the size of the tree (total number of entries).
   */
  public int getTreeSize() {
    return Integer.parseInt(String.valueOf(getJSONData(logUrl + "get-sth",
        ImmutableList.<NameValuePair>of()).get("tree_size")));
  }

  private final ExecutorService threadPool = Executors.newFixedThreadPool(30);

  /**
   * @return all {@link LogEntry} entities between the start and end indexes.
   */
  public CertificateDataSet getLogEntries(int start, int end) throws InterruptedException,
      ExecutionException {
    Preconditions.checkArgument(start < end,
        "Strating index %d should be smaller than the end index %d.", start, end);
    Preconditions.checkArgument(start >= 0, "Starting index %d should be greater than 0.", start);

    CertificateDataSet cds = new CertificateDataSet();
    List<Future<Integer>> futures = Lists.newArrayList();
    for (int current = start; current <= end; current += PAGE_SIZE) {
      int currentStart = current;
      int currentEnd = Math.min(end, current + PAGE_SIZE - 1);

      futures.add(threadPool.submit(
          () -> {
            LOG.info(String.format("Retrieving from %d to %d.", currentStart, currentEnd));
            cds.addAll(processEntries((JSONArray) getJSONData(
                logUrl + "get-entries",
                ImmutableList.<NameValuePair>of(getNVP("start", currentStart),
                    getNVP("end", currentEnd))).get("entries")));
          }, 1));
    }

    futures.forEach(f -> {
      try {
        f.get();
      } catch (Exception e) {
        LOG.warn(e);
      }
    });

    return cds;
  }

  private JSONObject getJSONData(String url, ImmutableList<NameValuePair> params) {
    String response = postInvoker.getData(url, params);
    try {
      Object obj = new JSONParser().parse(response);
      if (obj instanceof JSONObject)
        return (JSONObject) obj;
    } catch (ParseException e) {
      throw new LogCommunicationException("Cannot parse returned data.", e);
    }

    throw new LogCommunicationException("No usable data received from log. Data received: " + response);
  }

  private Collection<CertificateData> processEntries(JSONArray entries) {
    Builder<CertificateData> list = ImmutableList.builder();
    try {
      int size = entries.size();
      for (int index = 0; index < size; index++) {
        JSONObject object = (JSONObject) entries.get(index);
        list.add(getData(Base64.decodeBase64(String.valueOf(object.get("leaf_input"))),
            Base64.decodeBase64(String.valueOf(object.get("extra_data")))));
      }
    } catch (IOException e) {
      e.printStackTrace();
    } catch (CertificateParsingException e) {
      e.printStackTrace();
    }

    return list.build();
  }

  private CertificateData getData(byte[] leafInput, byte[] extraData) throws IOException,
      CertificateParsingException {
    CodedInputStream is = CodedInputStream.newInstance(leafInput);
    int logVersion = is.readRawByte();
    LOG.debug("version: " + logVersion);
    MerkleLeafType leafType = MerkleLeafType.getByIndex(is.readRawByte());
    LOG.debug("type: " + leafType);
    Date timestamp = new Date(Longs.fromByteArray(is.readRawBytes(8)));
    LOG.debug("timestamp: " + timestamp);
    LogEntryType entryType =
        LogEntryType.getByIndex(Shorts.fromByteArray(is.readRawBytes(LOG_ENTRY_TYPE
            .getPrefixLengthBytes())));

    X509CertificateObject certificate = null;
    TBSCertificate preCertificate = null;

    switch (entryType) {
      case X509_ENTRY:
        certificate =
            new X509CertificateObject(
                org.bouncycastle.asn1.x509.Certificate.getInstance(Deserializer.readVarBytesArray(is,
                    CERTIFICATE.getPrefixLengthBytes())));
        LOG.debug("cert Issuer: " + certificate.getIssuerDN());
        break;
      case PRECERT_ENTRY:
        byte[] preCert = Deserializer.readVarBytesArray(is, CERTIFICATE_CHAIN.getPrefixLengthBytes());
        if (preCert.length > 32) {
          CodedInputStream isPreCert = CodedInputStream.newInstance(preCert);
          byte[] issuerKeyHash = isPreCert.readRawBytes(KEY_ID.getMaxLength());
          LOG.debug("issuerKeyHash: " + Bytes.asList(issuerKeyHash));

          byte[] preCertBytes = isPreCert.readRawBytes(isPreCert.getBytesUntilLimit());
          while (preCertBytes.length > 0) {
            preCertificate = TBSCertificate.getInstance(preCertBytes);
            LOG.debug("preCert: " + preCertificate);
          }
        } else
          throw new LogCommunicationException("Precertification entry data is too short. Data bytes received: " + Bytes.asList(preCert));
        break;
      default:
          throw new LogCommunicationException("Unknown entry type of: " + entryType);
    }

    return CertificateData.newData(entryType, certificate, preCertificate,
        Deserializer.readVarBytesArray(is, EXTENSIONS.getPrefixLengthBytes()), getExtraCertificates(extraData));
  }

  private List<?> getExtensionsData(InputStream inputStream) throws IOException {
    Builder<Object> list = ImmutableList.builder();

    if (inputStream.available() > 0) {
      try (ASN1InputStream asn1Input = new ASN1InputStream(inputStream)) {
        int available = asn1Input.available();
        while (available > 0) {
          LOG.trace("available: " + available);
          ASN1Primitive asn1Primitive = asn1Input.readObject().toASN1Primitive();

          int tag = 0;
          if (asn1Primitive instanceof ASN1Sequence && ((ASN1Sequence) asn1Primitive).size() == 3) {
            X509CertificateObject certificate =
                new X509CertificateObject(
                    org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Primitive));
            list.add(certificate);
            LOG.debug(String.format("Extra Certificate: %s", certificate));
          } else {
            list.add(asn1Primitive);
            LOG.debug(String.format("tag: %d: %s:%s", tag,
                asn1Primitive.getClass().getSimpleName(), asn1Primitive.toString()));
          }

          available = asn1Input.available();
        }
      } catch (Exception e) {
        e.printStackTrace();
      }
    }

    return list.build();
  }

  private List<X509CertificateObject> getExtraCertificates(byte[] extraData) throws IOException {
    Builder<X509CertificateObject> list = ImmutableList.builder();
    CodedInputStream is = CodedInputStream.newInstance(extraData);

    while (!is.isAtEnd()) {
      byte[] extraData1 = Deserializer.readVarBytesArray(is, CERTIFICATE_CHAIN.getPrefixLengthBytes());
      CodedInputStream is1 = CodedInputStream.newInstance(extraData1);
      while (!is1.isAtEnd())
        list.addAll(Iterables.filter(
            getExtensionsData(new ByteArrayInputStream(Deserializer.readVarBytesArray(is1,
                CERTIFICATE_CHAIN.getPrefixLengthBytes()))), X509CertificateObject.class));
    }

    return list.build();
  }

  private BasicNameValuePair getNVP(String name, int value) {
    return new BasicNameValuePair(name, Integer.toString(value));
  }
}
