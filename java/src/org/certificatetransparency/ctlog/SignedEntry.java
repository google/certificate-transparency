package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.proto.Ct;


public class SignedEntry {
  public byte[] x509;
  public Ct.PreCert preCert;
}
