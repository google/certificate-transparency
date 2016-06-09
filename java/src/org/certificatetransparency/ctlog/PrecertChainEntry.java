package org.certificatetransparency.ctlog;

import java.util.ArrayList;
import java.util.List;
import org.certificatetransparency.ctlog.PreCert;


public class PrecertChainEntry {
  // The chain certifying the precertificate, as submitted by the CA.
  public List<byte[]> precertificateChain;

  // PreCert input to the SCT. Can be computed from the above.
  // Store it alongside the entry data so that the signers don't have to
  // parse certificates to recompute it.
  public PreCert preCert;

  public PrecertChainEntry() {
    precertificateChain = new ArrayList<byte[]>();
  }
}
