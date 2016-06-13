package org.certificatetransparency.ctlog;

import java.util.ArrayList;
import java.util.List;


public class X509ChainEntry {
  // For V1 this entry just includes the certificate in the
  // leaf_certificate field
  public byte[] leafCertificate;

  // A chain from the leaf to a trusted root (excluding leaf and
  // possibly root).
  public List<byte[]> certificateChain;

  public X509ChainEntry() {
    certificateChain = new ArrayList<byte[]>();
  }
}
