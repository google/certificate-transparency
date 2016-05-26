package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.proto.Ct;


public class SignedTreeHead {
  public Ct.Version version;
  public long timestamp;
  public long treeSize;
  public byte[] sha256RootHash;
  public Ct.DigitallySigned signature;

  public SignedTreeHead(Ct.Version version) {
    this.version = version;
  }
}
