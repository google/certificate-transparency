package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.proto.Ct;


public class MerkleTreeLeaf {
  public Ct.Version version;
  public Ct.MerkleLeafType type;
  public Ct.TimestampedEntry timestampedEntry;

  public MerkleTreeLeaf(Ct.Version version, Ct.MerkleLeafType type, Ct.TimestampedEntry timestamped_entry) {
    this.version = version;
    this.type = type;
    this.timestampedEntry = timestamped_entry;
  }
}
