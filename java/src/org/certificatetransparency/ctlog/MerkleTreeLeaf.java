package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.TimestampedEntry;
import org.certificatetransparency.ctlog.proto.Ct;


public class MerkleTreeLeaf {
  public Ct.Version version;
  public TimestampedEntry timestampedEntry;

  public MerkleTreeLeaf(Ct.Version version, TimestampedEntry timestamped_entry) {
    this.version = version;
    this.timestampedEntry = timestamped_entry;
  }
}
