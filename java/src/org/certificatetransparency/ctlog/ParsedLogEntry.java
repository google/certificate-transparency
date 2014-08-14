package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.proto.Ct;

/**
 * ParsedLogEntry data type contains an entry retrieved from Log.
 */
public class ParsedLogEntry {
  private final Ct.LogEntry logEntry;
  private final Ct.MerkleTreeLeaf merkleTreeLeaf;

  public ParsedLogEntry(Ct.MerkleTreeLeaf merkleTreeLeaf, Ct.LogEntry logEntry) {
    this.merkleTreeLeaf = merkleTreeLeaf;
    this.logEntry = logEntry;
  }

  public Ct.MerkleTreeLeaf getMerkleTreeLeaf() {
    return merkleTreeLeaf;
  }

  public Ct.LogEntry getLogEntry() {
    return logEntry;
  }
}
