package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.MerkleTreeLeaf;

/**
 * ParsedLogEntry data type contains an entry retrieved from Log.
 */
public class ParsedLogEntry {
  private final Ct.LogEntry logEntry;
  private final MerkleTreeLeaf merkleTreeLeaf;

  private ParsedLogEntry(MerkleTreeLeaf merkleTreeLeaf, Ct.LogEntry logEntry) {
    this.merkleTreeLeaf = merkleTreeLeaf;
    this.logEntry = logEntry;
  }

  public static ParsedLogEntry newInstance(MerkleTreeLeaf merkleTreeLeaf, Ct.LogEntry logEntry) {
    return new ParsedLogEntry(merkleTreeLeaf, logEntry);
  }

  public MerkleTreeLeaf getMerkleTreeLeaf() {
    return merkleTreeLeaf;
  }

  public Ct.LogEntry getLogEntry() {
    return logEntry;
  }
}
