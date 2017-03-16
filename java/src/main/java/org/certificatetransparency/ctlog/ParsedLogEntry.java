package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.LogEntry;
import org.certificatetransparency.ctlog.MerkleTreeLeaf;

/**
 * ParsedLogEntry data type contains an entry retrieved from Log.
 */
public class ParsedLogEntry {
  private final LogEntry logEntry;
  private final MerkleTreeLeaf merkleTreeLeaf;

  private ParsedLogEntry(MerkleTreeLeaf merkleTreeLeaf, LogEntry logEntry) {
    this.merkleTreeLeaf = merkleTreeLeaf;
    this.logEntry = logEntry;
  }

  public static ParsedLogEntry newInstance(MerkleTreeLeaf merkleTreeLeaf, LogEntry logEntry) {
    return new ParsedLogEntry(merkleTreeLeaf, logEntry);
  }

  public MerkleTreeLeaf getMerkleTreeLeaf() {
    return merkleTreeLeaf;
  }

  public LogEntry getLogEntry() {
    return logEntry;
  }
}
