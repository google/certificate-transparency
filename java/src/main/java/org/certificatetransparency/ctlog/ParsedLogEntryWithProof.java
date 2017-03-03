package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.MerkleAuditProof;

/**
 * ParsedLogEntry data type contains an entry retrieved from Log with it's audit proof.
 */
public class ParsedLogEntryWithProof  {
  private final ParsedLogEntry parsedLogEntry;
  private final MerkleAuditProof auditProof;

  private ParsedLogEntryWithProof(ParsedLogEntry parsedLogEntry, MerkleAuditProof auditProof) {
    this.parsedLogEntry = parsedLogEntry;
    this.auditProof = auditProof;
  }

  public static ParsedLogEntryWithProof newInstance(ParsedLogEntry logEntry,
    MerkleAuditProof proof) {
    return new ParsedLogEntryWithProof(logEntry, proof);
  }

  public ParsedLogEntry getParsedLogEntry() {
    return parsedLogEntry;
  }

  public MerkleAuditProof getAuditProof() {
    return auditProof;
  }
}
