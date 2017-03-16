package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.SignedEntry;
import org.certificatetransparency.ctlog.proto.Ct;


public class TimestampedEntry {
  public long timestamp;
  public Ct.LogEntryType entryType;
  public SignedEntry signedEntry;
}
