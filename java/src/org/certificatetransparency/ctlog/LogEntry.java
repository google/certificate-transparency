package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.proto.Ct;


public class LogEntry {
  public Ct.X509ChainEntry x509Entry;
  public Ct.PrecertChainEntry precertEntry;
}
