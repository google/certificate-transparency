package org.certificatetransparency.ctlog;

import org.certificatetransparency.ctlog.PrecertChainEntry;
import org.certificatetransparency.ctlog.proto.Ct;


public class LogEntry {
  public Ct.X509ChainEntry x509Entry;
  public PrecertChainEntry precertEntry;
}
