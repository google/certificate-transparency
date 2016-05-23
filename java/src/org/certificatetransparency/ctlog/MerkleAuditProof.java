package org.certificatetransparency.ctlog;

import java.util.ArrayList;
import java.util.List;
import org.certificatetransparency.ctlog.proto.Ct;


public class MerkleAuditProof {
  public Ct.Version version;
  public long treeSize;
  public long leafIndex;
  public List<byte[]> pathNode;

  public MerkleAuditProof(Ct.Version version, long treeSize, long leafIndex) {
    this.version = version;
    this.treeSize = treeSize;
    this.leafIndex = leafIndex;
    pathNode = new ArrayList<byte[]>();
  }
}
