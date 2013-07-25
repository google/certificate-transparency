package org.certificatetransparency.ctlog.serialization;

/**
 * Constants used for serializing and de-serializing.
 */
public class CTConstants {
  // All in bytes.
  public static final int MAX_EXTENSIONS_LENGTH = (1 << 16) - 1;
  public static final int MAX_SIGNATURE_LENGTH = (1 << 16) - 1;
  public static final int KEY_ID_LENGTH = 32;
  public static final int TIMESTAMP_LENGTH = 8;
  public static final int VERSION_LENGTH = 1;
  public static final int HASH_ALG_LENGTH = 1;
  public static final int SIGNATURE_ALG_LENGTH = 1;
}
