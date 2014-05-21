package org.certificatetransparency.ctlog.internal;

import java.util.Arrays;
import java.util.Map;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;

/**
 * Entry and log types and related constants.
 */
public class Types {
	/**
	 * Define max length and length encoding for the types of objects retrieved.
	 */
	public enum Length {
		CERTIFICATE(1 << 24 -1),

		CERTIFICATE_CHAIN(1 << 24 -1),

		SIGNATURE(1 << 16 - 1),

		EXTENSIONS(1 << 16 - 1),

		SERIALIZED_SCT(1 << 16 - 1),

		SCT_LIST(1 << 16 - 1),

		LOG_ENTRY_TYPE(2, 2),

		SIGNATURE_TYPE(1, 1),

		HASH_ALGORITHM(1, 1),

		SIG_ALGORITHM(1, 1),

		VERSION(1, 1),

		KEY_ID(32, 32),

		MERKLE_LEAF_TYPE(1, 1),

		TIMESTAMP(8, 8),
		;

		private final int maxLength;
		private final int prefixLengthBytes;

		Length(int length) {
			this(length, (int) Math.ceil(log2(length) / 8.0));
		}

		Length(int maxLength, int prefixLengthBytes) {
			this.maxLength = maxLength;
			this.prefixLengthBytes = prefixLengthBytes;
		}

		private static double log2(int val) {
			return Math.log(val)/Math.log(2);
		}

		/**
		 * @return the maximum lenght of the entry.
		 */
		public int getMaxLength() {
			return maxLength;
		}

		/**
		 * @return the number of bytes that encode the length of the entry.
		 */
		public int getPrefixLengthBytes() {
			return prefixLengthBytes;
		}
	}

	public enum MerkleLeafType implements Indexed<Integer> {
		/** The only known type of entries */
		TIMESTAMPED_ENTRY(0, 0),
		;

		private static MerkleLeafType[] values = values();

		/**
		 * @return the element by its index.
		 */
		public static MerkleLeafType getByIndex(int index) {
			Preconditions.checkPositionIndex(index, values.length, "Invalid index.");

			return values[index];
		}

		/**
		 * @return the element by its value.
		 */
		public static MerkleLeafType getByValue(int value) {
			Preconditions.checkArgument(value == 0, "Only element with value 0 is known.");
			return TIMESTAMPED_ENTRY;
		}

		private final int index;
		private final int value;

		MerkleLeafType(int index, int value) {
			this.index = index;
			this.value = value;
		}

		@Override
		public int getIndex() {
			return index;
		}

		@Override
		public Integer getValue() {
			return value;
		}
	}

	/**
	 * Types of log entries
	 */
	public enum LogEntryType implements Indexed<Integer> {
		/** X509_ENTRY = 0 */
		X509_ENTRY(0, 0),

		/** PRECERT_ENTRY = 1 */
		PRECERT_ENTRY(1, 1),

		/**
		 * UNKNOWN_ENTRY_TYPE = 65536
		 */
		UNKNOWN_ENTRY_TYPE(2, 65536),
		;

		private static LogEntryType[] values = values();

		/**
		 * @return the element by its index.
		 */
		public static LogEntryType getByIndex(int index) {
			Preconditions.checkPositionIndex(index, values.length, "Invalid index.");

			return values[index];
		}

		private static Map<Integer, LogEntryType> valuesToEntries = createValuesToEntriesMap();

		/**
		 * @return the element by its value.
		 */
		public static LogEntryType getByValue(int value) {
			return valuesToEntries.get(values);
		}

		private static Map<Integer, LogEntryType> createValuesToEntriesMap() {
			ImmutableMap.Builder<Integer, LogEntryType> mb = ImmutableMap.builder();

			Arrays.asList(values()).forEach(v -> { mb.put(v.getValue(), v); });

			return mb.build();
		}

		private final int index;
		private final int value;

		LogEntryType(int index, int value) {
			this.index = index;
			this.value = value;
		}

		@Override
		public int getIndex() {
			return index;
		}

		@Override
		public Integer getValue() {
			return value;
		}
	}
}
