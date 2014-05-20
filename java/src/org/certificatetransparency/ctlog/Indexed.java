package org.certificatetransparency.ctlog;

/**
 * Represents an indexed object
 */
public interface Indexed<T> {
	/**
	 * @return the index of the object
	 */
	int getIndex();

	/**
	 * @return the object.
	 */
	T getValue();
}
