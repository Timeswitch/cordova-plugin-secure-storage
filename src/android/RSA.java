package com.crypho.plugins;

import javax.crypto.Cipher;

public interface RSA {

	public byte[] encrypt(byte[] buf, String alias) throws Exception;

	public byte[] decrypt(byte[] encrypted, String alias) throws Exception;

	public void createKeyPair(String alias) throws Exception;

	public Cipher createCipher(int cipherMode, String alias) throws Exception;

	public boolean isEntryAvailable(String alias);
}