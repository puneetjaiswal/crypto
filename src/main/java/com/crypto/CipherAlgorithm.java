package com.crypto;
import javax.crypto.SecretKey;

public interface CipherAlgorithm {

	SecretKey generateSecretKey() throws Exception;
	
	byte[] encrypt(byte[] secretKey, String strToEncrypt);
}
