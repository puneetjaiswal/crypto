package com.crypto;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class AESCipher extends CipherBase{
	
	private static final String TRANSFORMATION_STRING="AES/ECB/PKCS5Padding";
	private static final String ALGORITHM_ID="AES";
	private static final int KEY_SIZE=128;
	
	@Override
	protected String getTransformation() {
		return TRANSFORMATION_STRING;
	}

	@Override
	protected String getAlgorithmId() {
		return ALGORITHM_ID;
	}

	@Override
	public SecretKey generateSecretKey() throws Exception {
		SecretKey secretKey=null;
		try{
			KeyGenerator keyGen=KeyGenerator.getInstance(getAlgorithmId());
			keyGen.init(KEY_SIZE);
			secretKey=keyGen.generateKey();
		}
		catch (Exception ex)
		{
			throw new Exception(ex.getMessage());
		}
		
		return secretKey;
	}

	@Override
	public int getKeySize() {
		return KEY_SIZE;
	}
}
