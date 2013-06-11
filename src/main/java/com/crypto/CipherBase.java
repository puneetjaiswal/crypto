package com.crypto;

import java.nio.charset.Charset;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public abstract class CipherBase implements CipherAlgorithm {

	protected abstract String getTransformation();
	
	protected abstract String getAlgorithmId();
	
	public abstract int getKeySize();
	
	@Override
	public byte[] encrypt(byte[] secretKey, String strToEncrypt)
	{
		try{
			SecretKeySpec keySpec=new SecretKeySpec(secretKey, getAlgorithmId());
			Cipher cipher=Cipher.getInstance(getTransformation());
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			return cipher.doFinal(strToEncrypt.getBytes(Charset.forName("UTF-8")));
		}
		catch(Exception ex)
		{
			throw new RuntimeException(ex.getMessage());
		}
	}
	
	/**
	 * 
	 * @param secretKey
	 * @param strToDecrypt
	 * @return
	 */
	public byte[] decrypt(byte[] secretKey, String strToDecrypt)
    {
        return decrypt(secretKey, strToDecrypt.getBytes(Charset.forName("UTF-8")));
    }
	
	/**
	 * 
	 * @param secretKey
	 * @param bytesToDecrypt
	 * @return
	 */
	public byte[] decrypt(byte[] secretKey, byte [] bytesToDecrypt)
    {
        try{
            SecretKeySpec keySpec=new SecretKeySpec(secretKey, getAlgorithmId());
            Cipher cipher=Cipher.getInstance(getTransformation());
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            return cipher.doFinal(bytesToDecrypt);
        }
        catch(Exception ex)
        {
            throw new RuntimeException(ex.getMessage());
        }
    }
}
