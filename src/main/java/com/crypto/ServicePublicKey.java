package com.crypto;


import java.nio.charset.Charset;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

/**
 * Represents public key belonging to a service account 
 *
 */
public class ServicePublicKey
{
	
	private static final String KEY_ALGO_NAME="keyAlgoName";
	private static final String KEY_ENCODING_FORMAT="keyEncodingFormat";
	private static final String ENCODED_KEY_TEXT="encoding";
	
	private String publicKeyAlgoName;
	private String publicKeyEncodingFormat;
	private byte[] publicKey;
	
	public ServicePublicKey(String encodedKey)
	{
		byte[] encodedBytes=Base64.decodeBase64(encodedKey);
		String plainTextString = StringUtils.newStringUtf8(encodedBytes);
		int keyAlgoNameIndex=plainTextString.indexOf(KEY_ALGO_NAME);
		int keyEncodingFormatIndex=plainTextString.indexOf(KEY_ENCODING_FORMAT);
		int encodedKeyTextIndex=plainTextString.indexOf(ENCODED_KEY_TEXT);
		publicKeyAlgoName=plainTextString.substring(plainTextString.indexOf('=', keyAlgoNameIndex)+1, plainTextString.indexOf('\t', keyAlgoNameIndex));
		publicKeyEncodingFormat=plainTextString.substring(plainTextString.indexOf('=', keyEncodingFormatIndex)+1, plainTextString.indexOf('\t', keyEncodingFormatIndex));
		String base64EncodedKey=plainTextString.substring(plainTextString.indexOf('=', encodedKeyTextIndex)+1, plainTextString.indexOf('\t', encodedKeyTextIndex));
		publicKey=Base64.decodeBase64(base64EncodedKey);
	}
	
	public ServicePublicKey(){}

	/**
	 * Gets encoded byte array of the public key generated by IAM service. This public key belongs to
	 * service account represented by this DTO
	 * @return
	 */
	public byte[] getEncoded() {
		return publicKey;
	}
	/**
	 * Sets public key belonging to this service account
	 * @param publicKey
	 */
	public void setEncoded(byte[] publicKey) {
		this.publicKey = publicKey;
	}
	
	
	/**
	 * Gets encoding format for the public key bytes returned by IAM service.
	 * @return
	 */
	public String getPublicKeyEncodingFormat() {
		return publicKeyEncodingFormat;
	}
	/**
	 * Sets encoding format for the public key. Client application should not set this field
	 * @param publicKeyEncodingFormat
	 */
	public void setPublicKeyEncodingFormat(String publicKeyEncodingFormat) {
		this.publicKeyEncodingFormat = publicKeyEncodingFormat;
	}
	
	/**
	 * Gets algorithm name for the generated public key
	 * @return
	 */
	public String getPublicKeyAlgoName() {
		return publicKeyAlgoName;
	}
	/**
	 * Sets algorithm name for the generated public key. Client application should not set this field
	 * @param publicKeyAlgoName
	 */
	public void setPublicKeyAlgoName(String publicKeyAlgoName) {
		this.publicKeyAlgoName = publicKeyAlgoName;
	}
	
	@Override
	public String toString()
	{
		StringBuffer stringBuffer=new StringBuffer();
		stringBuffer.append(KEY_ALGO_NAME).append("=").append(publicKeyAlgoName).append("\t");
		stringBuffer.append(KEY_ENCODING_FORMAT).append("=").append(publicKeyEncodingFormat).append("\t");
		stringBuffer.append(ENCODED_KEY_TEXT).append("=").append(Base64.encodeBase64String(publicKey)).append("\t");
		String encodedString=Base64.encodeBase64String(stringBuffer.toString().getBytes(Charset.forName("UTF-8")));
		return encodedString;
	}
	
	
}