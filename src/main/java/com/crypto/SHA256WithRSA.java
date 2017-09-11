package com.crypto;


import java.security.KeyRep;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

/**
 * Signature algorithm class representing SHA256WithRSA algorithm
 *
 */
public class SHA256WithRSA extends SignatureAlgorithmBase{

	public static final String SIGNATURE_ALGORITHM="SHA256WithRSA";

	@Override
	public String getSignatureAlgorithmId()
	{
		return SIGNATURE_ALGORITHM;
	}

	/**
	 * Generates signature string out of a map of parameters using a given private key
	 * @param parametersToSign
	 * @param privateKey
	 * @return returns signedInfo containing list of signed parameter names and signature value
	 * calculated on that list
	 */
	@Override
	public SignedInfo generateSignature(Map<String, String> parametersToSign, ServicePrivateKey privateKey)
	{
		String[] intermediateSignedInfo=canonicalize(parametersToSign);
		String signatureString;
		Signature signatureInstance=getSignatureAlgorithm();
		SignedInfo signedInfo=new SignedInfo();
		signedInfo.setSignedParameters(intermediateSignedInfo[0]);

		ServiceKeyRep keyRep=new ServiceKeyRep(KeyRep.Type.PRIVATE, privateKey.getPrivateKeyAlgoName(), privateKey.getPrivateKeyEncodingFormat(), privateKey.getEncoded());
		try{
			PrivateKey resolvedPrivateKey=(PrivateKey)keyRep.readResolve();
			signatureInstance.initSign(resolvedPrivateKey);
			byte[] bytesToSign=Base64.decodeBase64(intermediateSignedInfo[1]);
			signatureInstance.update(bytesToSign);
			byte[] signatureBytes=signatureInstance.sign();
			signatureString=Base64.encodeBase64String(signatureBytes);
			signedInfo.setSignatureVal(signatureString);
		}
		catch(Exception ex)
		{
			throw new RuntimeException(ex.getMessage());
		}
		return signedInfo;
	}

	/**
	 * Verifies signature for a given map of parameter name value pairs
	 * @param signedParameters map of parameter names and their plain text values
	 * @param signedInfo contains signature value and list of parameter names on which signature has been calculated
	 * @param publicKey public key belonging to the service
	 */
	@Override
	public boolean verifySignature(Map<String, String> signedParameters,
			SignedInfo signedInfo, ServicePublicKey publicKey) {
		boolean verificationResult=false;
		Signature signatureInstance=getSignatureAlgorithm();
		String[] intermediateSignedInfo=canonicalize(signedParameters);
		ServiceKeyRep keyRep=new ServiceKeyRep(KeyRep.Type.PUBLIC, publicKey.getPublicKeyAlgoName(), publicKey.getPublicKeyEncodingFormat(), publicKey.getEncoded());
		try{
			PublicKey resolvedPublicKey=(PublicKey)keyRep.readResolve();
			signatureInstance.initVerify(resolvedPublicKey);
			byte[] signedInfoBytes=Base64.decodeBase64(intermediateSignedInfo[1]);
			signatureInstance.update(signedInfoBytes);
			byte[] signatureValBytes=Base64.decodeBase64(signedInfo.getSignatureVal());
			verificationResult=signatureInstance.verify(signatureValBytes);
		}
		catch(Exception ex)
		{
			throw new RuntimeException(ex.getMessage());
		}
		return verificationResult;
	}

	/**
	 * Verifies signature for a given map of parameter name value pairs
	 * @param signedParameters map of parameter names and their plain text values
	 * @param signatureVal contains signature value and list of parameter names on which signature has been calculated
	 * @param publicKey public key belonging to the service
	 */
	@Override
	public boolean verifySignature(Map<String, String> signedParameters,
			String signatureVal, ServicePublicKey publicKey) {
		boolean verificationResult=false;
		Signature signatureInstance=getSignatureAlgorithm();
		String[] intermediateSignedInfo=canonicalize(signedParameters);
		ServiceKeyRep keyRep=new ServiceKeyRep(KeyRep.Type.PUBLIC, publicKey.getPublicKeyAlgoName(), publicKey.getPublicKeyEncodingFormat(), publicKey.getEncoded());
		try{
			PublicKey resolvedPublicKey=(PublicKey)keyRep.readResolve();
			signatureInstance.initVerify(resolvedPublicKey);
			byte[] signedInfoBytes=Base64.decodeBase64(intermediateSignedInfo[1]);
			signatureInstance.update(signedInfoBytes);
			byte[] signatureValBytes=Base64.decodeBase64(signatureVal);
			verificationResult=signatureInstance.verify(signatureValBytes);
		}
		catch(Exception ex)
		{
			throw new RuntimeException(ex.getMessage());
		}
		return verificationResult;
	}
}
