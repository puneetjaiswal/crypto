package com.crypto;
import java.util.Map;

import com.crypto.SignatureAlgorithmBase.SignedInfo;


public interface SignatureAlgorithm {
	
	/** Returns signature algorithm id */
	String getSignatureAlgorithmId();
	
	/** Generates signature info for the map of parameters using private key bytes */
	SignedInfo generateSignature(Map<String, String> parametersToSign, ServicePrivateKey privateKey);
	
	/** Verifies signature for a map of parameters
	 * @param signedParameters Contains a map of key value parameters for which signature needs to be verified
	 * @param signedInfo Contains signature value and a list of parameters names for which signature needs to be verified
	 * @param publicKey Contains public key which is used to verify the signature
	 * @return
	 */
	boolean verifySignature(Map<String, String> signedParameters, SignedInfo signedInfo, ServicePublicKey publicKey);
	
	/** Verifies signature for a map of parameters
	 * @param signedParameters Contains a map of key value parameters for which signature needs to be verified
	 * @param signatureVal signature value
	 * @param publicKey Contains public key which is used to verify the signature
	 * @return
	 */
	boolean verifySignature(Map<String, String> signedParameters,String signatureVal, ServicePublicKey publicKey);
}
