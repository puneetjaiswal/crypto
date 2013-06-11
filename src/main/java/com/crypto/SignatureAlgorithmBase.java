package com.crypto;


import java.io.ObjectStreamException;
import java.security.KeyRep;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Base class for all signature implementation classes 
 *
 */
public abstract class SignatureAlgorithmBase implements SignatureAlgorithm {

	@Override
	public abstract String getSignatureAlgorithmId();
	
	/**
	 * Generates array of strings of size 2 wherein first element of the array will contain the 
	 * list of parameters which are signed and second element will contain the canonicalized string
	 * to be signed
	 * @param headersToSign
	 * @return
	 */
	protected String[] canonicalize(Map<String, String> headersToSign)
	{
		StringBuffer canonicalizedStrBuffer=new StringBuffer();
		StringBuffer parameterNamesBuffer=new StringBuffer();
		Set<String> keySet=headersToSign.keySet();
		// Create sorted key set to enforce order on the key names
		SortedSet<String> sortedKeySet=new TreeSet<String>(keySet);
		for (String key :sortedKeySet)
		{
			Object val=headersToSign.get(key);
			parameterNamesBuffer.append(key.trim()).append(";");
			canonicalizedStrBuffer.append(val.toString().trim()).append("\n");
		}
		return new String[] {parameterNamesBuffer.toString(), canonicalizedStrBuffer.toString()};
	}
	
	/**
	 * Returns signature instance corresponding to a particular signature algorithm id
	 * @return java.security.Signature
	 */
	protected Signature getSignatureAlgorithm()
	{
		Signature signatureInstance=null;
		try {
			signatureInstance=Signature.getInstance(getSignatureAlgorithmId());
		}
		catch(NoSuchAlgorithmException ex)
		{
			throw new RuntimeException(ex.getMessage());
		}
		return signatureInstance;
	}

	/**
	 * Represents result object after signature operation has been performed successfully
	 *
	 */
	public static class SignedInfo
	{
		private String signedParametersList;
		private String signatureVal;
		
		public String getSignedParameters() {
			return signedParametersList;
		}
		public void setSignedParameters(String signedInfo) {
			this.signedParametersList = signedInfo;
		}
		public String getSignatureVal() {
			return signatureVal;
		}
		public void setSignatureVal(String signatureVal) {
			this.signatureVal = signatureVal;
		}
		
	}
}
class ServiceKeyRep extends KeyRep{
	private static final long serialVersionUID = -7213340660431987616L;
	
	public ServiceKeyRep(Type type, String algorithm, String format, byte[] encoded) {
		super(type, algorithm, format, encoded);
	}

	protected Object readResolve() throws ObjectStreamException
	{
		return super.readResolve();
	}
}

