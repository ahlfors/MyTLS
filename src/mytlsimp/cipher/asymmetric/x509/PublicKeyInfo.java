package mytlsimp.cipher.asymmetric.x509;

import mytlsimp.cipher.asymmetric.RSAKey;

public class PublicKeyInfo {
	private AlgorithmIdentifier algorithm;
	//private DSAParams dsaParameters;
	private RSAKey rsaPublicKey;
	//private Huge dsaPublicKey;
	
	public AlgorithmIdentifier getAlgorithm(){
		return algorithm;
	}
	
	public void setAlgorithm(AlgorithmIdentifier algorithm){
		this.algorithm = algorithm;
	}
	
	/*public DSAParams getDSAParameters(){
		return dsaParameters;
	}
	
	public void setDSAParameters(DSAParams dsaParameters){
		this.dsaParameters = dsaParameters; 
	}*/
	
	public RSAKey getRSAPublicKey(){
		return rsaPublicKey;
	}
	
	public void setRSAPublicKey(RSAKey rsaPublicKey){
		this.rsaPublicKey = rsaPublicKey;
	}
	
	/*public Huge getDSAPublicKey(){
		return dsaPublicKey;
	}
	
	public void setDSAPublicKey(Huge dsaPublicKey){
		this.dsaPublicKey = dsaPublicKey;
	}*/
}
