package mytlsimp.cipher.asymmetric.x509;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import mytlsimp.util.Huge;

public class SignedX509Certificate {
	private X509Certificate tbsCertificate;
	private String hash;
	private SignatureAlgorithmIdentifier algorithm;
	private Huge rsaSignatureValue;
	//private DSASignature dsaSignatureValue;
	
	public X509Certificate getTbsCertificate(){
		return tbsCertificate;
	}
	
	public void setTbsCertificate(X509Certificate tbsCertificate){
		this.tbsCertificate = tbsCertificate;
	}
	
	public String getHash(){
		return hash;
	}
	
	public void setHash(String hash){
		this.hash = hash;
	}
	
	public SignatureAlgorithmIdentifier getAlgorithm(){
		return algorithm;
	}
	
	public void setAlgorithm(SignatureAlgorithmIdentifier algorithm){
		this.algorithm = algorithm;
	}
	
	public Huge getRSASignatureValue(){
		return rsaSignatureValue;
	}
	
	public void setRSASignatureValue(Huge rsaSignatureValue){
		this.rsaSignatureValue = rsaSignatureValue;
	}

	/*public DSASignature getDSASignatureValue(){
		return dsaSignatureValue;
	}
	
	public void setDSASignatureValue(DSASignature dsaSignatureValue){
		this.dsaSignatureValue = dsaSignatureValue;
	}*/
	
	public SignedX509Certificate(){
		tbsCertificate = new X509Certificate();
		rsaSignatureValue = new Huge();		
	}
	
	public static void main(String[] args) {
		String test = "180320062429";
		
		System.out.println(LocalDateTime.parse(test, DateTimeFormatter.ofPattern("yyyyMMddHHmmss")));
	}
}
