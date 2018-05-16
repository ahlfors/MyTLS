package mytlsimp.cipher.asymmetric.x509;

import mytlsimp.util.Huge;

public class X509Certificate {
	  private int version;
	  private Huge serialNumber; // This can be much longer than a 4-byte long allows
	  private SignatureAlgorithmIdentifier signature;
	  private Name issuer;
	  private ValidityPeriod validity;
	  private Name subject;
	  private PublicKeyInfo subjectPublicKeyInfo;
	  private Huge issuerUniqueId;
	  private Huge subjectUniqueId;
	  private boolean certificateAuthority; // true if this is a CA, false if not
	  
	  public int getVersion(){
		  return version;
	  }
	  
	  public void setVersion(int version){
		  this.version = version;
	  }
	  
	  public Huge getSerialNumber(){
		  return serialNumber;
	  }
	  
	  public void setSerialNumber(Huge serialNumber){
		  this.serialNumber = serialNumber;
	  }
	  
	  public SignatureAlgorithmIdentifier getSignature(){
		  return signature;
	  }
	  
	  public void setSignature(SignatureAlgorithmIdentifier signature){
		  this.signature = signature;
	  }
	  
	  public Name getIssuer(){
		  return issuer;
	  }
	  
	  public void setIssuer(Name issuer){
		  this.issuer = issuer;
	  }
	  
	  public ValidityPeriod getValidity(){
		  return validity;
	  }
	  
	  public void setValidity(ValidityPeriod validity){
		  this.validity = validity;
	  }
	  
	  public Name getSubject(){
		  return subject;
	  }
	  
	  public void setSubject(Name subject){
		  this.subject = subject;
	  }
	  
	  public PublicKeyInfo getSubjectPublicKeyInfo(){
		  return subjectPublicKeyInfo;
	  }
	  
	  public void setSubjectPublicKeyInfo(PublicKeyInfo subjectPublicKeyInfo){
		  this.subjectPublicKeyInfo = subjectPublicKeyInfo;
	  }
	  
	  public Huge getIssuerUniqueId(){
		  return issuerUniqueId;
	  }
	  
	  public void setIssuerUniqueId(Huge issuerUniqueId){
		  this.issuerUniqueId = issuerUniqueId;
	  }
	  
	  public Huge getSubjectUniqueId(){
		  return subjectUniqueId;
	  }
	  
	  public void setSubjectUniqueId(Huge subjectUniqueId){
		  this.subjectUniqueId = subjectUniqueId;
	  }
	  
	  public boolean getCertificateAuthority(){
		  return certificateAuthority;
	  }
	  
	  public void setCertificateAuthority(boolean certificateAuthority){
		  this.certificateAuthority = certificateAuthority;
	  }
	  
	  public X509Certificate(){
			serialNumber = new Huge(1);
			issuer = new Name();
			subject = new Name();
			subjectPublicKeyInfo = new PublicKeyInfo();
			validity = new ValidityPeriod();
			issuerUniqueId = new Huge();			
			subjectUniqueId = new Huge();
	  }
}
