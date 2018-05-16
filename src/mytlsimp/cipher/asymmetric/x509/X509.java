package mytlsimp.cipher.asymmetric.x509;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

import mytlsimp.cipher.asymmetric.RSA;
import mytlsimp.cipher.asymmetric.RSAKey;
import mytlsimp.hash.Digest;
import mytlsimp.util.BitOperator;
import mytlsimp.util.Huge;

public class X509 {
	private static final byte[] OID_MD5WithRSA = { 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x04 };
	private static final byte[] OID_SHA1WithRSA =  { 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x05 };
	private static final byte[] OID_SHA256WithRSA =  { 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x0B };
	private static final byte[] OID_SHA1WithDSA = { 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x38, 0x04, 0x03 };
	private static final byte[] OID_SHA256WithDSA = { 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x38, 0x04, 0x03 }; //TODO FIND THE RIGHT DSA OID
	
	private static final byte[] OID_idAtCommonName = { 0x55, 0x04, 0x03 };
	private static final byte[] OID_idAtCountryName = { 0x55, 0x04, 0x06 };
	private static final byte[] OID_idAtLocalityName = { 0x55, 0x04, 0x07 };
	private static final byte[] OID_idAtStateOrProvinceName = { 0x55, 0x04, 0x08 };
	private static final byte[] OID_idAtOrganizationName = { 0x55, 0x04, 0x0A };
	private static final byte[] OID_idAtOrganizationalUnitName = { 0x55, 0x04, 0x0B };
	
	private static final byte[] OID_RSA = { 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x01 };
	private static final byte[] OID_DSA = { 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x38, 0x04, 0x01 };
	
	private static final byte[] OID_keyUsage = { 0x55, 0x1D, 0x0F };
	
	private static final int BIT_CERT_SIGNER = 5;
	
	private SignatureAlgorithmIdentifier parseSignatureAlgorithmIdentifier(ASN1Structure source){
		ASN1Structure oid = source.getChildren();
		if (Arrays.equals(oid.getData(), OID_MD5WithRSA)) {
			return SignatureAlgorithmIdentifier.MD5WithRSAEncryption;
		} else if (Arrays.equals(oid.getData(), OID_SHA1WithRSA)) {
			return SignatureAlgorithmIdentifier.SHA1WithRSAEncryption;
		} else if (Arrays.equals(oid.getData(), OID_SHA256WithRSA)) {
			return SignatureAlgorithmIdentifier.SHA256WithRSAEncryption;
		} else if (Arrays.equals(oid.getData(), OID_SHA1WithDSA)) {
			return SignatureAlgorithmIdentifier.SHA1WithDSAEncryption;
		} else if (Arrays.equals(oid.getData(), OID_SHA256WithDSA)) {
			return SignatureAlgorithmIdentifier.SHA256WithDSAEncryption;
		} else {
			throw new IllegalArgumentException("Unsupported or unrecognized algorithm identifier OID");
		}		
	}
	
	/**
	 * Name parsing is a bit different. Loop through all of the
	 * children of the source, each of which is going to be a struct containing
	 * an OID and a value. If the OID is recognized, copy its contents
	 * to the correct spot in "target". Otherwise, ignore it.
	 */
	private Name parseName(ASN1Structure source) {
		Name parsedName = new Name();
		
		ASN1Structure typeValuePair;
		ASN1Structure typeValuePairSequence;
		ASN1Structure type;
		ASN1Structure value;
		
		typeValuePair = source.getChildren();
		while (typeValuePair!=null){
			typeValuePairSequence = typeValuePair.getChildren();
			type = typeValuePairSequence.getChildren();
			value = type.getNext();
						
			if (Arrays.equals(type.getData(), OID_idAtCountryName)) {
				parsedName.setIdAtCountryName(new String(value.getData()));
		    } else if (Arrays.equals(type.getData(), OID_idAtStateOrProvinceName)) {
				parsedName.setIdAtStateOrProvinceName(new String(value.getData()));
		    } else if (Arrays.equals(type.getData(), OID_idAtLocalityName)) {
				parsedName.setIdAtLocalityName(new String(value.getData()));
		    } else if (Arrays.equals(type.getData(), OID_idAtOrganizationName)) {
				parsedName.setIdAtOrganizationName(new String(value.getData()));
		    } else if (Arrays.equals(type.getData(), OID_idAtOrganizationalUnitName)) {
				parsedName.setIdAtOrganizationalUnitName(new String(value.getData()));
		    } else if (Arrays.equals(type.getData(), OID_idAtCommonName)) {
				parsedName.setIdAtCommonName(new String(value.getData()));
		    } 
			
			typeValuePair = typeValuePair.getNext();
		}
		
		return parsedName;
	}
	
	private ValidityPeriod parseValidity(ASN1Structure source) {
		ValidityPeriod parsedValidity = new ValidityPeriod();  
		
		ASN1Structure notBefore;
		ASN1Structure notAfter;
		
		notBefore = source.getChildren();
		notAfter = notBefore.getNext();
		
		String strNotBefore = new String(notBefore.getData(), 0, notBefore.getData().length-1);
		String strNotAfter = new String(notAfter.getData(), 0, notAfter.getData().length-1);
		
		if (strNotBefore.length()==12){
			parsedValidity.setNotBefore(LocalDateTime.parse(strNotBefore, DateTimeFormatter.ofPattern("yyMMddHHmmss")));
		} else if (strNotBefore.length()==14){
			parsedValidity.setNotBefore(LocalDateTime.parse(strNotBefore, DateTimeFormatter.ofPattern("yyyyMMddHHmmss")));
		}
		
		if (strNotAfter.length()==12){
			parsedValidity.setNotAfter(LocalDateTime.parse(strNotAfter, DateTimeFormatter.ofPattern("yyMMddHHmmss")));
		} else if (strNotAfter.length()==14){
			parsedValidity.setNotAfter(LocalDateTime.parse(strNotAfter, DateTimeFormatter.ofPattern("yyyyMMddHHmmss")));
		}
				
		return parsedValidity;		
	}
	
	private PublicKeyInfo parsePublicKeyInfo(ASN1Structure source){
		PublicKeyInfo parsedPublicKey = new PublicKeyInfo();
		
		ASN1Structure oid;
		ASN1Structure publicKey;
		ASN1Structure publicKeyValue;
		
		oid = source.getChildren().getChildren();
		publicKey = source.getChildren().getNext();
		
		publicKeyValue = new ASN1().parse(Arrays.copyOfRange(publicKey.getData(), 1, publicKey.getData().length));
		  
		if (Arrays.equals(oid.getData(), OID_RSA)){
			parsedPublicKey.setAlgorithm(AlgorithmIdentifier.RSA);
			RSAKey key = new RSAKey(new Huge(publicKeyValue.getChildren().getData(), false), new Huge(publicKeyValue.getChildren().getNext().getData(), false));			
			parsedPublicKey.setRSAPublicKey(key);
			
			key.getExponent().contract();
			key.getModolus().contract();
		} else if (Arrays.equals(oid.getData(), OID_DSA)){
			/*ASN1Structure params =*/ oid.getNext();
			parsedPublicKey.setAlgorithm(AlgorithmIdentifier.DSA);
			//parsedPublicKey.setDSAPublicKey(new Huge(publicKeyValue.getData()));
			//parsedPublicKey.setDSAParameters(parseDSAParams(params));
		} else {
			throw new IllegalArgumentException("Error; unsupported OID in public key info.");
		}
		
		return parsedPublicKey;
	}
	
	/*private DSAParams parseDSAParams(ASN1Structure source){
		DSAParams params = new ssl.chapter4.DSAParams();
		
		ASN1Structure p = source.getChildren();
		ASN1Structure q = p.getNext();
		ASN1Structure g = q.getNext();
		
		//params.setP(new Huge(p.getData()));
		//params.setQ(new Huge(q.getData()));
		//params.setG(new Huge(g.getData()));
		
		return params;
	}*/
	
	private boolean parseExtensions(X509Certificate certificate, ASN1Structure extensions){
		ASN1Structure source = extensions.getChildren().getChildren();
		
		while (source!=null){
			if (parseExtension(certificate, source)){
				return true;
			}
			
			source = source.getNext();
		}
		
		return false;
	}
	
	private boolean parseExtension(X509Certificate certificate, ASN1Structure extension){
		ASN1Structure oid = extension.getChildren();
		ASN1Structure critical = oid.getNext();
		ASN1Structure data;
		if (critical.getTag() == ASN1.ASN1_BOOLEAN){
			data = critical.getNext();
		} else {
			
			data = critical;
			critical = null;
		}
		
		if (Arrays.equals(oid.getData(), OID_keyUsage)){
			ASN1Structure keyUsageBitString;
			keyUsageBitString = new ASN1().parse(data.getData());

			if (keyUsageBitString.getData() != null && asn1GetBit(keyUsageBitString.getLength(), keyUsageBitString.getData(), BIT_CERT_SIGNER)){
				certificate.setCertificateAuthority(true);
			}
		}
		
		return false;		
	}
	
	private boolean asn1GetBit(int length,  byte[] bitString, int bit) {
		if (bit>((length-1)*8)){
			return false;
		} else {
			return ((bitString[1+(bit/8)]&0xFF)&(0x80>>(bit%8)))!=0;
		}
	}
	
	public SignedX509Certificate parseX509Certificate(byte[] buffer){
		SignedX509Certificate parsedX509Certificate = new SignedX509Certificate();
		
		ASN1Structure certificate;
		ASN1Structure tbsCertificate;
		ASN1Structure algorithmIdentifier;
		ASN1Structure signatureValue;
		
		certificate = new ASN1().parse(buffer);
		tbsCertificate = certificate.getChildren();
		algorithmIdentifier = tbsCertificate.getNext();
		signatureValue = algorithmIdentifier.getNext();
		parsedX509Certificate.setTbsCertificate(parseTbsCertificate(tbsCertificate));
		parsedX509Certificate.setAlgorithm(parseSignatureAlgorithmIdentifier(algorithmIdentifier));
						
		try {
			if (parsedX509Certificate.getAlgorithm().equals(SignatureAlgorithmIdentifier.MD5WithRSAEncryption)){
				parsedX509Certificate.setHash(Digest.factory("MD5").hash(tbsCertificate.getData()));
				parsedX509Certificate.setRSASignatureValue(new Huge(Arrays.copyOfRange(signatureValue.getData(), 1, signatureValue.getData().length), false));		
			} else if (parsedX509Certificate.getAlgorithm().equals(SignatureAlgorithmIdentifier.SHA1WithRSAEncryption)){
				parsedX509Certificate.setHash(Digest.factory("SHA1").hash(tbsCertificate.getData()));
				parsedX509Certificate.setRSASignatureValue(new Huge(Arrays.copyOfRange(signatureValue.getData(), 1, signatureValue.getData().length), false));		
			} else if (parsedX509Certificate.getAlgorithm().equals(SignatureAlgorithmIdentifier.SHA256WithRSAEncryption)){
				parsedX509Certificate.setHash(Digest.factory("SHA256").hash(tbsCertificate.getData()));
				parsedX509Certificate.setRSASignatureValue(new Huge(Arrays.copyOfRange(signatureValue.getData(), 1, signatureValue.getData().length), false));		
			} else if (parsedX509Certificate.getAlgorithm().equals(SignatureAlgorithmIdentifier.SHA1WithDSAEncryption)){
				parsedX509Certificate.setHash(Digest.factory("SHA1").hash(tbsCertificate.getData()));
				//parsedX509Certificate.setDSASignatureValue(parseDSASignatureValue(signatureValue));
			} else if (parsedX509Certificate.getAlgorithm().equals(SignatureAlgorithmIdentifier.SHA256WithDSAEncryption)){
				parsedX509Certificate.setHash(Digest.factory("SHA256").hash(tbsCertificate.getData()));
				//parsedX509Certificate.setDSASignatureValue(parseDSASignatureValue(signatureValue));
			}
		} catch (IOException ioe){
			throw new IllegalArgumentException("Invalid certificate data");
		}
		
		return parsedX509Certificate;
	}
	
	/*private DSASignature parseDSASignatureValue(ASN1Structure source){
		DSASignature ret = new DSASignature();
		
		ASN1Structure dsaSignature = new ASN1().parse(Arrays.copyOfRange(source.getData(), 1, source.getData().length));
		ret.setR(new Huge(dsaSignature.getChildren().getData()));
		ret.setS(new Huge(dsaSignature.getChildren().getNext().getData()));
		
		return ret;		
	}*/
	
	private X509Certificate parseTbsCertificate(ASN1Structure source){
		X509Certificate parsedCertificate = new X509Certificate();
		ASN1Structure version;
		ASN1Structure serialNumber;
		ASN1Structure signatureAlgorithmIdentifier;
		ASN1Structure issuer;
		ASN1Structure validity;
		ASN1Structure subject;
		ASN1Structure publicKeyInfo;
		ASN1Structure extensions;
		
		// Figure out if there's an explicit version or not; if there is, then
		// everything else "shifts down" one spot.
		version = source.getChildren();
		
		if (version.getTag() == 0 && version.getTagClass() == ASN1.ASN1_CONTEXT_SPECIFIC) {
			ASN1Structure versionNumber = version.getChildren();

		    // This will only ever be one byte; safe
		    parsedCertificate.setVersion(versionNumber.getData()[0] + 1);		    
		    serialNumber = version.getNext();
		} else {
			parsedCertificate.setVersion(1); // default if not provided
		    serialNumber = version;
		}
		
		signatureAlgorithmIdentifier = serialNumber.getNext();
		issuer = signatureAlgorithmIdentifier.getNext();
		validity = issuer.getNext();
		subject = validity.getNext();
		publicKeyInfo = subject.getNext();
		extensions = publicKeyInfo.getNext();
		
		parsedCertificate.setSerialNumber(new Huge(serialNumber.getData(), false));
		parsedCertificate.setSignature(parseSignatureAlgorithmIdentifier(signatureAlgorithmIdentifier));
		parsedCertificate.setIssuer(parseName(issuer));
		parsedCertificate.setValidity(parseValidity(validity));
		parsedCertificate.setSubject(parseName(subject));
		parsedCertificate.setSubjectPublicKeyInfo(parsePublicKeyInfo(publicKeyInfo));
		if (extensions!=null){
			parseExtensions(parsedCertificate, extensions);
		}		
		
		return parsedCertificate;
	}
	
/*	public boolean validateCertificateDsa(SignedX509Certificate certificate) {
		 return new DSA().dsaVerify(
				 certificate.getTbsCertificate().getSubjectPublicKeyInfo().getDSAParameters(),
				 certificate.getTbsCertificate().getSubjectPublicKeyInfo().getDSAPublicKey(),
				 certificate.getHash(),
				 certificate.getDSASignatureValue());
	}*/
	
	public boolean validateCertificatRSA(SignedX509Certificate certificate, RSAKey publicKey){
		byte[] pkcs7SignatureDecrypted;
		ASN1Structure pkcs7Signature;
		ASN1Structure hashValue;
		
		boolean valid = false;
		
		RSA rsa = new RSA();
		pkcs7SignatureDecrypted = rsa.rsaDecrypt(certificate.getRSASignatureValue().getRep(), publicKey);
		
		if (pkcs7SignatureDecrypted!=null && pkcs7SignatureDecrypted.length>0){
			pkcs7Signature = new ASN1().parse(pkcs7SignatureDecrypted);
			hashValue = pkcs7Signature.getChildren().getNext();
			valid = BitOperator.getRadix16FromByteArray(hashValue.getData()).equals(certificate.getHash());
		} else {
			throw new IllegalArgumentException("Unable to decode signature value.");
		}
		
		return valid;
	}
	
	private void outputX500Name(Name x500Name) {
		System.out.printf("C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s\n",
				(x500Name.getIdAtCountryName()!=null?x500Name.getIdAtCountryName():"?"),
				(x500Name.getIdAtStateOrProvinceName()!=null?x500Name.getIdAtStateOrProvinceName():"?"),
				(x500Name.getIdAtLocalityName()!=null?x500Name.getIdAtLocalityName():"?"),
				(x500Name.getIdAtOrganizationName()!=null?x500Name.getIdAtOrganizationName():"?"),
				(x500Name.getIdAtOrganizationalUnitName()!=null?x500Name.getIdAtOrganizationalUnitName():"?"),
				(x500Name.getIdAtCommonName()!=null?x500Name.getIdAtCommonName():"?"));
	}

	public void printCertificate(SignedX509Certificate certificate){
		 System.out.println("Certificate details: ");
		 System.out.printf("Version: %d\n", certificate.getTbsCertificate().getVersion());
		 System.out.printf("Serial number: %s\n", BitOperator.getRadix16FromByteArray(certificate.getTbsCertificate().getSerialNumber().getRep()));
		 System.out.printf("issuer: ");
		 outputX500Name(certificate.getTbsCertificate().getIssuer());
		 System.out.printf("subject: ");
		 outputX500Name(certificate.getTbsCertificate().getSubject());	
		 System.out.printf("not before: %s ", certificate.getTbsCertificate().getValidity().getNotBefore());
		 System.out.printf("not after: %s \n", certificate.getTbsCertificate().getValidity().getNotAfter());
		 System.out.printf("Public key algorithm: ");
		 
		 switch (certificate.getTbsCertificate().getSubjectPublicKeyInfo().getAlgorithm()) {
		 	case RSA:
		 		System.out.printf("RSA\n");
		 		System.out.printf("modulus: %s\n", BitOperator.getRadix16FromByteArray(certificate.getTbsCertificate().getSubjectPublicKeyInfo().getRSAPublicKey().getModolus().getRep()));
		 		System.out.printf("exponent: %s\n",  BitOperator.getRadix16FromByteArray(certificate.getTbsCertificate().getSubjectPublicKeyInfo().getRSAPublicKey().getExponent().getRep()));		      
		 		
		 		break;
		 	case DH:
		 		System.out.printf("DH\n");
		 		
		 		break;
		 		
		 	case DSA:
		 		System.out.printf("DSA\n");
		 		//System.out.printf("y: %s", BitOperator.getRadix16FromCharArray(certificate.getTbsCertificate().getSubjectPublicKeyInfo().getDSAPublicKey().getRep()));
		 		//System.out.printf("p: %s", BitOperator.getRadix16FromCharArray(certificate.getTbsCertificate().getSubjectPublicKeyInfo().getDSAParameters().getP().getRep()));
		 		//System.out.printf("q: %s", BitOperator.getRadix16FromCharArray(certificate.getTbsCertificate().getSubjectPublicKeyInfo().getDSAParameters().getQ().getRep()));
		 		//System.out.printf("g: %s", BitOperator.getRadix16FromCharArray(certificate.getTbsCertificate().getSubjectPublicKeyInfo().getDSAParameters().getG().getRep()));

		 		break;		 		
		    default:
		    	System.out.printf("?\n");
		  
		    	break;
		 }
		 
		 System.out.printf("Signature algorithm: ");

		 switch (certificate.getAlgorithm()) {
		 	case MD5WithRSAEncryption:
		 		System.out.printf("MD5 with RSA Encryption\n");
		 		
		 		break;
		    case SHA1WithRSAEncryption:
		    	System.out.printf("SHA-1 with RSA Encryption\n");
		    	
		    	break;
		    case SHA256WithRSAEncryption:
		    	System.out.printf("SHA-256 with RSA Encryption\n");
		    	
		    	break;
		    case SHA1WithDSAEncryption:
		    	System.out.printf("SHA-1 with DSA Encryption\n");
		    	
		    	break;
		    case SHA256WithDSAEncryption:
		    	System.out.printf("SHA-256 with DSA Encryption\n");
		    	
		    	break;		    	
		    
		    default: break;
		 }
		 
		 System.out.printf("Signature value: ");
		 switch (certificate.getAlgorithm()) {
		 	case MD5WithRSAEncryption:
		    case SHA1WithRSAEncryption:
		    case SHA256WithRSAEncryption:
		    	System.out.printf("%s", BitOperator.getRadix16FromByteArray(certificate.getRSASignatureValue().getRep()));

		    	break;
		    case SHA1WithDSAEncryption:
		    case SHA256WithDSAEncryption:
		    	//System.out.printf("\n\tr: %s", BitOperator.getRadix16FromCharArray(certificate.getDSASignatureValue().getR().getRep()));
		    	//System.out.printf("\n\ts: %s", BitOperator.getRadix16FromCharArray(certificate.getDSASignatureValue().getS().getRep()));
		    	break;  
		      
		    default: break;
		 }
		 
		 System.out.printf("\n");
		 if (certificate.getTbsCertificate().getCertificateAuthority()) {
			 System.out.printf("is a CA\n");
		 } else {
			 System.out.printf("is not a CA\n");
		 }
	}
	
	public static void main(String[] args) throws Exception {
		File f = new File("c:\\output\\cert.der");
		BufferedInputStream br = new BufferedInputStream(new FileInputStream(f));
					
		//byte c[] = {0x30, (byte)0x0B, 0x30, 0x09, 0x02, 0x02, 0x01, 0x02, 0x02, 0x03, 0x03, 0x04, 0x05};		
		byte[] b = new byte[(int)f.length()];
		br.read(b);
		br.close();		
		
		X509 x509 = new X509();
		SignedX509Certificate certificate = x509.parseX509Certificate(b);
		x509.printCertificate(certificate);
		
		// Assume it's a self-signed certificate and try to validate it that
		switch (certificate.getAlgorithm()) {
			case MD5WithRSAEncryption:
			case SHA1WithRSAEncryption:
			case SHA256WithRSAEncryption:
				if (x509.validateCertificatRSA(certificate, certificate.getTbsCertificate().getSubjectPublicKeyInfo().getRSAPublicKey())){
					System.out.println("Certificate is a valid self-signed certificate.");	
				} else {
					System.out.println("Certificate is corrupt or not self-signed.");
				}
				break;
				
			case SHA1WithDSAEncryption:
			case SHA256WithDSAEncryption:
				/*if (x509.validateCertificateDsa(certificate)){
					System.out.println("Certificate is a valid self-signed certificate.");	
				} else {
					System.out.println("Certificate is corrupt or not self-signed.");
				}*/
				break;
			default: break;
			
		}
	}
}
