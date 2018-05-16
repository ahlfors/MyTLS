package mytlsimp.tls.type;

import java.util.Arrays;
import java.util.Optional;

public enum CipherSuiteEnum {
	TLS_NULL_WITH_NULL_NULL((short)0x0000, 0, 0, 0, 0, null, null, null),
	TLS_RSA_WITH_NULL_MD5((short)0x0001, 0, 0, 0, 16, "MD5", null, null),
	TLS_RSA_WITH_NULL_SHA((short)0x0002, 0, 0, 0, 20, "SHA1", null, null),
	//TLS_RSA_EXPORT_WITH_RC4_40_MD5((short)0x0003),
	//TLS_RSA_WITH_RC4_128_MD5((short)0x0004),
	//TLS_RSA_WITH_RC4_128_SHA((short)0x0005),
	//TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5((short)0x0006),
	//TLS_RSA_WITH_IDEA_CBC_SHA((short)0x0007),
	//TLS_RSA_EXPORT_WITH_DES40_CBC_SHA((short)0x0008),
	TLS_RSA_WITH_DES_CBC_SHA((short)0x0009, 8, 8, 8, 20, "SHA1", "DES", "CBC"),
	TLS_RSA_WITH_3DES_EDE_CBC_SHA((short)0x000A, 8, 8, 24, 20, "SHA1", "3DES", "EDE_CBC"),
	TLS_RSA_WITH_AES_128_CBC_SHA((short)0x002F, 16, 16, 16, 20, "SHA1", "AES", "CBC"),
	//TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256((short)0xC031),
	//TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256((short)0xC02F),	
	//TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384((short)0xC02C),
	TLS_RSA_WITH_AES_128_CBC_SHA256((short)0x003C, 16, 16, 16, 32, "SHA256", "AES", "CBC");
	
	private short value;
	private int blockSize;
	private int ivSize;
	private int keySize;
	private int hashSize;
	
	private String digest;
	private String cipher;
	private String mode;
	
	public short getValue(){
		return value;
	}
	
	public int getBlockSize(){
		return blockSize;
	}
	
	public int getIvSize(){
		return ivSize;
	}
	
	public int getKeySize(){
		return keySize;
	}
	
	public int getHashSize(){
		return hashSize;
	}
	
	public String getDigest(){
		return digest;
	}
	
	public String getCipher(){
		return cipher;
	}
	
	public String getMode(){
		return mode;
	}
		
	CipherSuiteEnum(short value){
		this.value = value;
	}	
	
	CipherSuiteEnum(short value, int blockSize, int ivSize, int keySize, int hashSize, String digest, String cipher, String mode){
		this.value = value;
		this.blockSize = blockSize;
		this.ivSize = ivSize;
		this.keySize = keySize;
		this.hashSize = hashSize;
		this.digest = digest;
		this.cipher = cipher;
		this.mode = mode;
	}
	
	public static CipherSuiteEnum valueOf(short value){		
		Optional<CipherSuiteEnum> ret = Arrays.stream(values()).filter(v -> value == v.getValue()).findFirst();
		
		return ret.isPresent()?ret.get():null;
	}
}
