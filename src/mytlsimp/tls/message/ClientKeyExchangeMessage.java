package mytlsimp.tls.message;

import java.security.SecureRandom;

import mytlsimp.cipher.asymmetric.RSA;
import mytlsimp.cipher.asymmetric.RSAKey;
import mytlsimp.tls.ProtocolVersion;
import mytlsimp.tls.TLS;

public class ClientKeyExchangeMessage extends TLSMessage{
	private byte[] data;
	private ProtocolVersion version = new ProtocolVersion();
	private byte[] premasterSecret;
	
	@Override
	public byte getMessageType() {
		return 16;
	}
	
	@Override
	public ProtocolVersion getVersion() {		
		return version;
	}
	
	public byte[] getPremasterSecret(){
		return premasterSecret;
	}
	
	@Override
	public byte[] getBytes() {
		byte[] bytes = new byte[getSize()];
		int i=0;
		bytes[i++] = getMessageType();
		bytes[i++] = (byte)((data.length&0xFF0000)>>>16);
		bytes[i++] = (byte)((data.length&0xFF00)>>>8);
		bytes[i++] = (byte)(data.length&0xFF);
		
		System.arraycopy(data, 0, bytes, i, data.length);		
		
		return bytes;
	}
	
	public void generateForRSA(RSAKey key){
		premasterSecret = new byte[TLS.MASTER_SECRET_LENGTH];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(premasterSecret);
		premasterSecret[0] = getVersion().getMajor();
		premasterSecret[1] = getVersion().getMinor();
				
		RSA rsa = new RSA();
		byte[] encrypted = rsa.rsaEncrypt(premasterSecret, key);
		
		data = new byte[encrypted.length+2];
		data[0] = (byte)((encrypted.length&0xFF00)>>>8);
		data[1] = (byte)(encrypted.length&0xFF);
		for (int i = 0; i < encrypted.length; i++) {
			data[i+2] = encrypted[i];
		}		
	}
	
	@Override
	public int getSize() {
		return 1 + 				// messageType
				3 +				// size
				data.length; 	// encrypted premaster secret				
	}
}
