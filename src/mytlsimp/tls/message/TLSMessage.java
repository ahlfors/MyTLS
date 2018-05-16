package mytlsimp.tls.message;

import mytlsimp.tls.ProtocolVersion;

public abstract class TLSMessage {
	
	public abstract byte getMessageType();
	
	public abstract ProtocolVersion getVersion();
			
	public abstract byte[] getBytes();
	
	public abstract int getSize();
	
	public static TLSMessage getMessage(byte[] b){
		switch (b[0]){
			case 1: return new ClientHelloMessage(b); 
			
			case 2: return new ServerHelloMessage(b);
			
			case 11: return new CertificateMessage(b);
			
			case 14: return new ServerHelloDoneMessage(b);
			
			default: return null;
		}
	}
}
