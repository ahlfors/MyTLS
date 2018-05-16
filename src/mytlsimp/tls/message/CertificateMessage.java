package mytlsimp.tls.message;

import java.util.ArrayList;
import java.util.List;

import mytlsimp.cipher.asymmetric.x509.SignedX509Certificate;
import mytlsimp.cipher.asymmetric.x509.X509;
import mytlsimp.tls.ProtocolVersion;

public class CertificateMessage extends TLSMessage{
	private ProtocolVersion version = new ProtocolVersion();
	private List<SignedX509Certificate> certificateChain;
	
	public CertificateMessage(byte[] b){
		int i = 7;
	
		certificateChain = new ArrayList<SignedX509Certificate>();
		
		X509 parser = new X509();
		while (i<b.length){
			int certificateLength = (b[i++]<<16) + (b[i++]<<8) + (b[i++]&0xFF);
			byte[] certBytes = new byte[certificateLength];
			System.arraycopy(b, i, certBytes, 0, certBytes.length);
			certificateChain.add(parser.parseX509Certificate(certBytes));
			
			i+=certBytes.length;
		}
	}
	
	@Override
	public byte getMessageType() {
		return 11;
	}

	@Override
	public ProtocolVersion getVersion() {
		return version;
	}

	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getSize() {
		// TODO Auto-generated method stub
		return 0;
	}
	
	public List<SignedX509Certificate> getCertificateChain(){
		return certificateChain;
	}
}
