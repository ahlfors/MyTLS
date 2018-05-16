package mytlsimp.tls.message;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import mytlsimp.tls.ProtocolVersion;
import mytlsimp.tls.Random;
import mytlsimp.tls.type.CipherSuiteEnum;
import mytlsimp.tls.type.CompressionMethodEnum;

public class ClientHelloMessage extends TLSMessage{
	private Random random;
	private ProtocolVersion version;
	private byte[] sessionId;
	private List<CipherSuiteEnum> cipherSuites;
	private List<CompressionMethodEnum> compressionMethods; 
	
	public ClientHelloMessage(){}
	
	public ClientHelloMessage(byte[] b){
		int i = 4;
		version = new ProtocolVersion(b[i++], b[i++]);
		random = new Random();
		random.setGmtUnixTime(b[i++],b[i++],b[i++],b[i++]);
		random.setRandomBytes(new byte[28]);
		System.arraycopy(b, i, random.getRandomBytes(), 0, random.getRandomBytes().length);
		i+=28;
		sessionId = new byte[b[i++]];
		System.arraycopy(b, i, sessionId, 0, sessionId.length);
		i+=sessionId.length;
		int cipherSuitesLength = ((b[i++]<<8) + b[i++])/2;
		cipherSuites = new ArrayList<CipherSuiteEnum>();
		for (int j=0; j<cipherSuitesLength; j++){
			cipherSuites.add(CipherSuiteEnum.valueOf((short)((b[i++]<<8) + b[i++])));
		}
		int compressionMethodLength = b[i++];
		compressionMethods = new ArrayList<CompressionMethodEnum>();
		for (int j=0; j<compressionMethodLength; j++){
			compressionMethods.add(CompressionMethodEnum.valueOf(b[i++]));
		}
	}
	
	public Random getRandom(){
		return random;
	}
	
	public void setRandom(Random random){
		this.random = random;
	}
	
	public void generateRandom(){
		int time = (int)(new Date().getTime()/1000);
		Random r = new Random();
		r.setGmtUnixTime(time);
		
		SecureRandom sr = new SecureRandom();
		byte[] b = new byte[28];
		sr.nextBytes(b);
		r.setRandomBytes(b);
		
		random = r;
	}
	
	public byte[] getSessionId(){
		return sessionId;
	}
	
	public void setSessionId(byte[] sessionId){
		this.sessionId = sessionId;
	}
	
	public List<CipherSuiteEnum> getCipherSuites(){
		return cipherSuites;
	}
	
	public void setCipherSuites(List<CipherSuiteEnum> cipherSuites){
		this.cipherSuites = cipherSuites;
	}
	
	public List<CompressionMethodEnum> getCompressionMethods(){
		return compressionMethods;
	}
	
	public void setCompressionMethods(List<CompressionMethodEnum> compressionMethods){
		this.compressionMethods = compressionMethods; 
	}
	
	@Override
	public byte getMessageType() {
		return 0x01;
	}

	@Override
	public ProtocolVersion getVersion(){
		return version;
	}
	
	public void setVersion(ProtocolVersion version){
		this.version = version;
	}

	@Override
	public byte[] getBytes() {
		byte[] bytes = new byte[getSize()];
		int i=0;
		bytes[i++] = getMessageType();
		int size = bytes.length-1-3; //MessageType(1)+Size(3)
		bytes[i++] = (byte)((size&0xFF0000)>>>16);
		bytes[i++] = (byte)((size&0xFF00)>>>8);
		bytes[i++] = (byte)(size&0xFF);
		bytes[i++] = version.getMajor();
		bytes[i++] = version.getMinor();
		byte[] clientRandom = random.getFullRandomBytes();
		for (int j=0;j<clientRandom.length; j++){
			bytes[i++] = clientRandom[j];
		}
		int sessionLength = sessionId!=null?sessionId.length:0;
		bytes[i++] = (byte)(sessionLength&0xFF);
		if (sessionLength>0){
			for (int j = 0; j < sessionId.length; j++) {
				bytes[i++] = sessionId[j];
			}
		}
		
		int cipherSuitesLength = cipherSuites!=null?cipherSuites.size()*2:0;
		bytes[i++] = (byte)((cipherSuitesLength&0xFF00)>>>8);
		bytes[i++] = (byte)(cipherSuitesLength&0xFF);
		if (cipherSuitesLength>0){
			for (int j = 0; j < cipherSuites.size(); j++) {
				bytes[i++] = (byte)((cipherSuites.get(j).getValue()&0xFF00)>>>8);
				bytes[i++] = (byte)(cipherSuites.get(j).getValue()&0xFF);				
			}
		}
		
		int compressionMethodsLength = compressionMethods!=null?compressionMethods.size():0;
		bytes[i++] = (byte)(compressionMethodsLength&0xFF);
		if (compressionMethodsLength>0){
			for (int j = 0; j < compressionMethods.size(); j++) {
				bytes[i++] = compressionMethods.get(j).getValue();
			}
		}
		return bytes;
	}

	@Override
	public int getSize() {
		return 1+3+2+32+			// MessateType(1)+Size(3)+ProtocolVersion(2) + Random(32)
				1+(sessionId!=null?sessionId.length:0)+ // Size(1)
				2+(cipherSuites!=null?cipherSuites.size()*2:0)+ //Size(2)
				1+(compressionMethods!=null?compressionMethods.size():0); //Size(1) 
	}
	
	public static void main(String[] args) {
		ClientHelloMessage hello = new ClientHelloMessage();		
		hello.setVersion(new ProtocolVersion());
		List<CipherSuiteEnum> cipherSuites = new ArrayList<CipherSuiteEnum>();
		cipherSuites.add(CipherSuiteEnum.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
		hello.generateRandom();
		hello.setCipherSuites(cipherSuites);
		List<CompressionMethodEnum> compressionMethods = new ArrayList<CompressionMethodEnum>();
		compressionMethods.add(CompressionMethodEnum.NO_COMPRESSION);
		hello.setCompressionMethods(compressionMethods);
		
		byte[] b = hello.getBytes();
		ClientHelloMessage hello2 = new ClientHelloMessage(b);
		System.out.println(hello2);
		
	}
}
