package mytlsimp.tls.message;

import java.util.ArrayList;
import java.util.List;

import mytlsimp.tls.ProtocolVersion;
import mytlsimp.tls.Random;
import mytlsimp.tls.type.CipherSuiteEnum;
import mytlsimp.tls.type.CompressionMethodEnum;

public class ServerHelloMessage extends TLSMessage{
	private Random random;
	private ProtocolVersion version;
	private byte[] sessionId;
	private CipherSuiteEnum cipherSuite;
	private CompressionMethodEnum compressionMethod; 
	
	public ServerHelloMessage(){}
	
	public ServerHelloMessage(byte[] b){
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
		cipherSuite = CipherSuiteEnum.valueOf((short)((b[i++]<<8) + b[i++]));
		compressionMethod = CompressionMethodEnum.valueOf(b[i++]);
	}
	
	public Random getRandom(){
		return random;
	}
	
	public void setRandom(Random random){
		this.random = random;
	}
	
	public byte[] getSessionId(){
		return sessionId;
	}
	
	public void setSessionId(byte[] sessionId){
		this.sessionId = sessionId;
	}
	
	public CipherSuiteEnum getCipherSuite(){
		return cipherSuite;
	}
	
	public void setCipherSuite(CipherSuiteEnum cipherSuite){
		this.cipherSuite = cipherSuite;
	}
	
	public CompressionMethodEnum getCompressionMethod(){
		return compressionMethod;
	}
	
	public void setCompressionMethod(CompressionMethodEnum compressionMethod){
		this.compressionMethod = compressionMethod; 
	}
	
	@Override
	public byte getMessageType() {
		return 0x02;
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
		bytes[i++] = (byte)((random.getGmtUnixTime()&0xFF000000)>>>24);
		bytes[i++] = (byte)((random.getGmtUnixTime()&0xFF0000)>>>16);
		bytes[i++] = (byte)((random.getGmtUnixTime()&0xFF00)>>>8);
		bytes[i++] = (byte)(random.getGmtUnixTime()&0xFF);
		for (int j=0;j<random.getRandomBytes().length; j++){
			bytes[i++] = random.getRandomBytes()[j];
		}
		int sessionLength = sessionId!=null?sessionId.length:0;
		bytes[i++] = (byte)(sessionLength&0xFF);
		if (sessionLength>0){
			for (int j = 0; j < sessionId.length; j++) {
				bytes[i++] = sessionId[j];
			}
		}
		
		bytes[i++] = (byte)((cipherSuite.getValue()&0xFF00)>>>8);
		bytes[i++] = (byte)(cipherSuite.getValue()&0xFF);				
		bytes[i++] = compressionMethod.getValue();
		
		return bytes;
	}

	@Override
	public int getSize() {
		return 1+3+2+32+			// MessateType(1)+Size(3)+ProtocolVersion(2) + Random(32)
				1+(sessionId!=null?sessionId.length:0)+ // Size(1)
				2+ //CipherSuite(2)
				1; //CompressionMethod(1) 
	}
	
	public static void main(String[] args) {
		ServerHelloMessage hello = new ServerHelloMessage();		
		hello.setVersion(new ProtocolVersion());
		hello.setRandom(new Random(true));
		List<CipherSuiteEnum> cipherSuites = new ArrayList<CipherSuiteEnum>();
		cipherSuites.add(CipherSuiteEnum.TLS_RSA_WITH_3DES_EDE_CBC_SHA);		
		hello.setCipherSuite(CipherSuiteEnum.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
		hello.setCompressionMethod(CompressionMethodEnum.NO_COMPRESSION);		
		
		byte[] b = hello.getBytes();
		ServerHelloMessage hello2 = new ServerHelloMessage(b);
		System.out.println(hello2);
		
	}
}
