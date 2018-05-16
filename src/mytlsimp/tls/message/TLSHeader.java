package mytlsimp.tls.message;

import java.util.ArrayList;
import java.util.List;

import mytlsimp.tls.ProtocolVersion;
import mytlsimp.tls.TLSHeaderTypeEnum;
import mytlsimp.tls.type.CipherSuiteEnum;
import mytlsimp.tls.type.CompressionMethodEnum;

public class TLSHeader {
	private TLSHeaderTypeEnum messageType;
	private ProtocolVersion version;
	private List<TLSMessage> messages;
	
	public TLSHeader(TLSHeaderTypeEnum messageType){
		this.messageType = messageType;
		version = new ProtocolVersion();
	}
	
	public TLSHeaderTypeEnum getMessageType(){
		return messageType;
	}
	
	public void setMessageType(TLSHeaderTypeEnum messageType){
		this.messageType = messageType;
	}
	
	public ProtocolVersion getVersion(){
		return version;
	}
	
	public void setVersion(ProtocolVersion version){
		this.version = version;
	}
	
	public List<TLSMessage> getMessages(){
		return messages;
	}
	
	public void setMessages(List<TLSMessage> messages){
		this.messages = messages;
	}
	
	public byte[] getBytes(){
		int size = 0;		
		
		for (int i = 0; i < messages.size(); i++) {
			size += messages.get(i).getSize();		
		}
		
		byte[] bytes = new byte[size+1+2+2]; //messageType(1)+version(2)+size(2)];
		bytes[0] = messageType.getValue();
		bytes[1] = version.getMajor();
		bytes[2] = version.getMinor();
		bytes[3] = (byte)((size&0xFF00)>>8);
		bytes[4] = (byte)(size&0x00FF);
		
		int idx=5;
		for (int i=0; i < messages.size(); i++) {
			byte[] b = messages.get(i).getBytes();
			for (int j=0; j<b.length; j++){
				bytes[idx++] = b[j];
			}
		}
		
		return bytes;
	}
	
	public static TLSHeader createMessage(byte[] b){
		TLSHeader message = new TLSHeader(TLSHeaderTypeEnum.valueOf(b[0]));
		message.setVersion(new ProtocolVersion(b[1], b[2]));
		int i = 5;
		message.setMessages(new ArrayList<TLSMessage>());
		
		if (message.getMessageType().equals(TLSHeaderTypeEnum.TLS_HANDSHAKE)){
			while (i<b.length){
				byte[] tmp = new byte[4];
				System.arraycopy(b, i, tmp, 0, tmp.length);
				i+=4;
				int messageSize = (tmp[1]<<16)+(tmp[2]<<8)+(tmp[3]&0xFF);
				byte[] messageBytes = new byte[4+messageSize];
				System.arraycopy(tmp, 0, messageBytes, 0, tmp.length);
				System.arraycopy(b, i, messageBytes, tmp.length, messageSize);
				i+=messageSize;
				
				message.getMessages().add(TLSMessage.getMessage(messageBytes));
			}			
		} else if (message.getMessageType().equals(TLSHeaderTypeEnum.CHANGE_CIPHER_SPEC)){
			message.getMessages().add(new ChangeCipherSpecMessage());
		}
		
		return message;
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
		
		TLSHeader message = new TLSHeader(TLSHeaderTypeEnum.TLS_HANDSHAKE);
		message.setVersion(new ProtocolVersion());
		List<TLSMessage> messages = new ArrayList<TLSMessage>();
		messages.add(hello);
		message.setMessages(messages);

		byte[] b = message.getBytes();
		for (int i = 0; i < b.length; i++) {
			String s = Integer.toHexString(b[i]&0xFF);
			if (s.length()==1){
				s="0"+s;
			}
			System.out.print(s + " "); 
		}
	}
}
