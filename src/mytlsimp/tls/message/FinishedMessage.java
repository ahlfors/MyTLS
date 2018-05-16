package mytlsimp.tls.message;

import mytlsimp.tls.ProtocolVersion;

public class FinishedMessage  extends TLSMessage{
	private byte[] verifyData;
	
	public FinishedMessage(byte[] verifyData){
		this.verifyData = verifyData;
	}
	
	@Override
	public byte getMessageType() {
		return 20;
	}

	@Override
	public ProtocolVersion getVersion() {
		return null;
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
		
		System.arraycopy(verifyData, 0, bytes, i, verifyData.length);
		
		return bytes;
	}

	@Override
	public int getSize() {
		return verifyData.length + 4;
	}
}
