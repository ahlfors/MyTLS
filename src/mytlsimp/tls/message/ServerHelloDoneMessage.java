package mytlsimp.tls.message;

import mytlsimp.tls.ProtocolVersion;

public class ServerHelloDoneMessage extends TLSMessage{	
	public ServerHelloDoneMessage(byte[] b){ }
	
	
	@Override
	public byte getMessageType() {
		return 14;
	}

	@Override
	public ProtocolVersion getVersion() {
		return null;
	}

	@Override
	public byte[] getBytes() {
		return null;
	}

	@Override
	public int getSize() {
		return 0;
	}

}
