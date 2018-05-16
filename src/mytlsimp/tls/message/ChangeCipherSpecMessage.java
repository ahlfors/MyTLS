package mytlsimp.tls.message;

import mytlsimp.tls.ProtocolVersion;

public class ChangeCipherSpecMessage extends TLSMessage{
	@Override
	public byte getMessageType() {
		return 0;
	}

	@Override
	public ProtocolVersion getVersion() {
		return null;
	}

	@Override
	public byte[] getBytes() {
		return new byte[]{ 1 };
	}

	@Override
	public int getSize() {
		return 1;
	}

}
