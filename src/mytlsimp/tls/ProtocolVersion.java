package mytlsimp.tls;

public class ProtocolVersion {
	private byte minor;
	private byte major;
	
	public ProtocolVersion(byte major, byte minor){
		this.major = major;
		this.minor = minor;
	}
	
	public ProtocolVersion(){
		this.major = (byte)3;
		this.minor = (byte)1;
	}
	
	public byte getMinor(){
		return minor;
	}
	
	public void setMinor(byte minor){
		this.minor = minor;
	}
	
	public byte getMajor(){
		return major;
	}
	
	public void setMajor(byte major){
		this.major = major;
	}
}
