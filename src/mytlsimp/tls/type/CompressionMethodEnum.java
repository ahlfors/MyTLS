package mytlsimp.tls.type;

import java.util.Arrays;
import java.util.Optional;

public enum CompressionMethodEnum {
	NO_COMPRESSION((byte)0),
	COMPRESSION((byte)1),
	COMPRESSION2((byte)255);
	
	private byte value;
	
	public byte getValue(){
		return value;
	}
	
	CompressionMethodEnum(byte value){
		this.value = value;
	}
	
	public static CompressionMethodEnum valueOf(short value){		
		Optional<CompressionMethodEnum> ret = Arrays.stream(values()).filter(v -> value == v.getValue()).findFirst();
		
		return ret.isPresent()?ret.get():null;
	}
}
