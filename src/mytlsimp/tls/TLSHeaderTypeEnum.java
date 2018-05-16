package mytlsimp.tls;

import java.util.Arrays;
import java.util.Optional;

public enum TLSHeaderTypeEnum {
	TLS_HANDSHAKE((byte)22),
	CHANGE_CIPHER_SPEC((byte)20);
	
	private byte value;
	
	public byte getValue(){
		return value;
	}
	
	TLSHeaderTypeEnum(byte value){
		this.value = value;
	}	
	
	
	public static TLSHeaderTypeEnum valueOf(byte value){
		Optional<TLSHeaderTypeEnum> ret = Arrays.stream(values()).filter(v -> value == v.getValue()).findFirst();

		return ret.isPresent()?ret.get():null;
	}
}
