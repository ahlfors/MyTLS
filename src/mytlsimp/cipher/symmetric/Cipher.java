package mytlsimp.cipher.symmetric;

public abstract class Cipher {
	public static Cipher getInstance(String algorithm){
		if ("AES".equals(algorithm)){
			return new AES();
		} else if ("DES".equals(algorithm)){
			return new DES();
		} else if ("RC4".equals(algorithm)){
			return new RC4();
		} else if ("3DES".equals(algorithm)){
			return new TrippleDES();
		} else {
			return null;
		}
		
	}
	
	public abstract byte[] encrypt(byte[] data, byte[] key, byte[] iv, String mode);
	public abstract byte[] decrypt(byte[] data, byte[] key, byte[] iv, String mode);
}
