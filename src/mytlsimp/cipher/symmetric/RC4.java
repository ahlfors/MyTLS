package mytlsimp.cipher.symmetric;

import mytlsimp.util.BitOperator;

public class RC4 extends Cipher{
	private byte[] rc4Operate(byte[] plaintext, byte[] key){
		byte[] output = new byte[plaintext.length]; 
		byte S[] = new byte[256];
		byte tmp;
		 
		// KSA (key scheduling algorithm)
		for (int i=0; i<256; i++){
			S[i] = (byte)i;
		}
		 
		int j = 0;
		for (int i=0; i<256; i++) {
			j = ((j+S[i]+key[i%key.length])&0xFF)%256;
			tmp = S[i];
			S[i] = S[j];
			S[j] = tmp;
		}
		 
		int i=0;
		j=0;
		int k=0;
		int length = plaintext.length;
		while (length-- > 0){
			i = ((i+1)&0xFF)%256;
			j = ((j+S[i])&0xFF)%256;
			tmp = S[i];
			S[i] = S[j];
			S[j] = tmp;
			output[k] = (byte)(S[((S[i]+S[j])&0xFF)%256] ^ plaintext[k++]);
		}
		 
		return output;
	}
	
	private byte[] rc4Encrypt(byte[] input, byte[] key){
		return rc4Operate(input, key);
	}
	
	private byte[] rc4Decrypt(byte[] input, byte[] key){
		return rc4Operate(input, key);
	}
	
	@Override
	public byte[] encrypt(byte[] data, byte[] key, byte[] iv, String mode) {
		return rc4Encrypt(data, key);
	}

	@Override
	public byte[] decrypt(byte[] data, byte[] key, byte[] iv, String mode) {
		return rc4Decrypt(data, key);
	}
	
	public static void main(String[] args) {
		byte[] output = new RC4().rc4Encrypt("abcdefghijklmnop".getBytes(), "abcdef".getBytes());
		System.out.println(BitOperator.getRadix16FromByteArray(output));
		
		output = new RC4().rc4Encrypt(output, "abcdef".getBytes());
		System.out.println(new String(output));
	}


}

