package mytlsimp.hash;

import java.io.IOException;
import java.util.Arrays;

public class HMAC {
	private static final int HASH_BLOCK_LENGTH = 64;
	
	public String hmac(String digestAlgorithm, byte[] key, byte[] text) throws IOException{		
		String ret = null;
		byte[] ipad, opad, paddedBlock;
		String hash = null;
			
		assert(key.length <= HASH_BLOCK_LENGTH);
		
		ipad = new byte[HASH_BLOCK_LENGTH];
		paddedBlock = new byte[text.length + HASH_BLOCK_LENGTH];
		Arrays.fill(ipad, 0, HASH_BLOCK_LENGTH, (byte)0x36);
		Arrays.fill(paddedBlock, (byte)0);
		for(int i=0; i<key.length; i++){
			paddedBlock[i] = key[i];
		}
		
		for (int i=0; i<HASH_BLOCK_LENGTH; i++) {
			paddedBlock[i] ^= ipad[i];
		}	
		
		for (int i=0; i<text.length; i++){
			paddedBlock[i+HASH_BLOCK_LENGTH] = text[i];
		}
		
		hash = Digest.factory(digestAlgorithm).hash(paddedBlock);
		
		opad = new byte[HASH_BLOCK_LENGTH];
		Arrays.fill(opad, (byte)0x5C);
		 
		paddedBlock = new byte[(hash.length()/2)+HASH_BLOCK_LENGTH]; 
		Arrays.fill(paddedBlock, 0, HASH_BLOCK_LENGTH, (byte)0);
		for(int i=0; i<key.length; i++){
			paddedBlock[i] = key[i];
		}
		for (int i=0; i<HASH_BLOCK_LENGTH; i++) {
			paddedBlock[i] ^= opad[i];
		}
				
		for (int i=0; i< hash.length()/2; i++){
			paddedBlock[i+HASH_BLOCK_LENGTH] = (byte)Integer.parseInt(hash.substring(2*i, 2*(i+1)), 16);
		}
		
		ret = Digest.factory(digestAlgorithm).hash(paddedBlock);
		
		return ret;
	}
	
	public static void main(String[] args) throws Exception{
		HMAC g = new HMAC();
		
		System.out.println(g.hmac("SHA1", "cd".getBytes(), "acdd195e0543b4d78d8cf69689eac1d10d094a7defghijkl".getBytes()));
	}
}
