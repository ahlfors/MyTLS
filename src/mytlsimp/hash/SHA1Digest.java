package mytlsimp.hash;

public class SHA1Digest extends Digest {
	private static final int[] SHA1_INITIAL_HASH = {
			0x67452301,
			0xefcdab89,
			0x98badcfe,
			0x10325476,
			0xc3d2e1f0
	};
	
	private static final int[] kSha1 = {
			0x5a827999, // 0 <= t <= 19
			0x6ed9eba1, // 20 <= t <= 39
			0x8f1bbcdc, // 40 <= t <= 59
			0xca62c1d6 // 60 <= t <= 79
	};
	
	// ch is functions 0 - 19
	private int ch(int x, int y, int z) {
		return (x&y)^(~x&z);
	}
	
	// parity is functions 20 - 39 & 60 - 79
	private int parity(int x, int y, int z) {
		return x^y^z;
	}
	
	// maj is functions 40 - 59
	private int maj(int x, int y, int z){
		return (x&y)^(x&z)^(y&z);
	}
	
	@Override
	protected int[] init() {
		int[] hash = new int[SHA1_INITIAL_HASH.length];
		hash[0] = SHA1_INITIAL_HASH[0];
		hash[1] = SHA1_INITIAL_HASH[1];
		hash[2] = SHA1_INITIAL_HASH[2];
		hash[3] = SHA1_INITIAL_HASH[3];
		hash[4] = SHA1_INITIAL_HASH[4];

		return hash;
	}

	@Override
	protected void update(byte[] input, int[] hash) {
		int[] W = new int[80];
		int t = 0;
		int a, b, c, d, e, T;
		
		// First 16 blocks of W are the original 16 blocks of the input
		for (t=0; t<80; t++) {
			if (t<16){
				W[t] = ((input[(t*4)]&0xFF)<<24) |
		            ((input[(t*4)+1]&0xFF)<<16) |
		            ((input[(t*4)+2]&0xFF)<<8) |
		            (input[(t*4)+3]&0xFF);
			} else {
				W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^  W[t-16];
				// Rotate left operation, simulated in C
				W[t] = (W[t]<<1)|((W[t]&0x80000000)>>>31);
			}
		}
		
		a = hash[0];
		b = hash[1];
		c = hash[2];
		d = hash[3];
		e = hash[4];
		
		for (t=0; t<80; t++) {
			T = ((a<<5)|(a>>>27))+e+kSha1[(t/20)]+W[t];

			if (t<=19){
				T += ch(b, c, d);
			} else if (t<=39) {
				T += parity(b, c, d);
			} else if (t<= 59) {
				T += maj(b, c, d);
			} else {
				T += parity(b, c, d);
			}

			e = d;
			d = c;
			c = ((b<<30)|(b>>>2));
			b = a;
			a = T;
		}
		
		hash[0] += a;
		hash[1] += b;
		hash[2] += c;
		hash[3] += d;
		hash[4] += e;		
	}

	@Override
	protected String finalize(byte[] input, int[] hash, int totalLength) {
		input[input.length-4] = (byte)(((totalLength*8)&0xFF000000) >> 24);
		input[input.length-3] = (byte)(((totalLength*8)&0x00FF0000) >> 16);
		input[input.length-2] = (byte)(((totalLength*8)&0x0000FF00) >> 8);
		input[input.length-1] = (byte)(((totalLength*8)&0x000000FF));		
				
		update(input, hash);
		
		return hashToString(hash);		
	}
	
	private String hashToString(int[] hash){
		String s="";
		for (int i = 0; i < hash.length; i++) {
			String tmp = Integer.toHexString(hash[i]);
			s+="00000000".substring(tmp.length()) + tmp;
		}
		
		return s;
	}
}
