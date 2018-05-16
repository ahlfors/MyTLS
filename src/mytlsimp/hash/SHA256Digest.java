package mytlsimp.hash;

public class SHA256Digest extends Digest{
	private static final int[] SHA256_INITIAL_HASH = {
			0x67e6096a,
			0x85ae67bb,
			0x72f36e3c,
			0x3af54fa5,
			0x7f520e51,
			0x8c68059b,
			0xabd9831f,
			0x19cde05b
	};
	
	private static final int[] kSha256 = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
			0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
			0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
			0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
			0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
			0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};
	
	@Override
	public int[] init() {
		int[] hash = new int[SHA256_INITIAL_HASH.length];
		hash[0] = SHA256_INITIAL_HASH[0];
		hash[1] = SHA256_INITIAL_HASH[1];
		hash[2] = SHA256_INITIAL_HASH[2];
		hash[3] = SHA256_INITIAL_HASH[3];
		hash[4] = SHA256_INITIAL_HASH[4];
		hash[5] = SHA256_INITIAL_HASH[5];
		hash[6] = SHA256_INITIAL_HASH[6];
		hash[7] = SHA256_INITIAL_HASH[7];
		
		return hash;		
	}
	
	// ch is functions 0 - 19
	private int ch(int x, int y, int z) {
		return (x&y)^(~x&z);
	}
	
	// maj is functions 40 - 59
	private int maj(int x, int y, int z){
		return (x&y)^(x&z)^(y&z);
	}
	
	private int rotr(int x, int n) {
		return (x>>>n)|((x)<<(32-n));
	}

	private int shr(int x, int n) {
		return x>>>n;
	}

	private int sigmaRot(int x, int i) {
		return rotr(x, i!=0?6:2)^rotr(x, i!=0?11:13)^rotr(x, i!=0?25:22);
	}

	private int sigmaShr(int x, int i) {
		return rotr(x, i!=0?17:7)^rotr(x, i!=0?19:18)^shr(x, i!=0?10:3);
	}

	@Override
	public void update(byte[] input, int[] hash) {
		int[] W = new int[64];
		int t, i;
		int a, b, c, d, e, f, g, h;
		int T1, T2;
		
		// deal with little-endian-ness
		for (i=0;i<hash.length; i++) {
			hash[i] = Integer.reverseBytes(hash[i]);
		}
		
		for (t=0; t<64; t++) {
			if (t <= 15) {
				W[t] = ((input[(t*4)]&0x00FF)<<24) |
						((input[(t*4)+1]&0x00FF)<<16) |
						((input[(t*4)+2]&0x00FF)<<8) |
						(input[(t*4)+3]&0x00FF);
			} else {
				W[t] = sigmaShr(W[t-2], 1) + W[t-7] +  sigmaShr(W[t-15], 0) +  W[t-16];
			}
		}
		
		a = hash[0];
		b = hash[1];
		c = hash[2];
		d = hash[3];
		e = hash[4];
		f = hash[5];
		g = hash[6];
		h = hash[7];
		
		for (t=0; t<64; t++) {
			T1 = h + sigmaRot(e, 1) + ch(e, f, g) + kSha256[t] + W[t];
			T2 = sigmaRot(a, 0) + maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}
		
		hash[0] = a + hash[0];
		hash[1] = b + hash[1];
		hash[2] = c + hash[2];
		hash[3] = d + hash[3];
		hash[4] = e + hash[4];
		hash[5] = f + hash[5];
		hash[6] = g + hash[6];
		hash[7] = h + hash[7];
		
		for (i = 0; i < 8; i++) {
			hash[i] = Integer.reverseBytes(hash[i]);
		}
	}

	@Override
	public String finalize(byte[] input, int[] hash, int totalLength) {
		input[input.length-4] = (byte)(((totalLength*8)&0xFF000000) >> 24);
		input[input.length-3] = (byte)(((totalLength*8)&0x00FF0000) >> 16);
		input[input.length-2] = (byte)(((totalLength*8)&0x0000FF00) >> 8);
		input[input.length-1] = (byte)(((totalLength*8)&0x000000FF));		
				
		update(input, hash);
		
		for (int i = 0; i < hash.length; i++) {
			hash[i] = Integer.reverseBytes(hash[i]);
		}
		
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
