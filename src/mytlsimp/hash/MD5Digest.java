package mytlsimp.hash;

public class MD5Digest extends Digest {
	private static final double BASE_T=4294967296.0;

	private static final int[] MD5_INITIAL_HASH = new int[] {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
	
	@Override
	protected int[] init() {
		int[] hash = new int[MD5_INITIAL_HASH.length];
		hash[0] = MD5_INITIAL_HASH[0];
		hash[1] = MD5_INITIAL_HASH[1];
		hash[2] = MD5_INITIAL_HASH[2];
		hash[3] = MD5_INITIAL_HASH[3];
		
		return hash;
	}

	@Override
	protected void update(byte[] input, int[] hash) {
		int a, b, c, d;
		int j;
		int x[] = new int[16];

		a = hash[0];
		b = hash[1];
		c = hash[2];
		d = hash[3];

		for (j=0; j<16; j++) {
			x[j] = (input[(j*4)+3]&0x00FF) << 24 | 
					(input[(j*4)+2]&0x00FF) << 16 |
		            (input[(j*4)+1]&0x00FF) << 8 |
		            (input[(j*4)]&0x00FF);
		}
		
		// Round 1
		a = round("F", x, a, b, c, d, 0, 7, 1 );		
		d = round("F", x, d, a, b, c, 1, 12, 2 );
		c = round("F", x, c, d, a, b, 2, 17, 3 );
		b = round("F", x, b, c, d, a, 3, 22, 4 );
		a = round("F", x, a, b, c, d, 4, 7, 5 );
		d = round("F", x, d, a, b, c, 5, 12, 6 );
		c = round("F", x, c, d, a, b, 6, 17, 7 );
		b = round("F", x, b, c, d, a, 7, 22, 8 );
		a = round("F", x, a, b, c, d, 8, 7, 9 );
		d = round("F", x, d, a, b, c, 9, 12, 10 );
		c = round("F", x, c, d, a, b, 10, 17, 11 );
		b = round("F", x, b, c, d, a, 11, 22, 12 );
		a = round("F", x, a, b, c, d, 12, 7, 13 );
		d = round("F", x, d, a, b, c, 13, 12, 14 );
		c = round("F", x, c, d, a, b, 14, 17, 15 );
		b = round("F", x, b, c, d, a, 15, 22, 16 );
		  
		// Round 2
		a = round("G", x, a, b, c, d, 1, 5, 17 );		
		d = round("G", x, d, a, b, c, 6, 9, 18 );
		c = round("G", x, c, d, a, b, 11, 14, 19 );
		b = round("G", x, b, c, d, a, 0, 20, 20 );
		a = round("G", x, a, b, c, d, 5, 5, 21 );
		d = round("G", x, d, a, b, c, 10, 9, 22 );
		c = round("G", x, c, d, a, b, 15, 14, 23 );
		b = round("G", x, b, c, d, a, 4, 20, 24 );
		a = round("G", x, a, b, c, d, 9, 5, 25 );
		d = round("G", x, d, a, b, c, 14, 9, 26 );
		c = round("G", x, c, d, a, b, 3, 14, 27 );
		b = round("G", x, b, c, d, a, 8, 20, 28 );
		a = round("G", x, a, b, c, d, 13, 5, 29 );
		d = round("G", x, d, a, b, c, 2, 9, 30 );
		c = round("G", x, c, d, a, b, 7, 14, 31 );
		b = round("G", x, b, c, d, a, 12, 20, 32 );
		
		// Round 3
		a = round("H", x, a, b, c, d, 5, 4, 33 );
		d = round("H", x, d, a, b, c, 8, 11, 34 );
		c = round("H", x, c, d, a, b, 11, 16, 35 );
		b = round("H", x, b, c, d, a, 14, 23, 36 );
		a = round("H", x, a, b, c, d, 1, 4, 37 );
		d = round("H", x, d, a, b, c, 4, 11, 38 );
		c = round("H", x, c, d, a, b, 7, 16, 39 );
		b = round("H", x, b, c, d, a, 10, 23, 40 );
		a = round("H", x, a, b, c, d, 13, 4, 41 );
		d = round("H", x, d, a, b, c, 0, 11, 42 );
		c = round("H", x, c, d, a, b, 3, 16, 43 );
		b = round("H", x, b, c, d, a, 6, 23, 44 );
		a = round("H", x, a, b, c, d, 9, 4, 45 );
		d = round("H", x, d, a, b, c, 12, 11, 46 );
		c = round("H", x, c, d, a, b, 15, 16, 47 );
		b = round("H", x, b, c, d, a, 2, 23, 48 );
		
		// Round 4		 
		a = round("I", x, a, b, c, d, 0, 6, 49 );
		d = round("I", x, d, a, b, c, 7, 10, 50 );
		c = round("I", x, c, d, a, b, 14, 15, 51 );
		b = round("I", x, b, c, d, a, 5, 21, 52 );
		a = round("I", x, a, b, c, d, 12, 6, 53 );
		d = round("I", x, d, a, b, c, 3, 10, 54 );
		c = round("I", x, c, d, a, b, 10, 15, 55 );
		b = round("I", x, b, c, d, a, 1, 21, 56 );
		a = round("I", x, a, b, c, d, 8, 6, 57 );
		d = round("I", x, d, a, b, c, 15, 10, 58 );
		c = round("I", x, c, d, a, b, 6, 15, 59 );
		b = round("I", x, b, c, d, a, 13, 21, 60 );
		a = round("I", x, a, b, c, d, 4, 6, 61 );
		d = round("I", x, d, a, b, c, 11, 10, 62 );
		c = round("I", x, c, d, a, b, 2, 15, 63 );
		b = round("I", x, b, c, d, a, 9, 21, 64 );
		
		
		hash[0] += a;
		hash[1] += b;
		hash[2] += c;
		hash[3] += d;
	}

	@Override
	protected String finalize(byte[] input, int[] hash, int totalLength) {		
		input[input.length-5] = (byte)(((totalLength*8)&0xFF000000) >>> 24);
		input[input.length-6] = (byte)(((totalLength*8)&0x00FF0000) >>> 16);
		input[input.length-7] = (byte)(((totalLength*8)&0x0000FF00) >>> 8);
		input[input.length-8] = (byte)(((totalLength*8)&0x000000FF));
		
		update(input, hash);
		
		return hashToString(hash);		
	}
	
	private String hashToString(int[] hash){
		String s="";
		for (int i = 0; i < hash.length; i++) {
			String tmp = Integer.toHexString(Integer.reverseBytes(hash[i]));
			s+="00000000".substring(tmp.length()) + tmp;
		}
			
		return s;
	}
	
	private int F(int x, int y, int z) {
		return (x&y)|(~x&z);
	}

	private int G(int x, int y, int z) {
		return (x&z)|(y&~z);
	}
	
	private int H(int x, int y, int z){
		return (x^y^z);
	}

	private int I(int x, int y, int z){
		return y^(x|~z);
	}
	
	private int round(String function, int[] x, int a, int b, int c, int d, int k, int s, int i){
		int ret = a;
				
		ret = (ret + x[k] + ((int)(long)(BASE_T * Math.abs(Math.sin((double)i)))));
		if ("F".equals(function)){
			ret += F(b, c, d); 
		} else if ("G".equals(function)){
			ret += G(b, c, d); 
		} else if ("H".equals(function)){
			ret += H(b, c, d); 
		} else if ("I".equals(function)){
			ret += I(b, c, d); 
		} 
		
		ret = (ret<<s)|(ret>>>(32-s)); 
		ret += b;
		
		return (int)ret;
	}	
}
