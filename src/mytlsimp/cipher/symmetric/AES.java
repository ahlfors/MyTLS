package mytlsimp.cipher.symmetric;

import java.util.Arrays;

import mytlsimp.util.BitOperator;

public class AES extends Cipher{
	private static final int AES_BLOCK_SIZE = 16; 
	
	private byte[][] sbox = {
			{ (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76 },
			{ (byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0, (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0 },
			{ (byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc, (byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15 },
			{ (byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75 },
			{ (byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0, (byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84 },
			{ (byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b, (byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf },
			{ (byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8 },
			{ (byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5, (byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2 },
			{ (byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73 },
			{ (byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb },
			{ (byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c, (byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79 },
			{ (byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9, (byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08 },
			{ (byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6, (byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a },
			{ (byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e },
			{ (byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94, (byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf },
			{ (byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16 }
	};
	
	private byte[][] invSbox = {
			{ (byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38, (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb },
			{ (byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87, (byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb },
			{ (byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d, (byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e },
			{ (byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2, (byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25 },
			{ (byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16, (byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92 },
			{ (byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda, (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84 },
			{ (byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a, (byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06 },
			{ (byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02, (byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b },
			{ (byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea, (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73 },
			{ (byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85, (byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e },
			{ (byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89, (byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b },
			{ (byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20, (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4 },
			{ (byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31, (byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f },
			{ (byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d, (byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef },
			{ (byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0, (byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61 },
			{ (byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26, (byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d }
	};
	
	private void rotationWord(byte[] word){
		byte tmp = word[0];
		word[0] = word[1];
		word[1] = word[2];
		word[2] = word[3];
		word[3] = tmp;
	}
	
	private void substituationWord(byte[] word){
		for (int i=0; i < 4; i++){
			word[i] = sbox[(word[i]&0xF0)>>4][word[i]&0x0F];
		 }
	}
	
	private byte[][] computeKeySchedule(byte[] key){		
		int keyWords = key.length >> 2;		
		byte rcon = 0x01;
		
		byte[][] ret = new byte[4*(keyWords+7)][4];
		
		for (int i=0; i<keyWords; i++){
			ret[i][0] = key[i*4+0];
			ret[i][1] = key[i*4+1];
			ret[i][2] = key[i*4+2];
			ret[i][3] = key[i*4+3];
		}
		for (int i=keyWords; i<4*(keyWords+7); i++){
			ret[i] = Arrays.copyOf(ret[i-1], 4);
			
			if (i%keyWords==0){
				rotationWord(ret[i]);
				substituationWord(ret[i]);				
				if (i%36==0){
					rcon = 0x1b;
				}
				ret[i][0] ^= rcon;
			    rcon <<= 1;
			} else if ((keyWords>6) && ((i%keyWords)==4)){
				substituationWord(ret[i]);
			}
			
			ret[i][0] ^= ret[i-keyWords][0];
			ret[i][1] ^= ret[i-keyWords][1];
			ret[i][2] ^= ret[i-keyWords][2];
			ret[i][3] ^= ret[i-keyWords][3];
		}
		
		return ret;
	}
	
	private void addRoundKey(byte[][] state, byte[][]w, int offset){
		for (int c=0;c<4;c++){
			for (int r=0; r<4; r++){
				state[r][c] = (byte)(state[r][c] ^ w[c+offset][r]);
			}
		}
	}
	
	private void substituationBytes(byte[][] state){
		for (int r=0;r<4;r++) {
			for (int c=0; c<4;c++){	
				state[r][c] = sbox[(state[r][c]&0xF0) >> 4 ][state[r][c] & 0x0F];
			}
		}
	}
	
	private void invSubstituationBytes(byte[][] state){
		for (int r=0;r<4;r++){
			for (int c=0;c<4;c++){
				state[r][c] = invSbox[(state[r][c]&0xF0)>>4][state[r][c]&0x0F];
			}
		}
	}
	
	private void shiftRows(byte[][] state){
		byte tmp;

		tmp = state[1][0];
		state[1][0] = state[1][1];
		state[1][1] = state[1][2];
		state[1][2] = state[1][3];
		state[1][3] = tmp;

		tmp = state[2][0];
		state[2][0] = state[2][2];
		state[2][2] = tmp;
		tmp = state[2][1];
		state[2][1] = state[2][3];
		state[2][3] = tmp;

		tmp = state[3][3];
		state[3][3] = state[3][2];
		state[3][2] = state[3][1];
		state[3][1] = state[3][0];
		state[3][0] = tmp;
	}
	
	private void invShiftRows(byte[][] state){
		byte tmp;

		tmp = state[1][2];
		state[1][2] = state[1][1];
		state[1][1] = state[1][0];
		state[1][0] = state[1][3];
		state[1][3] = tmp;

		tmp = state[2][0];
		state[2][0] = state[2][2];
		state[2][2] = tmp;
		tmp = state[2][1];
		state[2][1] = state[2][3];
		state[2][3] = tmp;

		tmp = state[3][0];
		state[3][0] = state[3][1];
		state[3][1] = state[3][2];
		state[3][2] = state[3][3];
		state[3][3] = tmp;
	}
	
	private byte xtime(byte x){
		return (byte)((x<<1)^((x&0x80)!=0?0x1b:0x00));
	}
	
	private byte dot(byte x, byte y){
		byte product = 0;
		
		for (int mask=0x01;mask!=0;mask<<=1){
			if (((y&0xFF)&mask)!=0){
				product ^= x;				
			}			
			x = xtime(x);
		}

		return product;
	}
	
	private void mixColumns(byte s[][]){
		byte t[] = new byte[4];

		for (int c=0; c<4; c++){		
			t[0] = (byte)(dot((byte)2, s[0][c]) ^ dot((byte)3, s[1][c]) ^ s[(byte)2][c] ^ s[(byte)3][c]);
			t[1] = (byte)(s[0][c]^dot((byte)2, s[1][c]) ^ dot((byte)3, s[2][c]) ^ s[3][c]);
			t[2] = (byte)(s[0][c] ^ s[1][c] ^ dot((byte)2, s[2][c]) ^ dot((byte)3, s[3][c]));
			t[3] = (byte)(dot((byte)3, s[0][c]) ^ s[1][c] ^ s[2][c] ^ dot((byte)2, s[3][c]));
			s[0][c] = t[0];
			s[1][c] = t[1];
			s[2][c] = t[2];
			s[3][c] = t[3];
		 }
	}
	
	private void invMixColumns(byte[][] s){
		byte t[] = new byte[4];

		for (int c=0;c<4; c++){
			t[0] = (byte)(dot((byte)0x0e, s[0][c]) ^ dot((byte)0x0b, s[1][c]) ^ dot((byte)0x0d, s[2][c]) ^ dot((byte)0x09, s[3][c]));
			t[1] = (byte)(dot((byte)0x09, s[0][c]) ^ dot((byte)0x0e, s[1][c]) ^ dot((byte)0x0b, s[2][c]) ^ dot((byte)0x0d, s[3][c]));
			t[2] = (byte)(dot((byte)0x0d, s[0][c]) ^ dot((byte)0x09, s[1][c]) ^ dot((byte)0x0e, s[2][c]) ^ dot((byte)0x0b, s[3][c]));
			t[3] = (byte)(dot((byte)0x0b, s[0][c]) ^ dot((byte)0x0d, s[1][c]) ^ dot((byte)0x09, s[2][c]) ^ dot((byte)0x0e, s[3][c]));
			s[0][c] = t[0];
			s[1][c] = t[1];
			s[2][c] = t[2];
			s[3][c] = t[3];
		}
	}
	
	private byte[] aesBlockEncrypt(byte[] inputBlock, byte[] key){
		byte[] outputBlock = new byte[16]; 
		
		int nr;
		byte state[][] = new byte[4][4];
		byte w[][] = new byte[60][4];
		
		for (int r=0; r<4; r++){
			for (int c=0; c<4; c++){
				state[r][c] = inputBlock[r+(4*c)];
			}
		}
		nr = (key.length>>2)+6;
		w = computeKeySchedule(key);
		
		addRoundKey(state, w, 0);
		
		for (int round=0; round<nr; round++){			
			substituationBytes(state);			
			shiftRows(state);

			if (round<(nr-1)){
				mixColumns(state);
			}
			
			addRoundKey(state, w, (round+1)*4);
		 }

		 for (int r=0; r<4; r++){		 
			 for (int c=0;c<4; c++){
				 outputBlock[r+(4*c)] = state[r][c];
			 }
		 }
		 
		 return outputBlock;
	}
	
	private byte[] aesBlockDecrypt(byte[] inputBlock, byte[] key){
		byte[] outputBlock = new byte[16]; 
		
		int nr;
		byte state[][] = new byte[4][4];
		byte w[][] = new byte[60][4];
		
		for (int r=0; r<4; r++){
			for (int c=0; c<4; c++){
				state[r][c] = inputBlock[r+(4*c)];
			}
		}		
		nr = (key.length>>2)+6;		
		w = computeKeySchedule(key);
		
		addRoundKey(state, w, nr*4);
		
		for (int round = nr; round > 0; round--){
			invShiftRows(state);
			invSubstituationBytes(state);
			addRoundKey(state, w, (round-1)*4);
			if ( round > 1 ){
				invMixColumns(state);
			}
			
			for (int r=0; r<4; r++){			 
				for (int c=0; c<4; c++){
					outputBlock[r+(4*c)] = state[r][c];
				}
			}
		}
		
		return outputBlock;
	}
	
	private byte[] aesEncrypt(byte[] input, byte[] iv, byte[] key){
		byte[] inputBlock = new byte[AES_BLOCK_SIZE];
		byte[] outputBlock = new byte[AES_BLOCK_SIZE];
		byte[] output = new byte[input.length];
		int i=0;
		
		if (input.length%AES_BLOCK_SIZE==0){	
			while (i < output.length) {
				inputBlock = Arrays.copyOfRange(input, i, i+AES_BLOCK_SIZE);
				
				BitOperator.xorArray(inputBlock, iv); // implement CBC		
				outputBlock = aesBlockEncrypt(inputBlock, key);					
				for (int j=0;j < outputBlock.length; j++) {
					iv[j] = outputBlock[j];
					output[i++] = outputBlock[j];
				}
			}
			
			return output;
		} 		
		
		return null;		
	}
	
	private byte[] aesDecrypt(byte[] input, byte[] iv, byte[] key){
		byte[] inputBlock = new byte[AES_BLOCK_SIZE];
		byte[] outputBlock = new byte[AES_BLOCK_SIZE];
		byte[] output = new byte[input.length];
		int i=0;
		
		if (input.length%AES_BLOCK_SIZE==0){	
			while (i < output.length) {
				inputBlock = Arrays.copyOfRange(input, i, i+AES_BLOCK_SIZE);
				
				outputBlock = aesBlockDecrypt(inputBlock, key);									
				BitOperator.xorArray(outputBlock, iv); // implement CBC		
				iv = Arrays.copyOfRange(input, i, i+AES_BLOCK_SIZE);				
				for (int j=0;j < outputBlock.length; j++) {
					output[i++] = outputBlock[j];
				}
			}
			
			return output;
		} 		
		
		return null;		
	}
	
	public byte[] encrypt(byte[] data, byte[] key, byte[] iv, String mode){
		if (mode.equals("CBC")){
			return aesEncrypt(data, iv, key);
		} else {
			return null;
		}
	}

	public byte[] decrypt(byte[] data, byte[] key, byte[] iv, String mode){
		if (mode.equals("CBC")){
			return aesDecrypt(data, iv, key);
		} else {
			return null;
		}
	}
	
	public static void main(String[] args) {
		System.out.println(BitOperator.getRadix16FromByteArray("initialzinitialz".getBytes()));
		
		byte[] out = new AES().aesEncrypt("abcdefghijklmnopabcdefghijklmnop".getBytes(), "initialzinitialz".getBytes(), "abcdefghabcdefgh".getBytes());
		
		System.out.println(BitOperator.getRadix16FromByteArray(out));
		
		
		System.out.println(new String(new AES().aesDecrypt(out, "initialzinitialz".getBytes(), "abcdefghabcdefgh".getBytes())));
		//new AES().dot((byte)2,  (byte)249);
		
		Cipher c = Cipher.getInstance("AES");
		byte[] b = c.encrypt("abcdefghijklmnopabcdefghijklmnop".getBytes(), "abcdefghabcdefgh".getBytes(), "initialzinitialz".getBytes(), "CBC");
		System.out.println(BitOperator.getRadix16FromByteArray(b));
		b = c.decrypt(b, "abcdefghabcdefgh".getBytes(), "initialzinitialz".getBytes(), "CBC");
		System.out.println(new String(b));
	}
}

