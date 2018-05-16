package mytlsimp.util;

public class BitOperator {
	public static void main(String args[]){
		byte b[] = {1, (byte)0, 0, 0, 0, 0, 1};
		
		//clearBit(b, 15);
		//setBit(b, 13);
		
		/*print(b);
		rightRotation(b);
		print(b);*/
		
		System.out.println(getRadix16FromByteArray(b));
		byte array[] = getByteArrayFromRadix16("71828547387b18e5");
		for (int i = 0; i < array.length; i++) {
			System.out.print((int)array[i] + " ");
		}
		System.out.println();
		System.out.println(getRadix16FromByteArray(array));
		
		System.out.println();
		
		for (int i = 0; i < 50; i++) {
			rightRotation(b);
			print(b);
		}
	}
	
	public static void print(byte[] bytes){
		for (int i=0;i<=bytes.length*8-1;i++){
			if (i%8==0 && i>0){
				System.out.print(" ");
			}
			System.out.print(getBit(bytes, i)?"1":"0");
		}
		System.out.println();
	}
		
	public static byte[] getByteArrayFromRadix16(String s){
		byte[] ret = new byte[s.length()/2];
		for (int i = 0; i < s.length(); i+=2) {
			ret[i/2] = (byte)Integer.parseInt(s.substring(i, i+2), 16);
		}
				
		return ret;
	}
	
	public static String getRadix16FromByteArray(byte[] bytes){
		String ret = "";
		for (int i=0;i<bytes.length;i++){
			String s = Integer.toHexString(bytes[i]&0xFF);
			ret += s.length()==1?"0"+s:s;
		}
		
		return ret;
	}
	
	public static boolean getBit(byte[] array, int bit){
		return ((byte)array[bit/8] & (0x80 >> (bit%8)))>0;
	}
	
	public static void setBit(byte[] array, int bit){
		array[bit/8] |= (0x80 >> (bit%8));  
	}
	
	public static void clearBit(byte[] array, int bit){
		array[bit/8] &= ~(0x80 >> (bit%8));
	}
	
	public static void xorArray(byte[] target, byte[] src){
		for (int i = 0; i < target.length; i++) {
			target[i] ^= src[i]; 
		}
	}
		
	public static void permute(byte[] target, byte[] src, int[] permuteTable){
		permute(target, 0, src, 0, permuteTable, 0, permuteTable.length);
	}
	
	public static void permute(byte[] target, int targetOffset, byte[] src, int srcOffset, int[] permuteTable, int permuteOffset, int permuteLength){
		for (int i=permuteOffset; i < permuteLength; i++){
			if (getBit(src, permuteTable[i]-1+(srcOffset*8))){
				setBit(target, i+targetOffset*8);
			} else {
				clearBit(target, i+targetOffset*8);
			}
		}
	}
	
	public static void leftRotation(byte[] target){
		int carryLeft,carryRight;
		
		carryLeft = (target[0] & 0x80) >> 3;
		target[0] = (byte)(((target[0]&0xFF) << 1) | ((target[1] & 0x80) >> 7));
		target[1] = (byte)(((target[1]&0xFF) << 1) | ((target[2] & 0x80) >> 7));
		target[2] = (byte)(((target[2]&0xFF) << 1) | ((target[3] & 0x80) >> 7));
		
		carryRight = (target[3] & 0x08) >> 3;
		target[3] =  (byte)(((((target[3]&0xFF)<<1) | ((target[4]&0x80)>>7))&~0x10) | carryLeft);
		
		target[4] = (byte)(((target[4]&0xFF)<<1) | ((target[5]&0x80)>>7));
		target[5] = (byte)(((target[5]&0xFF)<<1) | ((target[6]&0x80)>>7));
		target[6] = (byte)(((target[6]&0xFF)<<1) | carryRight);
	}
	
	public static void rightRotation(byte[] target){
		int carryLeft,carryRight;
		
		carryRight = (target[6] & 0x01) << 3;
		target[6] = (byte)(((target[6]&0xFF) >> 1) | ((target[5] & 0x01) << 7));
		target[5] = (byte)(((target[5]&0xFF) >> 1) | ((target[4] & 0x01) << 7));
		target[4] = (byte)(((target[4]&0xFF) >> 1) | ((target[3] & 0x01) << 7));
		
		carryLeft = (target[3] & 0x10) << 3;
		target[3] = (byte)(((((target[3]&0xFF)>>1) | ((target[2]&0x01)<<7))&~0x08) | carryRight);
		
		target[2] = (byte)(((target[2]&0xFF)>>1) | ((target[1]&0x01)<<7));
		target[1] = (byte)(((target[1]&0xFF)>>1) | ((target[0]&0x01)<<7));
		target[0] = (byte)(((target[0]&0xFF)>>1) | carryLeft);
	}
}
