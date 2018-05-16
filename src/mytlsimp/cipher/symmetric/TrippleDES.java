package mytlsimp.cipher.symmetric;

import java.util.Arrays;

import mytlsimp.util.BitOperator;

public class TrippleDES extends DES{	
	private byte[] tripledesOperateCBC(byte[] input, byte[] iv, byte[] key, boolean encrypt, String mode){
		byte[] inputBlock = new byte[DES_BLOCK_SIZE];
		byte[] outputBlock = new byte[DES_BLOCK_SIZE];
		byte[] output = new byte[input.length];
		int i=0;
		
		byte[] key1 = null;
		byte[] key2 = null;
		byte[] key3 = null;
		
		key1 = Arrays.copyOfRange(key, 0, 8);
		key2 = Arrays.copyOfRange(key, 8, 16);
		key3 = Arrays.copyOfRange(key, 16, 24);
		
		if (input.length%DES_BLOCK_SIZE==0){	
			while (i < output.length) {
				inputBlock = Arrays.copyOfRange(input, i, i+DES_BLOCK_SIZE);
				
				if (encrypt){
					BitOperator.xorArray(inputBlock, iv); // implement CBC		
					outputBlock = desBlockOperate(inputBlock, key1, mode.charAt(0)=='E'?encrypt:!encrypt);
					outputBlock = desBlockOperate(outputBlock, key2, mode.charAt(1)=='E'?encrypt:!encrypt);
					outputBlock = desBlockOperate(outputBlock, key3, mode.charAt(2)=='E'?encrypt:!encrypt);
					
					for (int j=0;j < outputBlock.length; j++) {
						iv[j] = outputBlock[j];
						output[i++] = outputBlock[j];
					}					
				} else {
					outputBlock = desBlockOperate(inputBlock, key3, mode.charAt(2)=='E'?encrypt:!encrypt);
					outputBlock = desBlockOperate(outputBlock, key2, mode.charAt(1)=='E'?encrypt:!encrypt);
					outputBlock = desBlockOperate(outputBlock, key1, mode.charAt(0)=='E'?encrypt:!encrypt);					
					
					BitOperator.xorArray(outputBlock, iv); // implement CBC		
					iv = Arrays.copyOfRange(input, i, i+DES_BLOCK_SIZE);
					
					for (int j=0;j < outputBlock.length; j++) {
						output[i++] = outputBlock[j];
					}
				}				
			}
			
			return output;
		}
		
		return null;
	}
	
	@Override
	public byte[] encrypt(byte[] data, byte[] key, byte[] iv, String mode) {
		String mode1 = "";
		String mode2 = "";
		if (mode.contains("_")){
			mode1 = mode.split("_")[0];
			mode2 = mode.split("_")[1];
		}
		if ("CBC".equals(mode2)){
			return tripledesOperateCBC(data, iv, key, true, mode1);
		}
		
		return null;
	}
	
	@Override
	public byte[] decrypt(byte[] data, byte[] key, byte[] iv, String mode) {
		String mode1 = "";
		String mode2 = "";
		if (mode.contains("_")){
			mode1 = mode.split("_")[0];
			mode2 = mode.split("_")[1];
		}
		if ("CBC".equals(mode2)){
			return tripledesOperateCBC(data, iv, key, false, mode1);
		}
		
		return null;
	}
		
}
