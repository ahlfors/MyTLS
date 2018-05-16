package mytlsimp.cipher.asymmetric;

import java.util.Arrays;

import mytlsimp.util.BitOperator;
import mytlsimp.util.Huge;

public class RSA {
	private static void loadHuge(Huge h, byte[] bytes, int inputOffset, int length){
		int i = inputOffset;
		
		while (bytes[i]==(char)0){
			i++;
			length--;
		}
		
		byte[] tmp = new byte[length];
		System.arraycopy(bytes, i, tmp, 0, length);
		
		h.setRep(tmp);
	}
	
	private static void unloadHuge(Huge h, byte[] bytes, int offset, int length){
		System.arraycopy(h.getRep(), 0, bytes, offset+(length-h.getRep().length), h.getRep().length);		
	}
	
	public byte[] rsaEncrypt(byte[] input, RSAKey publicKey){
		byte[] output = new byte[0];
		
		int i;
		Huge c = new Huge();
		Huge m = new Huge();
		int modulusLength = publicKey.getModolus().getRep().length;
		int blockSize;
		byte[] paddedBlock = new byte[modulusLength];
		int encryptedSize = 0;
		int len = input.length;
		int inputOffset = 0;
		
		while (len>0) {
			encryptedSize += modulusLength;
			blockSize = (len < modulusLength-11)?len:(modulusLength-11);
			// set block type
			Arrays.fill(paddedBlock, (byte)0);
			System.arraycopy(input, inputOffset, paddedBlock, (modulusLength-blockSize), blockSize);

			paddedBlock[1] = 0x02;

			for (i=2; i<(modulusLength-blockSize-1); i++){
				// TODO make these random
				paddedBlock[i] = (byte)i;
			}
			loadHuge(m, paddedBlock, 0, paddedBlock.length);
			c = Huge.modPow(m, publicKey.getExponent(), publicKey.getModolus());

			byte[] tmp = new byte[encryptedSize];
			System.arraycopy(output, 0, tmp, 0, output.length);
			output = tmp;

			unloadHuge(c, output, (encryptedSize-modulusLength), modulusLength);

			len -= blockSize;
			inputOffset += blockSize;
		}		
		
		return output;
	}
	
	public byte[] rsaDecrypt(byte[] input, RSAKey privateKey){		
		int inputLength = input.length;
		int inputOffset = 0;
		int i, outputLength = 0;
		Huge c = new Huge();
		Huge m = new Huge();
		int modulusLength = privateKey.getModolus().getRep().length;
		
		byte[] paddedBlock = new byte[modulusLength];
		byte[] output = new byte[0];
		
		while (inputLength > 0){
			if (inputLength < modulusLength) {
				System.err.printf("Error - input must be an even multiple of key modulus %d (got %d)\n", privateKey.getModolus().getRep().length, inputLength);
				System.exit(-1);
			}
			
			loadHuge(c, input, inputOffset, modulusLength);
			m = Huge.modPow(c, privateKey.getExponent(), privateKey.getModolus());
			unloadHuge(m, paddedBlock, 0, modulusLength);
			
			if ((paddedBlock[1]&0xFF) > 0x02) {
				System.err.printf("Decryption error or unrecognized block type %d.\n", paddedBlock[1]);
				System.exit(-1);
			}
			
			// Find next 0 byte after the padding type byte; this signifies
			// start-of-data
			i = 2;
			while ((paddedBlock[i++]&0xFF) > 0);

			outputLength += modulusLength - i;
			
			byte[] tmp = new byte[outputLength];
			System.arraycopy(output, 0, tmp, 0, output.length);
			output = tmp;			
			System.arraycopy(paddedBlock, i, output, outputLength-(modulusLength-i), modulusLength-i);			

			inputLength -= modulusLength;
			inputOffset += modulusLength;
		}		
		
		return output;
	}
	
	public static void main(String[] args) {
		/*Huge e = new Huge(79);
		Huge d = new Huge(1019);
		Huge n = new Huge(3337);
		
		Huge m = new Huge(688);
		System.out.println(BitOperator.getRadix16FromCharArray(m.getRep()));
		Huge c = new RSA().rsaCompute(m, e, n);
		
		System.out.println(BitOperator.getRadix16FromCharArray(c.getRep()));
		
		c = new RSA().rsaCompute(c, d, n);
		System.out.println(BitOperator.getRadix16FromCharArray(c.getRep()));*/
		
		/*
		byte[] testModulus = {
				(byte)0xC4, (byte)0xF8, (byte)0xE9, (byte)0xE1, (byte)0x5D, (byte)0xCA, (byte)0xDF, (byte)0x2B,
				(byte)0x96, (byte)0xC7, (byte)0x63, (byte)0xD9, (byte)0x81, (byte)0x00, (byte)0x6A, (byte)0x64,
				(byte)0x4F, (byte)0xFB, (byte)0x44, (byte)0x15, (byte)0x03, (byte)0x0A, (byte)0x16, (byte)0xED,
				(byte)0x12, (byte)0x83, (byte)0x88, (byte)0x33, (byte)0x40, (byte)0xF2, (byte)0xAA, (byte)0x0E,
				(byte)0x2B, (byte)0xE2, (byte)0xBE, (byte)0x8F, (byte)0xA6, (byte)0x01, (byte)0x50, (byte)0xB9,
				(byte)0x04, (byte)0x69, (byte)0x65, (byte)0x83, (byte)0x7C, (byte)0x3E, (byte)0x7D, (byte)0x15,
				(byte)0x1B, (byte)0x7D, (byte)0xE2, (byte)0x37, (byte)0xEB, (byte)0xB9, (byte)0x57, (byte)0xC2,
				(byte)0x06, (byte)0x63, (byte)0x89, (byte)0x82, (byte)0x50, (byte)0x70, (byte)0x3B, (byte)0x3F
		};
		
		byte[] testPrivateKey = {
				(byte)0x8a, (byte)0x7e, (byte)0x79, (byte)0xf3, (byte)0xfb, (byte)0xfe, (byte)0xa8, (byte)0xeb,
				(byte)0xfd, (byte)0x18, (byte)0x35, (byte)0x1c, (byte)0xb9, (byte)0x97, (byte)0x91, (byte)0x36,
				(byte)0xf7, (byte)0x05, (byte)0xb4, (byte)0xd9, (byte)0x11, (byte)0x4a, (byte)0x06, (byte)0xd4,
				(byte)0xaa, (byte)0x2f, (byte)0xd1, (byte)0x94, (byte)0x38, (byte)0x16, (byte)0x67, (byte)0x7a,
				(byte)0x53, (byte)0x74, (byte)0x66, (byte)0x18, (byte)0x46, (byte)0xa3, (byte)0x0c, (byte)0x45,
				(byte)0xb3, (byte)0x0a, (byte)0x02, (byte)0x4b, (byte)0x4d, (byte)0x22, (byte)0xb1, (byte)0x5a,
				(byte)0xb3, (byte)0x23, (byte)0x62, (byte)0x2b, (byte)0x2d, (byte)0xe4, (byte)0x7b, (byte)0xa2,
				(byte)0x91, (byte)0x15, (byte)0xf0, (byte)0x6e, (byte)0xe4, (byte)0x2c, (byte)0x41
		};
		
		byte[] testPublicKey = {0x01, 0x00, 0x01};
		
		byte[] data = "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabc".getBytes();
		byte[] exponentEncrypt = testPublicKey;
		byte[] exponentDecrypt = testPrivateKey;
		byte[] modulus = testModulus;
		
		RSAKey publicKey = new RSAKey();
		RSAKey privateKey = new RSAKey();
		
				
		
		loadHuge(publicKey.getModolus(), modulus, 0, modulus.length);
		loadHuge(publicKey.getExponent(), exponentEncrypt, 0, exponentEncrypt.length);
		RSA rsa = new RSA();
		byte[] encrypted = rsa.rsaEncrypt(data, publicKey);
		System.out.println(BitOperator.getRadix16FromByteArray(encrypted));
		
		
		loadHuge(privateKey.getModolus(), modulus, 0, modulus.length);
		loadHuge(privateKey.getExponent(), exponentDecrypt, 0, exponentDecrypt.length);
		
		rsa = new RSA();
		byte[] decrypted = rsa.rsaDecrypt(encrypted, privateKey);
		System.out.println(new String(decrypted));
		
		System.out.println(new String(decrypted).equals(new String(data)));
		*/
		
		RSA rsa2 = new RSA();
		RSAKey key = new RSAKey();
		key.setExponent(new Huge(BitOperator.getByteArrayFromRadix16("010001")));
		key.setModolus(new Huge(BitOperator.getByteArrayFromRadix16("c9bda60a8764f6c9af281a722bde065537786b60d456616b08e67723074b7a273ced2bb01c9212f265026d92ded96ce8a73150cfd9f323ffc5625d9e6ac412e5")));
		
		byte[] pkcs7SignatureDecrypted = rsa2.rsaDecrypt(BitOperator.getByteArrayFromRadix16("13a0a4c09560a0d1692d68275e263fe31abd7da3066c6c19c27637413ae94fd663142b265d18eba10ea8c55435069afa171ec2a62970633f93bd39311e17a5e5"), key);
		System.out.println(BitOperator.getRadix16FromByteArray(pkcs7SignatureDecrypted));
		
	}
}

