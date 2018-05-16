package mytlsimp.hash;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public abstract class Digest {
	private byte[] tmp;
	private int tmpLength;
	private int[] hash;
	private int totalLength;
	
	public static Digest factory(String algorithm){
		if ("MD5".equals(algorithm)){
			return new MD5Digest();
		} else if ("SHA1".equals(algorithm)){
			return new SHA1Digest();
		} else if ("SHA256".equals(algorithm)){
			return new SHA256Digest();
		}
		
		return null;
	}
	
	public void updateHash(byte[] input){
		if (tmp==null){
			tmp = new byte[64];
			tmpLength = 0;
			totalLength = 0;
			
			hash = init();
		}
		totalLength+=input.length;
		
		int inputLength = input.length;
		
		while (inputLength+tmpLength >= tmp.length){
			System.arraycopy(input, input.length-inputLength, tmp, tmpLength, tmp.length-tmpLength);
			update(tmp, hash);				
			inputLength-=(tmp.length-tmpLength);
			
			tmpLength = 0;
		}
		if (inputLength>0){
			System.arraycopy(input, input.length-inputLength, tmp, tmpLength, inputLength);
			tmpLength = inputLength;
		}
	}
	
	public String finalizeHash(){
		Arrays.fill(tmp, tmpLength, tmp.length, (byte)0);
		tmp[tmpLength] = (byte)0x80;
		if (tmpLength>=56){
			update(tmp, hash);
			Arrays.fill(tmp, (byte)0);
		}
				
		String ret = finalize(tmp, hash, totalLength);
		tmp = null;
		
		return ret;
	}
	
	public String hash(InputStream is) throws IOException{
		String ret = null;
	
		int totalLength = 0;
		int[] hash = init();
			
		byte[] b = new byte[64];		
		while (is.available()>=64){
			is.read(b);
			totalLength += 64;
			update(b, hash);
		}
			
		int avail = is.available();
		totalLength += avail;
			
		Arrays.fill(b, (byte)0);
		is.read(b, 0, avail);
		b[avail] = (byte)0x80;
		if (avail>=56){
			update(b, hash);
			Arrays.fill(b, (byte)0);	
		}
				
		ret = finalize(b, hash, totalLength);		
		is.close();
				
		return ret;
	}
	
	public String hash(byte[] input) throws IOException{
		return hash(new ByteArrayInputStream(input));
	}
	
	protected abstract int[] init();
	
	protected abstract void update(byte[] input, int[] hash);
	
	protected abstract String finalize(byte[] input, int[] hash, int totalLength);
	
	public static void main(String[] args) throws Exception{
		Map<String, String> testsMD5 = new HashMap<String, String>();
		testsMD5.put("","d41d8cd98f00b204e9800998ecf8427e");
		testsMD5.put("a","0cc175b9c0f1b6a831c399e269772661");
		testsMD5.put("abc","900150983cd24fb0d6963f7d28e17f72");
		testsMD5.put("message digest","f96b697d7cb7938d525a2f31aaf161d0");
		testsMD5.put("abcdefghijklmnopqrstuvwxyz","c3fcd3d76192e4007dfb496cca67e13b");
		testsMD5.put("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789","d174ab98d277d9f5a5611c2c9f419d9f");
		testsMD5.put("12345678901234567890123456789012345678901234567890123456789012345678901234567890","57edf4a22be3c955ac49da2e2107b67a");
		testsMD5.put("12345678901234567890123456789012345678901234567890123456789","0B9619419451AACDBA0001592FCA361C".toLowerCase());
		testsMD5.put("foobad","6ce0d31e08fc3c4de8e3b2fa0d3d72ff");
		
		for (String str : testsMD5.keySet()) {
			System.out.println(str);
			System.out.println(Digest.factory("MD5").hash(str.getBytes()));
			System.out.println(Digest.factory("MD5").hash(new ByteArrayInputStream(str.getBytes())));
			System.out.println(testsMD5.get(str));

			System.out.println();
		}

		System.out.println(Digest.factory("MD5").hash(new FileInputStream("c:\\install.exe")));
		
		Map<String, String> testsSHA1 = new HashMap<String, String>();
		testsSHA1.put("","da39a3ee5e6b4b0d3255bfef95601890afd80709");
		testsSHA1.put("a","86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
		testsSHA1.put("abc","a9993e364706816aba3e25717850c26c9cd0d89d");
		testsSHA1.put("message digest","c12252ceda8be8994d5fa0290a47231c1d16aae3");
		testsSHA1.put("abcdefghijklmnopqrstuvwxyz","32d10c7b8cf96570ca04ce37f2a19d84240d3a89");
		testsSHA1.put("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789","761c457bf73b14d27e9e9265c46f4b4dda11f940");
		testsSHA1.put("12345678901234567890123456789012345678901234567890123456789012345678901234567890","50abf5706a150990a08b2c5ea40fa0e585554732");
		testsSHA1.put("12345678901234567890123456789012345678901234567890123456789","b9bb1e4e23ff5abdd2443687d2c61747d9255ebc");
		testsSHA1.put("foobad","a5f83415bde2761572611e34904b6bb0eb882830");
		
		for (String str : testsSHA1.keySet()) {
			System.out.println(str);
			System.out.println(Digest.factory("SHA1").hash(str.getBytes()));
			System.out.println(Digest.factory("SHA1").hash(new ByteArrayInputStream(str.getBytes())));
			System.out.println(testsSHA1.get(str));

			System.out.println();
		}
		
		System.out.println(Digest.factory("SHA1").hash(new FileInputStream("c:\\install.exe")));
		
		Map<String, String> testsSHA256 = new HashMap<String, String>();
		testsSHA256.put("","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		testsSHA256.put("a","ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
		testsSHA256.put("abc","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
		testsSHA256.put("message digest","f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
		testsSHA256.put("abcdefghijklmnopqrstuvwxyz","71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73");
		testsSHA256.put("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789","db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0");
		testsSHA256.put("12345678901234567890123456789012345678901234567890123456789012345678901234567890","f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e");
		testsSHA256.put("12345678901234567890123456789012345678901234567890123456789","645683fa1b5b5a3496049dd04ae8cb825cadfad9b0dc2f4c03b3bf2d461264bc");
		testsSHA256.put("foobad","ec1006c62daf5d08d08c003864fc1f57076ad766666d89605c6d0689b46c0e81");
		
		for (String str : testsSHA256.keySet()) {
			System.out.println(str);
			System.out.println(Digest.factory("SHA256").hash(str.getBytes()));
			System.out.println(Digest.factory("SHA256").hash(new ByteArrayInputStream(str.getBytes())));
			System.out.println(testsSHA256.get(str));

			System.out.println();
		}
		
		System.out.println(Digest.factory("SHA256").hash(new FileInputStream("c:\\install.exe")));	
		
		
		byte[] b = new byte[64];
		for (int i=0; i<b.length; i++){
			b[i] = (byte)i;
		}
					
		Digest d = Digest.factory("MD5");
		d.updateHash(Arrays.copyOfRange(b, 0, 64));
		//d.updateHash(Arrays.copyOfRange(b, 50, 150));
		//d.updateHash(Arrays.copyOfRange(b, 150, 256));
		System.out.println(d.finalizeHash());
		
		System.out.println(d.hash(b));
	}
}
