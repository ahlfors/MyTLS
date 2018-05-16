package mytlsimp.tls;

import java.security.SecureRandom;
import java.util.Date;

public class Random {
	private int gmtUnixTime;
	private byte[] randomBytes = new byte[28];
	
	public Random(){}
	
	public Random(boolean generate){
		if (generate){
			generateRandom();
		}
	}
	
	public int getGmtUnixTime(){
		return gmtUnixTime;
	}
	
	public void setGmtUnixTime(int gmtUnixTime){
		this.gmtUnixTime = gmtUnixTime;
	}
	
	public void setGmtUnixTime(byte b0, byte b1, byte b2, byte b3){
		gmtUnixTime = (b0<<24)|(b1<<16&0xFF0000)|(b2<<8&0xFF00)|b3&0xFF;
	}
	
	public byte[] getRandomBytes(){
		return randomBytes;
	}
	
	public void setRandomBytes(byte[] randomBytes){
		if (randomBytes!=null && randomBytes.length!=28){
			throw new IllegalArgumentException("Random bytes need to have length of 28");
		}
		
		this.randomBytes = randomBytes;
	}
	
	public void generateRandom(){
		int time = (int)(new Date().getTime()/1000);
		setGmtUnixTime(time);
		
		SecureRandom sr = new SecureRandom();
		byte[] b = new byte[28];
		sr.nextBytes(b);
		setRandomBytes(b);
	}
	
	public byte[] getFullRandomBytes(){
		byte[] b = new byte[32];
		
		int i=0;
		b[i++] = (byte)((gmtUnixTime&0xFF000000)>>>24);
		b[i++] = (byte)((gmtUnixTime&0xFF0000)>>>16);
		b[i++] = (byte)((gmtUnixTime&0xFF00)>>>8);
		b[i++] = (byte)(gmtUnixTime&0xFF);
		for (int j=0;j<randomBytes.length; j++){
			b[i++] = randomBytes[j];
		}
		
		return b;
	}
}
