package mytlsimp.tls;

import mytlsimp.tls.type.CipherSuiteEnum;

public class ProtectionParameters {
	 private byte[] MACSecret;
	 private byte[] key; 
	 private byte[] initialValue;
	 
	 private int sequence = 0;
	 private CipherSuiteEnum suite = CipherSuiteEnum.TLS_NULL_WITH_NULL_NULL;
	 
	 public byte[] getMACSecret(){
		 return MACSecret;
	 }
	 
	 public void setMACSecret(byte[] MACSecret){
		 this.MACSecret = MACSecret;
	 }
	 
	 public byte[] getKey(){
		 return key;
	 }
	 
	 public void setKey(byte[] key){
		 this.key = key;
	 }
	 
	 public byte[] getInitialValue(){
		 return initialValue;
	 }
	 
	 public void setInitialValue(byte[] initialValue){
		 this.initialValue = initialValue;
	 }
	 
	 public int getSequence(){
		 return sequence;
	 }
	 
	 public void setSequence(int sequence){
		 this.sequence = sequence;
	 }
	 
	 public CipherSuiteEnum getSuite(){
		 return suite;
	 }
	 
	 public void setSuite(CipherSuiteEnum suite){
		 this.suite = suite;
	 }
}
