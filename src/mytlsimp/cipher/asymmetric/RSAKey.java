package mytlsimp.cipher.asymmetric;

import mytlsimp.util.Huge;

public class RSAKey {
	private Huge modolus;
	private Huge exponent;
	
	public RSAKey() {
		modolus = new Huge();
		exponent = new Huge();
	}
	
	public RSAKey(Huge modolus, Huge exponent){
		this.modolus = modolus;
		this.exponent = exponent;
	}
	
	public Huge getModolus(){
		return modolus;
	}
	
	public void setModolus(Huge modolus){
		this.modolus = modolus;
	}
	
	public Huge getExponent(){
		return exponent;
	}
	
	public void setExponent(Huge exponent){
		this.exponent = exponent;
	}
}
