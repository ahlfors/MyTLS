package mytlsimp.cipher.asymmetric.x509;

import java.time.LocalDateTime;

public class ValidityPeriod {
	private LocalDateTime notBefore;
	private LocalDateTime notAfter;
	
	public LocalDateTime getNotBefore(){
		return notBefore;
	}
	
	public void setNotBefore(LocalDateTime notBefore){
		this.notBefore = notBefore;
	}
	
	public LocalDateTime getNotAfter(){
		return notAfter; 
	}
	
	public void setNotAfter(LocalDateTime notAfter){
		this.notAfter = notAfter;
	}
}
