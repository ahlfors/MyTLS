package mytlsimp.cipher.asymmetric.x509;

public class Name {
	private String idAtCountryName;
	private String idAtStateOrProvinceName;
	private String idAtLocalityName;
	private String idAtOrganizationName;
	private String idAtOrganizationalUnitName;
	private String idAtCommonName;
	
	public String getIdAtCountryName(){
		return idAtCountryName;
	}
	
	public void setIdAtCountryName(String idAtCountryName){
		this.idAtCountryName = idAtCountryName;
	}
	
	public String getIdAtStateOrProvinceName(){
		return idAtStateOrProvinceName;
	}
	
	public void setIdAtStateOrProvinceName(String idAtStateOrProvinceName){
		this.idAtStateOrProvinceName = idAtStateOrProvinceName;
	}
	
	public String getIdAtLocalityName(){
		return idAtLocalityName;
	}
	
	public void setIdAtLocalityName(String idAtLocalityName){
		this.idAtLocalityName = idAtLocalityName;
	}
	
	public String getIdAtOrganizationName(){
		return idAtOrganizationName;
	}
	
	public void setIdAtOrganizationName(String idAtOrganizationName){
		this.idAtOrganizationName = idAtOrganizationName;
	}
	
	public String getIdAtOrganizationalUnitName(){
		return idAtOrganizationalUnitName;
	}
	
	public void setIdAtOrganizationalUnitName(String idAtOrganizationalUnitName){
		this.idAtOrganizationalUnitName = idAtOrganizationalUnitName;
	}
	
	public String getIdAtCommonName(){
		return idAtCommonName;
	}
	
	public void setIdAtCommonName(String idAtCommonName){
		this.idAtCommonName = idAtCommonName;
	}
}
