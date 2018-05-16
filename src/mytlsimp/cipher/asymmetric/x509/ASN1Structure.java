package mytlsimp.cipher.asymmetric.x509;

public class ASN1Structure {
	private boolean constructed;  // bit 6 of the identifier byte
	private int tagClass;   // bits 7-8 of the identifier byte
	private int tag;      // bits 1-5 of the identifier byte
	private int length;
	private byte[] data;
	private ASN1Structure children;
	private ASN1Structure next;
	
	public boolean getConstructed(){
		return constructed;
	}
	
	public void setConstructed(boolean constructed){
		this.constructed = constructed;
	}
	
	public int getTagClass(){
		return tagClass;
	}
	
	public void setTagClass(int tagClass){
		this.tagClass = tagClass;
	}
	
	public int getTag(){
		return tag;
	}
	
	public void setTag(int tag){
		this.tag = tag;
	}
	
	public int getLength(){
		return length;
	}
	
	public void setLength(int length){
		this.length = length;
	}
	
	public byte[] getData(){
		return data;
	}
	
	public void setData(byte[] data){
		this.data = data;
	}
	
	public ASN1Structure getChildren(){
		return children;
	}
	
	public void setChildren(ASN1Structure children){
		this.children = children;
	}
	
	public ASN1Structure getNext(){
		return next;
	}
	
	public void setNext(ASN1Structure next){
		this.next = next;
	}
}
