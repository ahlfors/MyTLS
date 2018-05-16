package mytlsimp.util;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class Huge {
	private boolean negative;
	private byte[] rep;
	
	public Huge(){}
	
	public Huge(long value){
		setHuge(value);
	}
	
	public Huge(byte[] rep){
		this.rep = rep;
		
		contract();
	}
	
	public Huge(byte[] rep, boolean contract){
		this.rep = rep;
		
		if (contract){
			contract();
		}
	}
	
	public void setRep(byte[] rep){
		this.rep = rep;
	}
	
	public byte[] getRep(){
		return rep;
	}
	
	public boolean getNegative(){
		return negative;
	}
	
	public void setNegative(boolean negative){
		this.negative = negative;
	}
	
	public void expand(){
		byte[] tmp = this.rep;
		this.rep = new byte[this.rep.length+1];
		
		System.arraycopy(tmp, 0, this.rep, 1, tmp.length);
		this.rep[0] = (byte)1;
	}
	
	public void contract(){
		int i = 0;
		while ((this.rep[i]==0) && (i<this.rep.length-1)) { i++; }

		 if ( i > 0 && i < this.rep.length) {
			 this.rep = Arrays.copyOfRange(this.rep, i, rep.length);
		 }
	}
	
	public void add(Huge h){
		boolean resultNegative;

		// First compute sign of result, then compute magnitude
		if (this.compare(h)>0){
			resultNegative = getNegative();

			if (getNegative()==h.getNegative()){
				this.addMagnitude(h);
			} else {
				this.subtractMagnitude(h);
			}
		} else  {
			Huge tmp = new Huge();
			
			//put h1 into tmp and h2 into h1 to swap the operands
			tmp.copyHuge(this);
			this.copyHuge(h);

			if (getNegative()==tmp.getNegative()) {
		     	resultNegative = h.getNegative();
		     	this.addMagnitude(tmp);
			} else {
				resultNegative = h.getNegative();
				this.subtractMagnitude(tmp);
			}
		}

		//Use the stored sign to set the result
		this.negative = resultNegative;
	}
	
	public void subtract(Huge h){
		boolean resultNegative;

		// First compute sign of result, then compute magnitude
		if (this.compare(h)>0) {
			resultNegative = this.getNegative();

			if (getNegative()==h.getNegative()) {
				this.subtractMagnitude(h);
			} else {
				this.addMagnitude(h);
			}
		} else {
			Huge tmp = new Huge();

			// put h1 into tmp and h2 into h1 to swap the operands
			tmp.copyHuge(this);
			this.copyHuge(h);

			if (getNegative()==tmp.getNegative()) {
				resultNegative = !getNegative();
				this.subtractMagnitude(tmp);
			} else {
				resultNegative = !(getNegative());
				this.addMagnitude(tmp);
			}
		}

		//@Use the stored sign to set the result
		negative = resultNegative;
	}
	
	private void addMagnitude(Huge h){
		int i, j;
		int sum;
		int carry = 0;
		
		if ( h.rep.length > this.rep.length){
			byte[] tmp = this.rep;
			this.rep = new byte[h.rep.length];
			
			System.arraycopy(tmp, 0, this.rep, h.rep.length-tmp.length, tmp.length);
		}
		
		i = this.rep.length;
		j = h.rep.length;
		
		do {
			i--;
			if (j > 0) {
				j--;
				sum = (rep[i]&0xFF) + (h.rep[j]&0xFF) + carry;
			} else {
				sum = (rep[i]&0xFF) + carry;
			}
			
			carry = (sum>0xFF?1:0);
			this.rep[i] = (byte)(sum&0xFF);
		} while (i > 0);
		
		if (carry>0){
			expand();
		}
	}
	
	private void subtractMagnitude(Huge h){
		h.contract();
		contract();
		
		int i = this.rep.length;
		int j = h.rep.length;
		int difference; // signed int - important!
		int borrow = 0;
		
		if (this.rep.length >= h.rep.length){
			do {
				i--;
			
				int tmp;
				if (j > 0){
					j--;
					tmp = (rep[i]&0xFF)-(h.rep[j]&0xFF) - borrow;
					difference = tmp>=0?tmp:(0x100+(this.rep[i]&0xFF)-(h.rep[j]&0xFF)-borrow);
				} else {
					tmp = this.rep[i]-borrow;
					difference = tmp>=0?tmp:(0x100+(this.rep[i]&0xFF)-borrow);				
				}
			
				borrow = (tmp<0?1:0);
				this.rep[i] = (byte)(difference);
			} while (i > 0);		
		} else {
			throw new IllegalArgumentException("subtraction result is negative");
		}
		
		if (borrow>0){
			throw new IllegalArgumentException("subtraction result is negative");
		}
		
		contract();
	}
	
	public void multiply(Huge h){
		byte mask;
		int i;
		Huge temp = new Huge();
		
		temp.copyHuge(this);		
		this.setHuge(0);
		
		boolean resultNegative = !(this.getNegative()==h.getNegative());
		
		i=h.rep.length;
		
		do {
			i--;
			for (mask = 0x01; (mask&0xFF)!=0; mask <<= 1){				
				if ((mask & h.rep[i]) != 0){					
					this.add(temp);
				}
				temp.leftShift();
			}
		 } while (i>0);
		
		negative = resultNegative;
	}
	
	public void copyHuge(Huge h){		
		this.rep = Arrays.copyOf(h.rep, h.rep.length);
		this.setNegative(h.getNegative());
	}
	
	private void setHuge(long value){
		if (value < 0){
			negative = true;
			value = -value;
		}
		
		long mask; 
		int i, shift;
			
		int length = 7;
			
		for (mask = 0x00FF000000000000l; mask > 0xFF; mask >>=8 ){
			if ((value & mask) > 0){
				break;
			}
			
			length--;
		}
			
		rep = new byte[length];
		mask = 0xFF;
		shift = 0;
		for (i=length; i>0; i--){
			rep[i-1] = (byte)((value & mask) >> shift);
			mask <<= 8;
			shift += 8;
		}
	}
	
	private void leftShift(){
		int i;
		int oldCarry, carry = 0;
		
		i = rep.length;
		do{
			i--;
			oldCarry = carry;
			carry = (rep[i]&0x80)==0x80?1:0;
			rep[i] = (byte)((((rep[i]&0xFF)<<1)|oldCarry)&0xFF);
		   // Again, if C exposed the overflow bit...
		}
		while (i > 0);
		
		if (carry>0){
			expand();
		}
	}
	
	public Huge divide(Huge divisor){
		Huge quotient = new Huge();
		int bitSize, bitPosition;
		
		bitSize = bitPosition = 0;
		while (divisor.compare(this)<0){
			divisor.leftShift();
			bitSize++;
		}
		
		quotient.negative = !(this.negative==divisor.negative);
		quotient.rep = new byte[(bitSize/8)+1];
		bitPosition = 8-(bitSize%8)-1;
		
		do {
			if (divisor.compare(this)<=0){
				this.subtractMagnitude(divisor);  // dividend -= divisor
				quotient.rep[(int)(bitPosition/8)] |= (0x80>>(bitPosition%8));
		   }

		   if (bitSize>0){
			   divisor.rightShift();
		   }
		   bitPosition++;
		} while (bitSize-->0);
		
		quotient.contract();
		return quotient;
	}
	
	public void inv(Huge h){
		Huge i, j, y2, y1, y, quotient, remainder, aTemp;
		i = new Huge(1);
		j = new Huge(1);
		remainder = new Huge(1);
		y = new Huge(1);
		
		aTemp = new Huge(1);
		
		y2 = new Huge(0);
		y1 = new Huge(1);

		i.copyHuge(h);
		j.copyHuge(this);
		
		if (this.negative) {
			j.divide(h);
			// force positive remainder always
			j.negative = false;
			j.subtract(h);
		}
		while (!((j.rep.length==1) && (j.rep[0]==0))) {
			remainder.copyHuge(i);
			i.copyHuge(j);
			quotient = remainder.divide(j);

			quotient.multiply(y1); // quotient = y1 * quotient
			y.copyHuge(y2);
			y.subtract(quotient);  // y = y2 - ( y1 * quotient )

			j.copyHuge(remainder);
			y2.copyHuge(y1);
			y1.copyHuge(y);
		}
		
		this.copyHuge(y2);
		aTemp.copyHuge(h);
		this.divide(aTemp);  // inv_z = y2 % a
		
		if (this.negative) {
			this.negative = false;
			this.subtract(aTemp);
			
			if (this.negative) {
				this.negative = false;
			}
		}
	}
	
	public int compare(Huge h){
		if (this.rep.length > h.rep.length){
			return 1;
		}

		if (this.rep.length < h.rep.length){
			return -1;
		}
		
		// Otherwise, sizes are equal, have to actually compare.
		// only have to compare "hi-int", since the lower ints
		// can't change the comparison.
		int i=0, j=0;
		
		// Otherwise, keep searching through the representational integers
		// until one is bigger than another - once we've found one, it's
		// safe to stop, since the "lower order bytes" can't affect the
		// comparison
		while (i<this.rep.length && j<h.rep.length){
			if ((rep[i]&0xFF)<(h.rep[j]&0xFF)) {
				return -1;
			} else if ((this.rep[i]&0xFF)>(h.rep[j]&0xFF)){
				return 1;
			}
			i++;
			j++;
		}
		
		// If we got all the way to the end without a comparison, the
		// two are equal
		return 0;
	}
	
	private void rightShift(){
		int i;
		int oldCarry, carry = 0;	

		i=0;
		do {
		   oldCarry = carry;
		   carry = ((this.rep[i]&0x01)<<7)&0xFF;
		   this.rep[i] = (byte)((((this.rep[i]&0xFF)>>1)|oldCarry)&0xFF);
		 } while (++i<this.rep.length);

		 this.contract();
	}
	
	public void exponentiate(Huge exp){
		int i = exp.rep.length, mask;
		Huge tmp1 = new Huge();
		Huge tmp2 = new Huge();
				
		tmp1.copyHuge(this);
		this.setHuge(1);
		
		do {
			i--;
			for (mask = 0x01; (mask&0xFF)!=0; mask <<= 1) {
				if ((exp.rep[i]&mask)!=0) {
					multiply(tmp1);
				}

				// Square tmp1
				tmp2.copyHuge(tmp1);
				tmp1.multiply(tmp2);
			}
		} while(i>0);
	}
	
	public static Huge modPow(Huge h, Huge exp, Huge n){
		Huge ret = new Huge(1);
		int i = exp.rep.length;
		byte mask;
		Huge tmp1 = new Huge();
		Huge tmp2 = new Huge();
		
		tmp1.copyHuge(h);
		
		do {
			i--;
			for (mask=0x01; mask!=0; mask<<=1) {
				if (((exp.rep[i]&0xFF)&mask)>0) {
					ret.multiply(tmp1);
					ret.divide(n);
				}
				// square tmp1
				tmp2.copyHuge(tmp1);
				tmp1.multiply(tmp2);
				tmp1.divide(n);
			}
		} while (i>0);
		
		return ret;		
	}
		
	public static void main(String[] args) {	
		for (int k = 0; k<1; k++){
			Random r = new Random();
			int i = r.nextInt(1000);
			int j = r.nextInt(1000);
			
			if (i<j){
				int tmp = i;
				i = j;
				j = tmp;
			}
			
			Huge h1 = new Huge(i);
			Huge h2 = new Huge(j);
			
			Huge h3 = new Huge((long)(i%j));
			h1.divide(h2);
			String s1 = BitOperator.getRadix16FromByteArray(h1.rep);
			String s2 = BitOperator.getRadix16FromByteArray(h3.rep);
			
			if (!s1.equals(s2)){
				System.out.println(i+","+j+","+s1+","+s2);
			}
			
		}

		int i1 = 300;
		int i2 = 100;
		int i3 = 17;
		Huge h1 = new Huge(i1);
		Huge h2 = new Huge(i2);
		Huge h3 = new Huge(i3);
		
		BigInteger b1 = new BigInteger(""+i1);
		BigInteger b2 = new BigInteger(""+i2);
		BigInteger b3 = new BigInteger(""+i3);
		
		
		//Huge h4 = new Huge((long)Math.pow(i1,i2)%i3);
		Huge h4 = new Huge((long)b1.modPow(b2, b3).intValue());
		
		h1.exponentiate(h2);
		h1.divide(h3);

		System.out.println((h1.getNegative()?"-":"")+BitOperator.getRadix16FromByteArray(h1.rep));
		System.out.println((h3.getNegative()?"-":"")+BitOperator.getRadix16FromByteArray(h4.rep));
		
		
		Huge hm = new Huge(BitOperator.getByteArrayFromRadix16("0202030405060708090a0b0c0d0e00616263646561626364656162636465616263646561626364656162636465616263646561626364656162636465616263"));
		Huge hex = new Huge(BitOperator.getByteArrayFromRadix16("010001"));
		Huge mod = new Huge(BitOperator.getByteArrayFromRadix16("c4f8e9e15dcadf2b96c763d981006a644ffb4415030a16ed1283883340f2aa0e2be2be8fa60150b9046965837c3e7d151b7de237ebb957c20663898250703b3f"));
		hm = Huge.modPow(hm, hex, mod);
		
		System.out.println(BitOperator.getRadix16FromByteArray(hm.getRep()));
	}
	
	public byte[] getByteArray(){
		byte[] ret = new byte[rep.length];
		for (int i = 0; i < ret.length; i++) {
			ret[i] = (byte)(rep[i]&0xFF);
		}
		
		return ret;
	}
}
