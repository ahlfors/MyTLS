package mytlsimp.cipher.asymmetric.x509;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.Base64;

public class ASN1 {
	public static final int ASN1_CLASS_UNIVERSAL = 0;
	public static final int ASN1_CLASS_APPLICATION = 1;
	public static final int ASN1_CONTEXT_SPECIFIC = 2;
	public static final int ASN1_PRIVATE = 3;

	//private static final int ASN1_BER = 0;
	public static final int ASN1_BOOLEAN = 1;
	private static final int ASN1_INTEGER = 2;
	private static final int ASN1_BIT_STRING = 3;
	private static final int ASN1_OCTET_STRING = 4;
	//private static final int ASN1_NULL = 5;
	private static final int ASN1_OBJECT_IDENTIFIER = 6;
	//private static final int ASN1_OBJECT_DESCRIPTOR = 7;
	//private static final int ASN1_INSTANCE_OF_EXTERNAL = 8;
	//private static final int ASN1_REAL = 9;
	//private static final int ASN1_ENUMERATED = 10;
	//private static final int ASN1_EMBEDDED_PPV = 11;
	private static final int ASN1_UTF8_STRING = 12;
	//private static final int ASN1_RELATIVE_OID = 13;
	// 14 & 15 undefined
	//private static final int ASN1_SEQUENCE = 16;
	//private static final int ASN1_SET = 17;
	private static final int ASN1_NUMERIC_STRING = 18;
	private static final int ASN1_PRINTABLE_STRING = 19;
	private static final int ASN1_TELETEX_STRING = 20;
	//private static final int ASN1_T61_STRING = 20;
	private static final int ASN1_VIDEOTEX_STRING = 21;
	private static final int ASN1_IA5_STRING = 22;
	private static final int ASN1_UTC_TIME = 23;
	private static final int ASN1_GENERALIZED_TIME = 24;
	private static final int ASN1_GRAPHIC_STRING = 25;
	private static final int ASN1_VISIBLE_STRING = 26;
	//private static final int ASN1_ISO64_STRING = 26;
	private static final int ASN1_GENERAL_STRING = 27;
	private static final int ASN1_UNIVERSAL_STRING = 28;
	private static final int ASN1_CHARACTER_STRING = 29;
	private static final int ASN1_BMP_STRING = 30;
	
	private static final String TAG_NAMES[] = {
			 "BER",                        // 0
			 "BOOLEAN",                    // 1
			 "INTEGER",                    // 2
			 "BIT STRING",                 // 3
			 "OCTET STRING",               // 4
			 "NULL",                       // 5
			 "OBJECT IDENTIFIER",          // 6
			 "ObjectDescriptor",           // 7
			 "INSTANCE OF, EXTERNAL",      // 8
			 "REAL",                       // 9
			 "ENUMERATED",                 // 10
			 "EMBEDDED PPV",               // 11
			 "UTF8String",                 // 12
			 "RELATIVE-OID",               // 13
			 "undefined(14)",              // 14
			 "undefined(15)",              // 15
			 "SEQUENCE, SEQUENCE OF",      // 16
			 "SET, SET OF",                // 17
			 "NumericString",              // 18
			 "PrintableString",            // 19
			 "TeletexString, T61String",   // 20
			"VideotexString",              // 21
			 "IA5String",                  // 22
			 "UTCTime",                    // 23
			 "GeneralizedTime",            // 24
			 "GraphicString",              // 25
			 "VisibleString, ISO64String", // 26
			 "GeneralString",              // 27
			 "UniversalString",            // 28
			 "CHARACTER STRING",           // 29
			 "BMPString"                   // 30
			};
	
	public ASN1Structure parse(byte[] buffer){
		buffer = decodePEM(buffer);
		
		ASN1Structure topLevelToken = new ASN1Structure();
		if (buffer.length>0){			
			int offset = 0;			
			offset = getNode(buffer, offset, topLevelToken);
			offset = getLength(buffer, offset, topLevelToken);
			
			if (topLevelToken.getConstructed()){
				topLevelToken.setChildren(new ASN1Structure());
				
				processASN1(buffer, offset, topLevelToken.getLength(), topLevelToken.getChildren());
			} else {
				topLevelToken.setData(new byte[topLevelToken.getLength()]);
				for (int i=offset; i<offset+topLevelToken.getLength(); i++){
					topLevelToken.getData()[i-offset] = buffer[i];
				}
			}
		}
		
		return topLevelToken;
	}
	
	private int processASN1(byte[] buffer, int offset, int length, ASN1Structure node){
		ASN1Structure n = node;
		boolean stop = false;
		int initialOffset = offset;
		
		do {	
			offset = getNode(buffer, offset, n);
			offset = getLength(buffer, offset, n);	

			if (n.getConstructed()){								
				n.setData(new byte[n.getLength()+(offset-initialOffset)]);			
				for (int i=0; i<n.getData().length; i++){
					n.getData()[i] = buffer[i+initialOffset];
				}
				
				n.setChildren(new ASN1Structure());
				offset = processASN1(buffer, offset, n.getLength(), n.getChildren());
			} else {
				n.setData(new byte[n.getLength()]);			
				for (int i=0; i<n.getData().length; i++){
					n.getData()[i] = buffer[i+offset];
				}
				
				offset += n.getLength();
			}
			
			if (offset >= initialOffset+length){
				stop = true;				
			} else {
				n.setNext(new ASN1Structure());
				n = n.getNext();
			}
		} while (!stop);
		
		return offset;
	}
	
	private int getNode(byte[] b, int offset, ASN1Structure node){
		node.setConstructed((b[offset]&0x20)==0x20);
		node.setTagClass((b[offset]&0xFF)>>6);
		node.setTag((b[offset]&0xFF)&0x1F);
		
		return offset+1;
	}
	
	private int getLength(byte[] b, int offset, ASN1Structure node){
		int skip = 1;
		if ((b[offset]&0x80)==0x80){
			int n = (b[offset]&0x7F);
			int length = 0;
			for (int i=0; i<n; i++){
				length+=((b[offset+n-i]&0xFF)<<i*8);
			}
			node.setLength(length);
			skip = n+1;
		} else {
			node.setLength(b[offset]);
		}
		
		return offset+skip;
	}
	
	public void asn1Show(int depth, ASN1Structure certificate){
		ASN1Structure token = certificate;
		
		while (token!=null){
			for (int i=0; i<depth; i++){
				System.out.print("\t");
		    }
			switch (token.getTagClass()) {
				case ASN1_CLASS_UNIVERSAL:
					System.out.print(TAG_NAMES[token.getTag()]);
					break;
				case ASN1_CLASS_APPLICATION:
		        	System.out.print("application");
		        	break;
		      	case ASN1_CONTEXT_SPECIFIC:
		      		System.out.print("context");
		      		break;
		      	case ASN1_PRIVATE:
		      		System.out.print("private");
		      		break;
		    }
			System.out.printf(" (%d:%d) ", token.getTag(), token.getLength());
			if (token.getTagClass()==ASN1_CLASS_UNIVERSAL){
				switch (token.getTag()) {
					case ASN1_INTEGER:
						break;
					case ASN1_BIT_STRING:
			        case ASN1_OCTET_STRING:
			        case ASN1_OBJECT_IDENTIFIER:
			        	for (int i=0; i<token.getLength(); i++) {
			        		String t = Integer.toHexString((token.getData()[i]&0xFF));
			        		if (t.length()==1){
			        			t="0"+t;
			        		}
			        		System.out.printf("%s ", t.toUpperCase());
			        	}
			        	break;
			        case ASN1_NUMERIC_STRING:
			        case ASN1_PRINTABLE_STRING:
			        case ASN1_TELETEX_STRING:
			        case ASN1_VIDEOTEX_STRING:
			        case ASN1_IA5_STRING:
			        case ASN1_UTC_TIME:
			        case ASN1_GENERALIZED_TIME:
			        case ASN1_GRAPHIC_STRING:
			        case ASN1_VISIBLE_STRING:
			        case ASN1_GENERAL_STRING:
			        case ASN1_UNIVERSAL_STRING:
			        case ASN1_CHARACTER_STRING:
			        case ASN1_BMP_STRING:
			        case ASN1_UTF8_STRING:
		        		System.out.printf( " %s", new String(token.getData()));
			        	break;
			        default:
			        	break;
			    }
			}
			
			System.out.println();
			if (token.getChildren()!=null){
				asn1Show(depth+1, token.getChildren());
			}
			token = token.getNext();
		}
	}
	
	private static byte[] decodePEM(byte[] input){
		String pem = new String(input);
		pem = pem.replaceAll("\r", "").replaceAll("\n","");
		if (pem.startsWith("-----BEGIN CERTIFICATE-----") && pem.endsWith("-----END CERTIFICATE-----")){
			return Base64.getDecoder().decode(pem.substring(27, pem.length()-25));
		}
		return input;
	}
	
	public static void main(String[] args) throws Exception{
		File f = new File("c:\\output\\cert.der");
		BufferedInputStream br = new BufferedInputStream(new FileInputStream(f));
					
		//byte c[] = {0x30, (byte)0x0B, 0x30, 0x09, 0x02, 0x02, 0x01, 0x02, 0x02, 0x03, 0x03, 0x04, 0x05};		
		byte[] b = new byte[(int)f.length()];
		br.read(b);
		br.close();		
		
		ASN1Structure certificate = new ASN1().parse(b);
		new ASN1().asn1Show(0, certificate);
	}
}
