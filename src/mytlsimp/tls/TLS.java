package mytlsimp.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import mytlsimp.cipher.asymmetric.x509.SignedX509Certificate;
import mytlsimp.cipher.symmetric.AES;
import mytlsimp.cipher.symmetric.Cipher;
import mytlsimp.hash.Digest;
import mytlsimp.hash.HMAC;
import mytlsimp.tls.message.CertificateMessage;
import mytlsimp.tls.message.ChangeCipherSpecMessage;
import mytlsimp.tls.message.ClientHelloMessage;
import mytlsimp.tls.message.ClientKeyExchangeMessage;
import mytlsimp.tls.message.FinishedMessage;
import mytlsimp.tls.message.ServerHelloMessage;
import mytlsimp.tls.message.TLSHeader;
import mytlsimp.tls.message.TLSMessage;
import mytlsimp.tls.type.CipherSuiteEnum;
import mytlsimp.tls.type.CompressionMethodEnum;
import mytlsimp.util.BitOperator;

public class TLS {
	public static final int MASTER_SECRET_LENGTH = 48;
	
	private CipherSuiteEnum cipherSuite;
	private List<SignedX509Certificate> certificateChain;
	
	private Random clientRandom;
	private Random serverRandom;
	private byte[] premasterSecret;
	private byte[] masterSecret;
	private byte[] sessionId;
	
	private boolean sendParameterActive = false;
	private boolean receiveParameterActive = false;
	private ProtectionParameters sendParameters;
	private ProtectionParameters receiveParameters;
	
	private Digest md5Digest;
	private Digest sha1Digest;
		
		
	public List<SignedX509Certificate> getCertificateChain(){
		return certificateChain;
	}
	
	public CipherSuiteEnum getCipherSuite(){
		return cipherSuite;
	}
	
	public Random getClientRandom(){
		return clientRandom;
	}
	
	public Random getServerRandom(){
		return serverRandom;
	}
	
	public byte[] getMasterSecret(){
		return masterSecret;
	}
	
	public void tlsConnect(OutputStream os, InputStream is) throws IOException{
		md5Digest = Digest.factory("MD5");
		sha1Digest = Digest.factory("SHA1");
		
		sendHelloClient(os);
		TLSHeader helloServer = receiveTLSMessage(is);
		TLSMessage certificate = null;
		if (helloServer.getMessages().size()==1){
			certificate = receiveTLSMessage(is).getMessages().get(0);
		} else {
			certificate = helloServer.getMessages().get(1);
		}
		receiveTLSMessage(is); //HelloServerDone!
		
		cipherSuite = ((ServerHelloMessage)helloServer.getMessages().get(0)).getCipherSuite();
		serverRandom = ((ServerHelloMessage)helloServer.getMessages().get(0)).getRandom();
		sessionId = ((ServerHelloMessage)helloServer.getMessages().get(0)).getSessionId();
		certificateChain = ((CertificateMessage)certificate).getCertificateChain();
		
		sendClientKeyExchange(os);
		masterSecret = computeMasterSecreat(premasterSecret, clientRandom, serverRandom);
		calculateKeys();
		sendChangeCipherSpec(os);
		sendFinished(os);
		
		TLSHeader m = receiveTLSMessage(is);
		if (m.getMessageType().equals(TLSHeaderTypeEnum.CHANGE_CIPHER_SPEC)){
			receiveParameters.setSequence(0);
			receiveParameterActive = true;
		}
	}
	
	private void sendFinished(OutputStream os) throws IOException{
		byte[] verifyData = computeVerifyData();
		FinishedMessage finished = new FinishedMessage(verifyData);	
		
		TLSHeader message = new TLSHeader(TLSHeaderTypeEnum.TLS_HANDSHAKE);
		message.setVersion(new ProtocolVersion());
		List<TLSMessage> messages = new ArrayList<TLSMessage>();
		messages.add(finished);
		message.setMessages(messages);
		
		sendTLSMessage(message, os);
	}
	
	private byte[] computeVerifyData() throws IOException{
		byte[] md5 = BitOperator.getByteArrayFromRadix16(md5Digest.finalizeHash());
		byte[] sha1 = BitOperator.getByteArrayFromRadix16(sha1Digest.finalizeHash());
		
		byte[] handshakeHash = new byte[md5.length+sha1.length];
		System.arraycopy(md5, 0, handshakeHash, 0, md5.length);
		System.arraycopy(sha1, 0, handshakeHash, md5.length, sha1.length);
		
		return prf(masterSecret, "client finished".getBytes(), handshakeHash, 12);
	}
	
	private TLSHeader receiveTLSMessage(InputStream is) throws IOException {
		byte[] tmp = new byte[5];
		is.read(tmp);
				
		int length = (tmp[3]<<8) + (tmp[4]&0xFF);
		
		byte[] b = new byte[length+5];
		System.arraycopy(tmp, 0, b, 0, tmp.length);
		is.read(b, tmp.length, length);
		
		if (TLSHeaderTypeEnum.valueOf(tmp[0]).equals(TLSHeaderTypeEnum.TLS_HANDSHAKE)){
			md5Digest.updateHash(Arrays.copyOfRange(b, tmp.length, b.length));
			sha1Digest.updateHash(Arrays.copyOfRange(b, tmp.length, b.length));
		}
		
		return TLSHeader.createMessage(b);
	}
	
	private void sendTLSMessage(TLSHeader message, OutputStream os) throws IOException{		
		byte[] b = message.getBytes();
		byte[] inner = Arrays.copyOfRange(b, 5, b.length); 
		if (message.getMessageType().equals(TLSHeaderTypeEnum.TLS_HANDSHAKE)){
			if (!sendParameterActive){
				md5Digest.updateHash(inner);
				sha1Digest.updateHash(inner);
			}
		}
		
		byte[] mac = new byte[0];
		CipherSuiteEnum activeSuite = null;
		if (sendParameterActive && sendParameters!=null){
			activeSuite = sendParameters.getSuite();	
		}
		
		
		if (activeSuite != null && activeSuite.getDigest()!=null){
			byte[] macBuffer = new byte[8+b.length];
			int sequence = sendParameters.getSequence();
			
			macBuffer[4] = (byte)((sequence&0xFF000000)>>>24);
			macBuffer[5] = (byte)((sequence&0xFF0000)>>>16);
			macBuffer[6] = (byte)((sequence&0xFF00)>>>8);
			macBuffer[7] = (byte)(sequence&0xFF);
			System.arraycopy(b, 0, macBuffer, 8, b.length);
			mac = BitOperator.getByteArrayFromRadix16(new HMAC().hmac(activeSuite.getDigest(), sendParameters.getMACSecret(), macBuffer));
			
			inner = Arrays.copyOf(inner, inner.length+mac.length);
			
			System.arraycopy(mac, 0, inner, inner.length-mac.length, mac.length);
			
			sendParameters.setSequence(sendParameters.getSequence()+1);
		}
				
		int paddingLength = 0;
		if (activeSuite != null && activeSuite.getBlockSize()>0){
			paddingLength = activeSuite.getBlockSize() - inner.length%activeSuite.getBlockSize();
			
			inner = Arrays.copyOf(inner, inner.length+paddingLength);
			Arrays.fill(inner, inner.length-paddingLength, inner.length, (byte)(paddingLength-1));
			System.out.println(BitOperator.getRadix16FromByteArray(inner));
			inner = Cipher.getInstance(activeSuite.getCipher()).encrypt(inner, sendParameters.getKey(), sendParameters.getInitialValue(), activeSuite.getMode());
			System.out.println(BitOperator.getRadix16FromByteArray(inner));
		}		
		
			
		byte[] sendBuffer = new byte[inner.length+5];
		sendBuffer[0] = b[0];
		sendBuffer[1] = b[1];
		sendBuffer[2] = b[2];		
		sendBuffer[3] = (byte)((inner.length&0xFF00)>>>8);
		sendBuffer[4] = (byte)(inner.length&0xFF);			
		System.arraycopy(inner, 0, sendBuffer, 5, inner.length);

		os.write(sendBuffer);
		os.flush();
	}
	
	private void sendHelloClient(OutputStream os) throws IOException{
		ClientHelloMessage hello = new ClientHelloMessage();		
		hello.setVersion(new ProtocolVersion((byte)3, (byte)1));
		List<CipherSuiteEnum> cipherSuites = new ArrayList<CipherSuiteEnum>();
		cipherSuites.add(CipherSuiteEnum.TLS_RSA_WITH_AES_128_CBC_SHA);
		cipherSuites.add(CipherSuiteEnum.TLS_RSA_WITH_AES_128_CBC_SHA256);
		cipherSuites.add(CipherSuiteEnum.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
		
		hello.generateRandom();
		clientRandom = hello.getRandom();
		hello.setCipherSuites(cipherSuites);
		List<CompressionMethodEnum> compressionMethods = new ArrayList<CompressionMethodEnum>();
		compressionMethods.add(CompressionMethodEnum.NO_COMPRESSION);
		hello.setCompressionMethods(compressionMethods);
		
		TLSHeader message = new TLSHeader(TLSHeaderTypeEnum.TLS_HANDSHAKE);
		message.setVersion(new ProtocolVersion());
		List<TLSMessage> messages = new ArrayList<TLSMessage>();
		messages.add(hello);
		message.setMessages(messages);

		sendTLSMessage(message, os);
	}
	
	
	private void sendClientKeyExchange(OutputStream os) throws IOException{
		ClientKeyExchangeMessage clientKey = new ClientKeyExchangeMessage();		
		clientKey.generateForRSA(certificateChain.get(0).getTbsCertificate().getSubjectPublicKeyInfo().getRSAPublicKey());
		premasterSecret = clientKey.getPremasterSecret();
		
		TLSHeader message = new TLSHeader(TLSHeaderTypeEnum.TLS_HANDSHAKE);
		message.setVersion(new ProtocolVersion());
		List<TLSMessage> messages = new ArrayList<TLSMessage>();
		messages.add(clientKey);
		message.setMessages(messages);
		
		sendTLSMessage(message, os);
	}
	
	private void sendChangeCipherSpec(OutputStream os) throws IOException{
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
		
		TLSHeader message = new TLSHeader(TLSHeaderTypeEnum.CHANGE_CIPHER_SPEC);
		message.setVersion(new ProtocolVersion());
		List<TLSMessage> messages = new ArrayList<TLSMessage>();
		messages.add(changeCipherSpecMessage);
		message.setMessages(messages);
		
		sendTLSMessage(message, os);
		
		sendParameters.setSequence(0);
		sendParameterActive = true;
	}
	
	private static byte[] pHash(String digestAlgorithm, byte[] secret, byte[] seed, int outputLength) throws IOException{
		byte[] output = new byte[outputLength];
		int i=0;
		
		//hmac( secret, secret_len, seed, seed_len, &A_ctx );
		HMAC hmac = new HMAC();
		String aStr = "";
		String outStr;
		byte[] originalSeed = seed;
		
		
		while (i<outputLength){
			aStr = hmac.hmac(digestAlgorithm, secret, seed);
			byte[] aStrBytes = BitOperator.getByteArrayFromRadix16(aStr);
			byte[] a = new byte[aStrBytes.length+originalSeed.length];
			
			System.arraycopy(aStrBytes, 0, a, 0, aStrBytes.length);
			System.arraycopy(originalSeed, 0, a, aStrBytes.length, originalSeed.length);
			
			outStr = hmac.hmac(digestAlgorithm, secret, a);
			byte[] outStrBytes = BitOperator.getByteArrayFromRadix16(outStr);
			System.arraycopy(outStrBytes, 0, output, i, outputLength<i+outStrBytes.length?outputLength-i:outStrBytes.length);
			i += outputLength<i+outStrBytes.length?outputLength-i:outStrBytes.length;
			seed = aStrBytes;
		}		
		
		return output;
	}
	
	private static byte[] prf(byte[] secret, byte[] label, byte[] seed, int outputLength) throws IOException{
		int halfSecretLength;
		
		byte[] concat = new byte[label.length+seed.length];
		System.arraycopy(label, 0, concat, 0, label.length);
		System.arraycopy(seed, 0, concat, label.length, seed.length);	
		halfSecretLength = (secret.length/2) + (secret.length%2);
		byte[] firstSecret = new byte[halfSecretLength];
		byte[] secondSecret = new byte[halfSecretLength];
		System.arraycopy(secret, 0, firstSecret, 0, halfSecretLength);
		System.arraycopy(secret, secret.length/2, secondSecret, 0, halfSecretLength);
		
		byte[] pMD5 = pHash("MD5", firstSecret, concat, outputLength);
		byte[] pSHA1 = pHash("SHA1", secondSecret, concat, outputLength);
		
		byte[] output = new byte[outputLength];
		for (int i = 0; i < outputLength; i++) {
			output[i] = (byte)(pMD5[i]^pSHA1[i]);
		}
		
		return output;
	}
	
	private byte[] computeMasterSecreat(byte[] premasterSecret, Random clientRandom, Random serverRandom) throws IOException{
		String label = "master secret";
		byte[] clientRandomBytes = clientRandom.getFullRandomBytes();
		byte[] serverRandomBytes = serverRandom.getFullRandomBytes();
		byte[] seed = new byte[clientRandomBytes.length+serverRandomBytes.length];
		System.arraycopy(clientRandomBytes, 0, seed, 0, clientRandomBytes.length);
		System.arraycopy(serverRandomBytes, 0, seed, clientRandomBytes.length, serverRandomBytes.length);
		
		return prf(premasterSecret, label.getBytes(), seed, MASTER_SECRET_LENGTH); 
	}
	
	private void calculateKeys() throws IOException{
		sendParameters = new ProtectionParameters();
		receiveParameters = new ProtectionParameters();
		
		sendParameters.setSuite(cipherSuite);
		
		String label = "key expansion";
		int keyBlockLength = cipherSuite.getHashSize()*2 
				+ cipherSuite.getKeySize()*2 
				+ cipherSuite.getIvSize()*2;
		
		byte[] serverBytes = serverRandom.getFullRandomBytes();
		byte[] clientBytes = clientRandom.getFullRandomBytes();
		
		byte[] seed = new byte[serverBytes.length+clientBytes.length];
		System.arraycopy(serverBytes, 0, seed, 0, serverBytes.length);
		System.arraycopy(clientBytes, 0, seed, serverBytes.length, clientBytes.length);
		
		byte[] keyBlock = prf(masterSecret, label.getBytes(), seed, keyBlockLength);
		int i=0;
		sendParameters.setMACSecret(Arrays.copyOfRange(keyBlock, i, i+=cipherSuite.getHashSize()));
		receiveParameters.setMACSecret(Arrays.copyOfRange(keyBlock, i, i+=cipherSuite.getHashSize()));
		sendParameters.setKey(Arrays.copyOfRange(keyBlock, i, i+=cipherSuite.getKeySize()));
		receiveParameters.setKey(Arrays.copyOfRange(keyBlock, i, i+=cipherSuite.getKeySize()));
		sendParameters.setInitialValue(Arrays.copyOfRange(keyBlock, i, i+=cipherSuite.getIvSize()));
		receiveParameters.setInitialValue(Arrays.copyOfRange(keyBlock, i, i+=cipherSuite.getIvSize()));
	}
	
	public static void main(String[] args) throws Exception{
		/*byte c[] = pHash("SHA1", "cd".getBytes(), "efghijkl".getBytes(), 40);
		byte b[] = pHash("MD5", "ab".getBytes(), "efghijkl".getBytes(), 40);
		byte d[] = new byte[40];
		for (int i = 0; i < d.length; i++) {
			d[i] = (byte)(b[i]^c[i]);
		}
		
		
		byte b[] = {
				(byte)0x01, (byte)0x00, (byte)0x00, (byte)0x77, (byte)0x03, (byte)0x01, (byte)0xe8, (byte)0xd4, (byte)0x9b, (byte)0x7d, (byte)0x0f, (byte)0x2a, (byte)0x93, (byte)0xbb, (byte)0x64, (byte)0x42,
				(byte)0xa2, (byte)0xe9, (byte)0xba, (byte)0xcf, (byte)0x81, (byte)0xe1, (byte)0xcc, (byte)0xf1, (byte)0x37, (byte)0x2a, (byte)0x10, (byte)0xf3, (byte)0x85, (byte)0x2c, (byte)0x12, (byte)0x8f,
				(byte)0x3e, (byte)0x96, (byte)0x1d, (byte)0x14, (byte)0xba, (byte)0x1c, (byte)0x00, (byte)0x00, (byte)0x2c, (byte)0xc0, (byte)0x0a, (byte)0xc0, (byte)0x14, (byte)0xc0, (byte)0x09, (byte)0xc0,
				(byte)0x13, (byte)0xc0, (byte)0x08, (byte)0xc0, (byte)0x12, (byte)0x00, (byte)0x35, (byte)0x00, (byte)0x84, (byte)0x00, (byte)0x2f, (byte)0x00, (byte)0x41, (byte)0x00, (byte)0x0a, (byte)0x00,
				(byte)0x39, (byte)0x00, (byte)0x38, (byte)0x00, (byte)0x88, (byte)0x00, (byte)0x87, (byte)0x00, (byte)0x33, (byte)0x00, (byte)0x32, (byte)0x00, (byte)0x45, (byte)0x00, (byte)0x44, (byte)0x00,
				(byte)0x16, (byte)0x00, (byte)0x13, (byte)0x00, (byte)0xff, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x22, (byte)0x00, (byte)0x0b, (byte)0x00, (byte)0x04, (byte)0x03, (byte)0x00, (byte)0x01,
				(byte)0x02, (byte)0x00, (byte)0x0a, (byte)0x00, (byte)0x0a, (byte)0x00, (byte)0x08, (byte)0x00, (byte)0x1d, (byte)0x00, (byte)0x17, (byte)0x00, (byte)0x19, (byte)0x00, (byte)0x18, (byte)0x00,
				(byte)0x23, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x16, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x17, (byte)0x00, (byte)0x00, 
				(byte)0x02, (byte)0x00, (byte)0x00, (byte)0x4d, (byte)0x03, (byte)0x01, (byte)0x5a, (byte)0xcd, (byte)0x75, (byte)0x43, (byte)0x7a, (byte)0x91, (byte)0x0f, (byte)0xfc, (byte)0xc9, (byte)0xbc,
				(byte)0x66, (byte)0xe0, (byte)0xf4, (byte)0x9c, (byte)0xbb, (byte)0xaf, (byte)0xad, (byte)0x69, (byte)0xc8, (byte)0xc9, (byte)0x1f, (byte)0x91, (byte)0x3e, (byte)0x53, (byte)0x36, (byte)0x51,
				(byte)0x47, (byte)0x35, (byte)0x48, (byte)0x2a, (byte)0x7b, (byte)0x4a, (byte)0x20, (byte)0x21, (byte)0xf5, (byte)0xe0, (byte)0x82, (byte)0x17, (byte)0x29, (byte)0x89, (byte)0x31, (byte)0x8a,
				(byte)0x87, (byte)0x64, (byte)0x54, (byte)0x6d, (byte)0xbb, (byte)0x0c, (byte)0xd2, (byte)0xc0, (byte)0x6a, (byte)0x26, (byte)0x95, (byte)0x76, (byte)0xae, (byte)0x79, (byte)0x79, (byte)0x08,
				(byte)0x08, (byte)0xf2, (byte)0x7e, (byte)0x97, (byte)0xa3, (byte)0x73, (byte)0xdb, (byte)0x00, (byte)0x2f, (byte)0x00, (byte)0x00, (byte)0x05, (byte)0xff, (byte)0x01, (byte)0x00, (byte)0x01,
				(byte)0x00,
				(byte)0x0b, (byte)0x00, (byte)0x05, (byte)0xc9, (byte)0x00, (byte)0x05, (byte)0xc6, (byte)0x00, (byte)0x05, (byte)0xc3, (byte)0x30, (byte)0x82, (byte)0x05, (byte)0xbf, (byte)0x30, (byte)0x82,
				(byte)0x04, (byte)0xa7, (byte)0xa0, (byte)0x03, (byte)0x02, (byte)0x01, (byte)0x02, (byte)0x02, (byte)0x11, (byte)0x00, (byte)0xd0, (byte)0x93, (byte)0x82, (byte)0xa1, (byte)0xa1, (byte)0x2e,
				(byte)0xe4, (byte)0x3d, (byte)0xe7, (byte)0xb9, (byte)0x86, (byte)0xb5, (byte)0x1f, (byte)0xab, (byte)0x1b, (byte)0x67, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86,
				(byte)0x48, (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x0b, (byte)0x05, (byte)0x00, (byte)0x30, (byte)0x81, (byte)0x86, (byte)0x31, (byte)0x0b, (byte)0x30, (byte)0x09,
				(byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02, (byte)0x55, (byte)0x53, (byte)0x31, (byte)0x0b, (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55,
				(byte)0x04, (byte)0x08, (byte)0x13, (byte)0x02, (byte)0x44, (byte)0x45, (byte)0x31, (byte)0x13, (byte)0x30, (byte)0x11, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x07, (byte)0x13,
				(byte)0x0a, (byte)0x57, (byte)0x69, (byte)0x6c, (byte)0x6d, (byte)0x69, (byte)0x6e, (byte)0x67, (byte)0x74, (byte)0x6f, (byte)0x6e, (byte)0x31, (byte)0x24, (byte)0x30, (byte)0x22, (byte)0x06,
				(byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x13, (byte)0x1b, (byte)0x43, (byte)0x6f, (byte)0x72, (byte)0x70, (byte)0x6f, (byte)0x72, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f,
				(byte)0x6e, (byte)0x20, (byte)0x53, (byte)0x65, (byte)0x72, (byte)0x76, (byte)0x69, (byte)0x63, (byte)0x65, (byte)0x20, (byte)0x43, (byte)0x6f, (byte)0x6d, (byte)0x70, (byte)0x61, (byte)0x6e,
				(byte)0x79, (byte)0x31, (byte)0x2f, (byte)0x30, (byte)0x2d, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x13, (byte)0x26, (byte)0x54, (byte)0x72, (byte)0x75, (byte)0x73,
				(byte)0x74, (byte)0x65, (byte)0x64, (byte)0x20, (byte)0x53, (byte)0x65, (byte)0x63, (byte)0x75, (byte)0x72, (byte)0x65, (byte)0x20, (byte)0x43, (byte)0x65, (byte)0x72, (byte)0x74, (byte)0x69,
				(byte)0x66, (byte)0x69, (byte)0x63, (byte)0x61, (byte)0x74, (byte)0x65, (byte)0x20, (byte)0x41, (byte)0x75, (byte)0x74, (byte)0x68, (byte)0x6f, (byte)0x72, (byte)0x69, (byte)0x74, (byte)0x79,
				(byte)0x20, (byte)0x35, (byte)0x30, (byte)0x1e, (byte)0x17, (byte)0x0d, (byte)0x31, (byte)0x38, (byte)0x30, (byte)0x33, (byte)0x30, (byte)0x31, (byte)0x30, (byte)0x30, (byte)0x30, (byte)0x30,
				(byte)0x30, (byte)0x30, (byte)0x5a, (byte)0x17, (byte)0x0d, (byte)0x31, (byte)0x39, (byte)0x30, (byte)0x33, (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x35, (byte)0x39, (byte)0x35,
				(byte)0x39, (byte)0x5a, (byte)0x30, (byte)0x81, (byte)0xd4, (byte)0x31, (byte)0x0b, (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02,
				(byte)0x44, (byte)0x45, (byte)0x31, (byte)0x0e, (byte)0x30, (byte)0x0c, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x11, (byte)0x13, (byte)0x05, (byte)0x38, (byte)0x30, (byte)0x33,
				(byte)0x33, (byte)0x35, (byte)0x31, (byte)0x10, (byte)0x30, (byte)0x0e, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x08, (byte)0x13, (byte)0x07, (byte)0x42, (byte)0x61, (byte)0x76,
				(byte)0x61, (byte)0x72, (byte)0x69, (byte)0x61, (byte)0x31, (byte)0x11, (byte)0x30, (byte)0x0f, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x07, (byte)0x13, (byte)0x08, (byte)0x4d,
				(byte)0x75, (byte)0x65, (byte)0x6e, (byte)0x63, (byte)0x68, (byte)0x65, (byte)0x6e, (byte)0x31, (byte)0x17, (byte)0x30, (byte)0x15, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x09,
				(byte)0x13, (byte)0x0e, (byte)0x4d, (byte)0x61, (byte)0x72, (byte)0x73, (byte)0x73, (byte)0x74, (byte)0x72, (byte)0x61, (byte)0x73, (byte)0x73, (byte)0x65, (byte)0x20, (byte)0x34, (byte)0x30,
				(byte)0x31, (byte)0x21, (byte)0x30, (byte)0x1f, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x13, (byte)0x18, (byte)0x54, (byte)0x72, (byte)0x69, (byte)0x75, (byte)0x6d,
				(byte)0x70, (byte)0x68, (byte)0x20, (byte)0x49, (byte)0x6e, (byte)0x74, (byte)0x65, (byte)0x72, (byte)0x6e, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x61, (byte)0x6c,
				(byte)0x20, (byte)0x41, (byte)0x47, (byte)0x31, (byte)0x15, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0b, (byte)0x13, (byte)0x0c, (byte)0x43, (byte)0x6f,
				(byte)0x72, (byte)0x70, (byte)0x6f, (byte)0x72, (byte)0x61, (byte)0x74, (byte)0x65, (byte)0x20, (byte)0x49, (byte)0x54, (byte)0x31, (byte)0x20, (byte)0x30, (byte)0x1e, (byte)0x06, (byte)0x03,
				(byte)0x55, (byte)0x04, (byte)0x0b, (byte)0x13, (byte)0x17, (byte)0x45, (byte)0x6e, (byte)0x74, (byte)0x65, (byte)0x72, (byte)0x70, (byte)0x72, (byte)0x69, (byte)0x73, (byte)0x65, (byte)0x20,
				(byte)0x53, (byte)0x53, (byte)0x4c, (byte)0x20, (byte)0x57, (byte)0x69, (byte)0x6c, (byte)0x64, (byte)0x63, (byte)0x61, (byte)0x72, (byte)0x64, (byte)0x31, (byte)0x1b, (byte)0x30, (byte)0x19,
				(byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x0c, (byte)0x12, (byte)0x2a, (byte)0x2e, (byte)0x74, (byte)0x72, (byte)0x69, (byte)0x75, (byte)0x6d, (byte)0x70, (byte)0x68,
				(byte)0x6a, (byte)0x61, (byte)0x70, (byte)0x61, (byte)0x6e, (byte)0x2e, (byte)0x63, (byte)0x6f, (byte)0x6d, (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x22, (byte)0x30, (byte)0x0d, (byte)0x06,
				(byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x00, (byte)0x03, (byte)0x82, (byte)0x01, (byte)0x0f,
				(byte)0x00, (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x0a, (byte)0x02, (byte)0x82, (byte)0x01, (byte)0x01, (byte)0x00, (byte)0xcc, (byte)0x24, (byte)0x08, (byte)0x18, (byte)0x8f, (byte)0xbf,
				(byte)0x8c, (byte)0xf9, (byte)0x0f, (byte)0xa8, (byte)0x3e, (byte)0x83, (byte)0x3b, (byte)0x12, (byte)0xbc, (byte)0x9d, (byte)0x47, (byte)0xc7, (byte)0x0b, (byte)0x55, (byte)0xb8, (byte)0x02,
				(byte)0x72, (byte)0xea, (byte)0x7d, (byte)0x3d, (byte)0xfd, (byte)0x28, (byte)0xd3, (byte)0xec, (byte)0x30, (byte)0x27, (byte)0xc6, (byte)0x2f, (byte)0xad, (byte)0x54, (byte)0x21, (byte)0xa0,
				(byte)0x2e, (byte)0x3c, (byte)0x0a, (byte)0x31, (byte)0x4b, (byte)0x54, (byte)0xfd, (byte)0x5c, (byte)0xea, (byte)0x73, (byte)0xf9, (byte)0x92, (byte)0x91, (byte)0x55, (byte)0xe6, (byte)0x08,
				(byte)0x7d, (byte)0x0c, (byte)0x63, (byte)0x38, (byte)0x6d, (byte)0x95, (byte)0x2f, (byte)0x18, (byte)0x04, (byte)0xad, (byte)0x31, (byte)0x3a, (byte)0x2c, (byte)0x25, (byte)0x02, (byte)0x7b,
				(byte)0x7e, (byte)0x95, (byte)0x7c, (byte)0x42, (byte)0xab, (byte)0x89, (byte)0x95, (byte)0x1f, (byte)0x1b, (byte)0x07, (byte)0x2e, (byte)0xda, (byte)0x1b, (byte)0xfd, (byte)0x60, (byte)0xfc,
				(byte)0x7e, (byte)0x1f, (byte)0xe2, (byte)0xc5, (byte)0x3c, (byte)0xf4, (byte)0xd2, (byte)0x62, (byte)0xcd, (byte)0x0a, (byte)0x41, (byte)0x81, (byte)0x4c, (byte)0xe0, (byte)0xdd, (byte)0x87,
				(byte)0xd5, (byte)0x77, (byte)0x00, (byte)0x72, (byte)0x63, (byte)0xc8, (byte)0x8f, (byte)0x3b, (byte)0x63, (byte)0xef, (byte)0x29, (byte)0x01, (byte)0x40, (byte)0x3d, (byte)0x27, (byte)0xae,
				(byte)0xd8, (byte)0x5b, (byte)0x45, (byte)0xe5, (byte)0x58, (byte)0x9a, (byte)0xbc, (byte)0x7c, (byte)0x7a, (byte)0xeb, (byte)0xe1, (byte)0x93, (byte)0x37, (byte)0xc1, (byte)0xa5, (byte)0x08,
				(byte)0x76, (byte)0x05, (byte)0xb7, (byte)0xd6, (byte)0x04, (byte)0x6f, (byte)0xa7, (byte)0xbc, (byte)0xc4, (byte)0x63, (byte)0x10, (byte)0x7a, (byte)0x4a, (byte)0x0f, (byte)0xcd, (byte)0x58,
				(byte)0xe1, (byte)0xb9, (byte)0x53, (byte)0xf4, (byte)0xaf, (byte)0x8c, (byte)0xb3, (byte)0xd2, (byte)0xa1, (byte)0xac, (byte)0x83, (byte)0xc7, (byte)0x1a, (byte)0xc9, (byte)0x22, (byte)0xb3,
				(byte)0xa0, (byte)0x74, (byte)0xb1, (byte)0x74, (byte)0xfd, (byte)0x08, (byte)0x75, (byte)0x76, (byte)0x8a, (byte)0x8f, (byte)0x80, (byte)0xc7, (byte)0x18, (byte)0xf1, (byte)0x75, (byte)0x5f,
				(byte)0x55, (byte)0xe7, (byte)0xb1, (byte)0x32, (byte)0x1a, (byte)0xd8, (byte)0x5c, (byte)0x5f, (byte)0x69, (byte)0xa8, (byte)0xc5, (byte)0x1c, (byte)0xf4, (byte)0xb5, (byte)0x7a, (byte)0x4e,
				(byte)0xb7, (byte)0xdf, (byte)0xa7, (byte)0x8f, (byte)0xba, (byte)0xf6, (byte)0x34, (byte)0x13, (byte)0xc9, (byte)0x6d, (byte)0x90, (byte)0x75, (byte)0xf7, (byte)0x64, (byte)0x28, (byte)0x77,
				(byte)0xef, (byte)0x5c, (byte)0x59, (byte)0x84, (byte)0xfa, (byte)0x9c, (byte)0x01, (byte)0x9e, (byte)0xf7, (byte)0xdd, (byte)0xce, (byte)0x84, (byte)0x10, (byte)0xfc, (byte)0xd0, (byte)0xe5,
				(byte)0x40, (byte)0x81, (byte)0x0f, (byte)0xf4, (byte)0x3f, (byte)0xaf, (byte)0xd0, (byte)0xfd, (byte)0xe8, (byte)0x24, (byte)0xd7, (byte)0x2b, (byte)0x74, (byte)0x55, (byte)0xdb, (byte)0x56,
				(byte)0x32, (byte)0x55, (byte)0x70, (byte)0xe5, (byte)0x51, (byte)0x93, (byte)0x33, (byte)0x75, (byte)0x03, (byte)0x9d, (byte)0x02, (byte)0x03, (byte)0x01, (byte)0x00, (byte)0x01, (byte)0xa3,
				(byte)0x82, (byte)0x01, (byte)0xd6, (byte)0x30, (byte)0x82, (byte)0x01, (byte)0xd2, (byte)0x30, (byte)0x1f, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x23, (byte)0x04, (byte)0x18,
				(byte)0x30, (byte)0x16, (byte)0x80, (byte)0x14, (byte)0xf2, (byte)0xbb, (byte)0x55, (byte)0xee, (byte)0xfc, (byte)0x8f, (byte)0xcf, (byte)0xd0, (byte)0x3f, (byte)0x14, (byte)0x68, (byte)0x1a,
				(byte)0x95, (byte)0x7e, (byte)0x79, (byte)0x0e, (byte)0xab, (byte)0x17, (byte)0x30, (byte)0xf4, (byte)0x30, (byte)0x1d, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x0e, (byte)0x04,
				(byte)0x16, (byte)0x04, (byte)0x14, (byte)0xee, (byte)0x72, (byte)0x1c, (byte)0xf9, (byte)0x43, (byte)0xc7, (byte)0x52, (byte)0x9c, (byte)0xad, (byte)0x12, (byte)0xcc, (byte)0x62, (byte)0x48,
				(byte)0x30, (byte)0x26, (byte)0xd4, (byte)0x0d, (byte)0x86, (byte)0xa3, (byte)0x29, (byte)0x30, (byte)0x0e, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x0f, (byte)0x01, (byte)0x01,
				(byte)0xff, (byte)0x04, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x05, (byte)0xa0, (byte)0x30, (byte)0x0c, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x13, (byte)0x01, (byte)0x01,
				(byte)0xff, (byte)0x04, (byte)0x02, (byte)0x30, (byte)0x00, (byte)0x30, (byte)0x1d, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x25, (byte)0x04, (byte)0x16, (byte)0x30, (byte)0x14,
				(byte)0x06, (byte)0x08, (byte)0x2b, (byte)0x06, (byte)0x01, (byte)0x05, (byte)0x05, (byte)0x07, (byte)0x03, (byte)0x01, (byte)0x06, (byte)0x08, (byte)0x2b, (byte)0x06, (byte)0x01, (byte)0x05,
				(byte)0x05, (byte)0x07, (byte)0x03, (byte)0x02, (byte)0x30, (byte)0x4b, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x20, (byte)0x04, (byte)0x44, (byte)0x30, (byte)0x42, (byte)0x30,
				(byte)0x36, (byte)0x06, (byte)0x0b, (byte)0x2b, (byte)0x06, (byte)0x01, (byte)0x04, (byte)0x01, (byte)0xb2, (byte)0x31, (byte)0x01, (byte)0x02, (byte)0x02, (byte)0x08, (byte)0x30, (byte)0x27,
				(byte)0x30, (byte)0x25, (byte)0x06, (byte)0x08, (byte)0x2b, (byte)0x06, (byte)0x01, (byte)0x05, (byte)0x05, (byte)0x07, (byte)0x02, (byte)0x01, (byte)0x16, (byte)0x19, (byte)0x68, (byte)0x74,
				(byte)0x74, (byte)0x70, (byte)0x73, (byte)0x3a, (byte)0x2f, (byte)0x2f, (byte)0x63, (byte)0x70, (byte)0x73, (byte)0x2e, (byte)0x75, (byte)0x73, (byte)0x65, (byte)0x72, (byte)0x74, (byte)0x72,
				(byte)0x75, (byte)0x73, (byte)0x74, (byte)0x2e, (byte)0x63, (byte)0x6f, (byte)0x6d, (byte)0x30, (byte)0x08, (byte)0x06, (byte)0x06, (byte)0x67, (byte)0x81, (byte)0x0c, (byte)0x01, (byte)0x02,
				(byte)0x02, (byte)0x30, (byte)0x50, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x1f, (byte)0x04, (byte)0x49, (byte)0x30, (byte)0x47, (byte)0x30, (byte)0x45, (byte)0xa0, (byte)0x43,
				(byte)0xa0, (byte)0x41, (byte)0x86, (byte)0x3f, (byte)0x68, (byte)0x74, (byte)0x74, (byte)0x70, (byte)0x3a, (byte)0x2f, (byte)0x2f, (byte)0x63, (byte)0x72, (byte)0x6c, (byte)0x2e, (byte)0x75,
				(byte)0x73, (byte)0x65, (byte)0x72, (byte)0x74, (byte)0x72, (byte)0x75, (byte)0x73, (byte)0x74, (byte)0x2e, (byte)0x63, (byte)0x6f, (byte)0x6d, (byte)0x2f, (byte)0x54, (byte)0x72, (byte)0x75,
				(byte)0x73, (byte)0x74, (byte)0x65, (byte)0x64, (byte)0x53, (byte)0x65, (byte)0x63, (byte)0x75, (byte)0x72, (byte)0x65, (byte)0x43, (byte)0x65, (byte)0x72, (byte)0x74, (byte)0x69, (byte)0x66,
				(byte)0x69, (byte)0x63, (byte)0x61, (byte)0x74, (byte)0x65, (byte)0x41, (byte)0x75, (byte)0x74, (byte)0x68, (byte)0x6f, (byte)0x72, (byte)0x69, (byte)0x74, (byte)0x79, (byte)0x35, (byte)0x2e,
				(byte)0x63, (byte)0x72, (byte)0x6c, (byte)0x30, (byte)0x81, (byte)0x82, (byte)0x06, (byte)0x08, (byte)0x2b, (byte)0x06, (byte)0x01, (byte)0x05, (byte)0x05, (byte)0x07, (byte)0x01, (byte)0x01,
				(byte)0x04, (byte)0x76, (byte)0x30, (byte)0x74, (byte)0x30, (byte)0x4b, (byte)0x06, (byte)0x08, (byte)0x2b, (byte)0x06, (byte)0x01, (byte)0x05, (byte)0x05, (byte)0x07, (byte)0x30, (byte)0x02,
				(byte)0x86, (byte)0x3f, (byte)0x68, (byte)0x74, (byte)0x74, (byte)0x70, (byte)0x3a, (byte)0x2f, (byte)0x2f, (byte)0x63, (byte)0x72, (byte)0x74, (byte)0x2e, (byte)0x75, (byte)0x73, (byte)0x65,
				(byte)0x72, (byte)0x74, (byte)0x72, (byte)0x75, (byte)0x73, (byte)0x74, (byte)0x2e, (byte)0x63, (byte)0x6f, (byte)0x6d, (byte)0x2f, (byte)0x54, (byte)0x72, (byte)0x75, (byte)0x73, (byte)0x74,
				(byte)0x65, (byte)0x64, (byte)0x53, (byte)0x65, (byte)0x63, (byte)0x75, (byte)0x72, (byte)0x65, (byte)0x43, (byte)0x65, (byte)0x72, (byte)0x74, (byte)0x69, (byte)0x66, (byte)0x69, (byte)0x63,
				(byte)0x61, (byte)0x74, (byte)0x65, (byte)0x41, (byte)0x75, (byte)0x74, (byte)0x68, (byte)0x6f, (byte)0x72, (byte)0x69, (byte)0x74, (byte)0x79, (byte)0x35, (byte)0x2e, (byte)0x63, (byte)0x72,
				(byte)0x74, (byte)0x30, (byte)0x25, (byte)0x06, (byte)0x08, (byte)0x2b, (byte)0x06, (byte)0x01, (byte)0x05, (byte)0x05, (byte)0x07, (byte)0x30, (byte)0x01, (byte)0x86, (byte)0x19, (byte)0x68,
				(byte)0x74, (byte)0x74, (byte)0x70, (byte)0x3a, (byte)0x2f, (byte)0x2f, (byte)0x6f, (byte)0x63, (byte)0x73, (byte)0x70, (byte)0x2e, (byte)0x75, (byte)0x73, (byte)0x65, (byte)0x72, (byte)0x74,
				(byte)0x72, (byte)0x75, (byte)0x73, (byte)0x74, (byte)0x2e, (byte)0x63, (byte)0x6f, (byte)0x6d, (byte)0x30, (byte)0x2f, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x11, (byte)0x04,
				(byte)0x28, (byte)0x30, (byte)0x26, (byte)0x82, (byte)0x12, (byte)0x2a, (byte)0x2e, (byte)0x74, (byte)0x72, (byte)0x69, (byte)0x75, (byte)0x6d, (byte)0x70, (byte)0x68, (byte)0x6a, (byte)0x61,
				(byte)0x70, (byte)0x61, (byte)0x6e, (byte)0x2e, (byte)0x63, (byte)0x6f, (byte)0x6d, (byte)0x82, (byte)0x10, (byte)0x74, (byte)0x72, (byte)0x69, (byte)0x75, (byte)0x6d, (byte)0x70, (byte)0x68,
				(byte)0x6a, (byte)0x61, (byte)0x70, (byte)0x61, (byte)0x6e, (byte)0x2e, (byte)0x63, (byte)0x6f, (byte)0x6d, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48,
				(byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x0b, (byte)0x05, (byte)0x00, (byte)0x03, (byte)0x82, (byte)0x01, (byte)0x01, (byte)0x00, (byte)0x89, (byte)0x78, (byte)0x8c,
				(byte)0xc7, (byte)0x86, (byte)0x8f, (byte)0x1b, (byte)0xd6, (byte)0xd3, (byte)0xcf, (byte)0xc5, (byte)0xd2, (byte)0xf5, (byte)0xa5, (byte)0x3e, (byte)0x5c, (byte)0xb0, (byte)0x62, (byte)0x62,
				(byte)0x2e, (byte)0xdf, (byte)0xad, (byte)0xb4, (byte)0xa1, (byte)0x24, (byte)0xac, (byte)0x4b, (byte)0x07, (byte)0x5d, (byte)0xd5, (byte)0x2f, (byte)0xe3, (byte)0x30, (byte)0xe9, (byte)0xd7,
				(byte)0x43, (byte)0x6d, (byte)0x4c, (byte)0x3e, (byte)0x33, (byte)0x4f, (byte)0x51, (byte)0x09, (byte)0x18, (byte)0x85, (byte)0x8b, (byte)0xdf, (byte)0x3e, (byte)0xb0, (byte)0x78, (byte)0x87,
				(byte)0x4c, (byte)0x2e, (byte)0xfd, (byte)0x2f, (byte)0x15, (byte)0xef, (byte)0x3d, (byte)0x06, (byte)0xf4, (byte)0x85, (byte)0x54, (byte)0x4f, (byte)0x0c, (byte)0x90, (byte)0xed, (byte)0xed,
				(byte)0x0b, (byte)0x31, (byte)0x51, (byte)0x66, (byte)0x03, (byte)0x65, (byte)0xef, (byte)0x5d, (byte)0xc1, (byte)0x81, (byte)0xde, (byte)0xb1, (byte)0xf1, (byte)0x9f, (byte)0x86, (byte)0xb7,
				(byte)0x4c, (byte)0x2e, (byte)0x62, (byte)0x13, (byte)0x1f, (byte)0xe5, (byte)0xac, (byte)0xe0, (byte)0x20, (byte)0x63, (byte)0xfc, (byte)0x3c, (byte)0xf2, (byte)0xd7, (byte)0x1d, (byte)0x1b,
				(byte)0xf4, (byte)0x99, (byte)0x18, (byte)0x65, (byte)0x30, (byte)0x2a, (byte)0x48, (byte)0xe3, (byte)0x71, (byte)0xae, (byte)0x29, (byte)0x23, (byte)0x21, (byte)0x26, (byte)0xf4, (byte)0x08,
				(byte)0xf1, (byte)0xfe, (byte)0xc0, (byte)0xbc, (byte)0xcb, (byte)0x4a, (byte)0x0b, (byte)0x60, (byte)0x4f, (byte)0x6b, (byte)0x52, (byte)0x85, (byte)0xf8, (byte)0x05, (byte)0xe5, (byte)0xe8,
				(byte)0xe6, (byte)0x14, (byte)0xf2, (byte)0x03, (byte)0xd0, (byte)0xe4, (byte)0x98, (byte)0xab, (byte)0x31, (byte)0x51, (byte)0x6a, (byte)0x18, (byte)0xe3, (byte)0x96, (byte)0x92, (byte)0x5f,
				(byte)0x87, (byte)0x7d, (byte)0x8f, (byte)0xbc, (byte)0x2d, (byte)0xb8, (byte)0x17, (byte)0x06, (byte)0xf7, (byte)0x5d, (byte)0xc5, (byte)0x1c, (byte)0x58, (byte)0xe5, (byte)0x65, (byte)0x88,
				(byte)0xbe, (byte)0x34, (byte)0xa4, (byte)0x45, (byte)0xe3, (byte)0xdc, (byte)0x0d, (byte)0x7a, (byte)0xff, (byte)0xf2, (byte)0x3c, (byte)0x21, (byte)0xe4, (byte)0x18, (byte)0xe1, (byte)0xbf,
				(byte)0x14, (byte)0x5e, (byte)0x9d, (byte)0x02, (byte)0x41, (byte)0x1f, (byte)0x96, (byte)0x1f, (byte)0xde, (byte)0xfa, (byte)0x88, (byte)0x72, (byte)0x8a, (byte)0xef, (byte)0x65, (byte)0xe1,
				(byte)0x32, (byte)0x29, (byte)0x9b, (byte)0x47, (byte)0x5d, (byte)0xdc, (byte)0xb4, (byte)0xfe, (byte)0x9d, (byte)0x3c, (byte)0x32, (byte)0x6c, (byte)0xca, (byte)0xc8, (byte)0x7c, (byte)0x23,
				(byte)0x47, (byte)0x95, (byte)0x82, (byte)0x91, (byte)0x59, (byte)0x4d, (byte)0x80, (byte)0x11, (byte)0x21, (byte)0x36, (byte)0x58, (byte)0xb9, (byte)0xa2, (byte)0x23, (byte)0xfb, (byte)0xc9,
				(byte)0xee, (byte)0x61, (byte)0x21, (byte)0x15, (byte)0x6e, (byte)0xdc, (byte)0x79, (byte)0x54, (byte)0x1a, (byte)0xe2, (byte)0x97, (byte)0x7d, (byte)0x5e, (byte)0x33, (byte)0xa6, (byte)0x16,
				(byte)0x0f, (byte)0x00, (byte)0xbc, (byte)0x6d, (byte)0xa8, (byte)0xc6, (byte)0xe0, (byte)0x1c, (byte)0x45, (byte)0x3c, (byte)0xa0, (byte)0xe3, (byte)0x35,
				(byte)0x0e, (byte)0x00, (byte)0x00, (byte)0x00,
				(byte)0x10, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x03, (byte)0xa1, (byte)0xc6, (byte)0x57, (byte)0xa7, (byte)0x84, (byte)0xa4, (byte)0xdb, (byte)0x60, (byte)0xae,
				(byte)0xef, (byte)0x06, (byte)0xa1, (byte)0xd1, (byte)0x8a, (byte)0xab, (byte)0xd6, (byte)0xf8, (byte)0xbf, (byte)0x1f, (byte)0x96, (byte)0x41, (byte)0x0e, (byte)0xce, (byte)0x07, (byte)0x9a,
				(byte)0xae, (byte)0x16, (byte)0x8d, (byte)0x4d, (byte)0x79, (byte)0xfe, (byte)0x60, (byte)0xd1, (byte)0x9b, (byte)0x17, (byte)0xb9, (byte)0x4e, (byte)0x3e, (byte)0x17, (byte)0xd8, (byte)0xd6,
				(byte)0xf3, (byte)0xd6, (byte)0x45, (byte)0x52, (byte)0xe5, (byte)0x69, (byte)0xbb, (byte)0xb7, (byte)0x85, (byte)0x48, (byte)0xc8, (byte)0x23, (byte)0xa4, (byte)0x89, (byte)0x7d, (byte)0x0b,
				(byte)0xe3, (byte)0x7b, (byte)0x3c, (byte)0xbb, (byte)0x92, (byte)0x14, (byte)0x8b, (byte)0xb8, (byte)0x0e, (byte)0xa8, (byte)0x2c, (byte)0xee, (byte)0xfc, (byte)0xcc, (byte)0x2b, (byte)0x17,
				(byte)0x96, (byte)0x71, (byte)0x26, (byte)0xc5, (byte)0x54, (byte)0x9a, (byte)0xd4, (byte)0x45, (byte)0x3f, (byte)0x35, (byte)0x62, (byte)0x04, (byte)0x87, (byte)0xfe, (byte)0x20, (byte)0xd7,
				(byte)0xef, (byte)0x7a, (byte)0xec, (byte)0x68, (byte)0x96, (byte)0xd1, (byte)0x34, (byte)0xe7, (byte)0xc7, (byte)0xa9, (byte)0x5f, (byte)0x20, (byte)0x60, (byte)0x04, (byte)0x8c, (byte)0x79,
				(byte)0x53, (byte)0xb5, (byte)0xa4, (byte)0x7e, (byte)0x06, (byte)0x0d, (byte)0x91, (byte)0x6a, (byte)0x3e, (byte)0xa0, (byte)0xea, (byte)0xe7, (byte)0x13, (byte)0xb0, (byte)0xac, (byte)0x0f,
				(byte)0x8a, (byte)0xb8, (byte)0x8a, (byte)0x0c, (byte)0x05, (byte)0x11, (byte)0x6d, (byte)0xb3, (byte)0xb1, (byte)0x01, (byte)0xa1, (byte)0x04, (byte)0x67, (byte)0x7e, (byte)0x3f, (byte)0x56,
				(byte)0x27, (byte)0xbe, (byte)0x9d, (byte)0xc5, (byte)0x12, (byte)0x7f, (byte)0x85, (byte)0x55, (byte)0x4d, (byte)0x4a, (byte)0x6b, (byte)0x33, (byte)0x5f, (byte)0x58, (byte)0x7d, (byte)0x15,
				(byte)0xf3, (byte)0x9d, (byte)0xcc, (byte)0x08, (byte)0xd9, (byte)0xdb, (byte)0x9b, (byte)0x37, (byte)0xe5, (byte)0xde, (byte)0xf9, (byte)0x37, (byte)0xd1, (byte)0xaf, (byte)0xe7, (byte)0x34,
				(byte)0xd9, (byte)0xc1, (byte)0x5a, (byte)0x21, (byte)0xdb, (byte)0xec, (byte)0x77, (byte)0xb4, (byte)0x16, (byte)0x4b, (byte)0x4d, (byte)0x3f, (byte)0xb3, (byte)0xe4, (byte)0x0d, (byte)0x73,
				(byte)0xc8, (byte)0x82, (byte)0x1f, (byte)0xeb, (byte)0xdf, (byte)0x02, (byte)0xcf, (byte)0x5c, (byte)0x5d, (byte)0x04, (byte)0xa3, (byte)0x0e, (byte)0x63, (byte)0x54, (byte)0xd2, (byte)0xf9,
				(byte)0x3d, (byte)0x1c, (byte)0x4d, (byte)0x2b, (byte)0x68, (byte)0x93, (byte)0xc6, (byte)0x3a, (byte)0x48, (byte)0x88, (byte)0xfb, (byte)0x89, (byte)0x44, (byte)0xcd, (byte)0x25, (byte)0x70,
				(byte)0x97, (byte)0x8b, (byte)0x43, (byte)0x1d, (byte)0x74, (byte)0xc6, (byte)0x6e, (byte)0x8f, (byte)0xf9, (byte)0x25, (byte)0x6b, (byte)0xa7, (byte)0x63, (byte)0x25, (byte)0xfe, (byte)0x12,
				(byte)0x9c, (byte)0x02, (byte)0x88, (byte)0xd0, (byte)0xfa, (byte)0x16, (byte)0x97, (byte)0xc4, (byte)0x22, (byte)0xe1, (byte)0xd6, (byte)0xcf, (byte)0x1f, (byte)0x9b, (byte)0x8a, (byte)0x65,
				(byte)0xcf, (byte)0x88, (byte)0xb8, (byte)0x79, (byte)0xd6, (byte)0xf1				
		};
		
		System.out.println(b.length);
		
		MyTLS tls = new MyTLS();
		tls.md5Digest = Digest.factory("MD5");
		tls.sha1Digest = Digest.factory("SHA1");
		
		tls.md5Digest.updateHash(b);
		tls.sha1Digest.updateHash(b);
		tls.masterSecret = new byte[]{
			(byte)0x96, (byte)0xF0, (byte)0x23, (byte)0xF0, (byte)0x87, (byte)0xAB, (byte)0xF3, (byte)0xA1, (byte)0xA7, (byte)0x11, (byte)0x83, (byte)0x84, (byte)0x6F, (byte)0x78, (byte)0x35, (byte)0x54, (byte)0x87, (byte)0x1A, (byte)0x33, (byte)0xD5, (byte)0x0B, (byte)0xEE, (byte)0x28, (byte)0x7B, (byte)0x3B, (byte)0x4E, (byte)0xC1, (byte)0x5C, (byte)0x36, (byte)0x95, (byte)0xEA, (byte)0x4E, (byte)0x6F, (byte)0x28, (byte)0x7C, (byte)0xB0, (byte)0x77, (byte)0x1E, (byte)0xD9, (byte)0xBB, (byte)0xD1, (byte)0x38, (byte)0x14, (byte)0xE8, (byte)0x99, (byte)0xC9, (byte)0xC2, (byte)0xDF				
		};
		
		byte[] data = tls.computeVerifyData();
		System.out.println(BitOperator.getRadix16FromByteArray(data));*/
		
		TLS tls = new TLS();
		tls.cipherSuite = CipherSuiteEnum.TLS_RSA_WITH_AES_128_CBC_SHA;
		byte[] clientRandomBytes = BitOperator.getByteArrayFromRadix16("7447667f060d7fddd1f8869f5943ba49aab0afde0a3a0db13b8227171f3fb0fc");
		byte[] serverRandomBytes = BitOperator.getByteArrayFromRadix16("5acdb57b62c584c15e21c198fdfc33ef09417d9b25fbe58f2b4d874440417e5a");
		tls.masterSecret = BitOperator.getByteArrayFromRadix16("bd9ecb262406b306a66597e9a65c0e8e53bfdd7873e7d55643aeb8ebd16b68770c6d7fa2454d6f0fcc6d90ade9e01291");
		
		System.out.println(BitOperator.getRadix16FromByteArray(prf(BitOperator.getByteArrayFromRadix16("bd9ecb262406b306a66597e9a65c0e8e53bfdd7873e7d55643aeb8ebd16b68770c6d7fa2454d6f0fcc6d90ade9e01291"), "key expansion".getBytes(), BitOperator.getByteArrayFromRadix16("5acdb57b62c584c15e21c198fdfc33ef09417d9b25fbe58f2b4d874440417e5a7447667f060d7fddd1f8869f5943ba49aab0afde0a3a0db13b8227171f3fb0fc"), 104)));
		
				
		
		tls.clientRandom = new Random();
		tls.clientRandom.setGmtUnixTime(clientRandomBytes[0],clientRandomBytes[1],clientRandomBytes[2],clientRandomBytes[3]);
		tls.clientRandom.setRandomBytes(new byte[28]);
		System.arraycopy(clientRandomBytes, 4, tls.clientRandom.getRandomBytes(), 0, tls.clientRandom.getRandomBytes().length);
		
		tls.serverRandom = new Random();
		tls.serverRandom.setGmtUnixTime(serverRandomBytes[0],serverRandomBytes[1],serverRandomBytes[2],serverRandomBytes[3]);
		tls.serverRandom.setRandomBytes(new byte[28]);
		System.arraycopy(serverRandomBytes, 4, tls.serverRandom.getRandomBytes(), 0, tls.serverRandom.getRandomBytes().length);

		tls.sendParameters = new ProtectionParameters();
		tls.receiveParameters = new ProtectionParameters();
		tls.calculateKeys();
		
		System.out.println(BitOperator.getRadix16FromByteArray(tls.sendParameters.getInitialValue()));
		System.out.println(BitOperator.getRadix16FromByteArray(tls.sendParameters.getKey()));
		
		byte[] input = BitOperator.getByteArrayFromRadix16("51761598013c69ee18f2f9836dc6ac1057813d8285af1cffaed53b79897ed5ebca9b5b7223dc57898261cd0a2c75b27a");
		byte[] iv = BitOperator.getByteArrayFromRadix16("4ad1c29e4adf6f377104fff4c295e804");
		byte[] key = BitOperator.getByteArrayFromRadix16("c5990b6b57ba686e56598369e9ebd083");
		byte[] ret = new AES().decrypt(input, key, iv,"CBC");
		System.out.println(BitOperator.getRadix16FromByteArray(ret));
	}
}
