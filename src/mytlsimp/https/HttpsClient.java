package mytlsimp.https;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import mytlsimp.tls.TLS;

public class HttpsClient {
	public String doGet(String url) throws IOException{
		String[] parsedUrl = parseUrl(url);
		TLS tls = new TLS();
		
		try (Socket socket = new Socket(parsedUrl[0], 443)){
			OutputStream os = socket.getOutputStream();
			InputStream is = socket.getInputStream();
			
			tls.tlsConnect(os, is);
		}
		
		return null;
	}
		
	private String[] parseUrl(String url){
		int pos = -1;
		if ((pos = url.indexOf("//"))==-1){
			return null;	
		}
		pos+=2;
		String host = url.substring(pos);
		String path = "/";
		if ((pos = host.indexOf("/"))!=-1){
			path = host.substring(pos);
			host = host.substring(0, pos);
		}
				
		return new String[]{host, path};
	}
	
	public static void main(String[] args) throws Exception{
		new HttpsClient().doGet("https://web.triumphjapan.com/NewSis/Satex2016/");
		// new MyHttpsClient().doGet("https://google.com");
		//new MyHttpsClient().doGet("https://jp.triumph.com");
	}
}
