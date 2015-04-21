import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;



import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;


public class Server {

	
	private static ServerSocket serverSocket;

	public static void main(String[] args) throws IOException {
		
		serverSocket = new ServerSocket(4321);
		new Thread(new Runnable() {
			
			@Override
			public void run() {
				while(true){
					try {
						Socket socket = serverSocket.accept();
						new Thread(new ClientHandler(socket)).start();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}).start();
	}
}

class ClientHandler implements Runnable{

	public static final String END_PROTOCOL = "END_PROTOCOL";
	public static final String IDENTITY_PROTOCOL = "IDENTITY_PROTOCOL";
	public static final String PUBLIC_KEY = "PUBLIC_KEY";
	public static final String RESEND_KEY = "RESEND_KEY";
	public static final String KEY_OK = "KEY_OK";
	
	Socket socket;
	BufferedReader in;
	PrintWriter out;
	
	public ClientHandler(Socket socket) throws IOException {
		System.out.println("Client connected");
		this.socket = socket;
		this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		this.out = new PrintWriter(socket.getOutputStream());
		
	}
	
	/*
	 * 5.	If digests do not match, return to step 1
	 * 5.	If digests match, client begins file transfer
	 * */
	@Override
	public void run() {
		String input;
		try {
			while(!(END_PROTOCOL).equals(input = in.readLine())){
//				Handle file transfer
				if(Client.FILE_TRANSFER_START.equals(input)){
					
					String fileName = "server//"+in.readLine();
					System.out.println("File name: "+fileName);
					
					int length = Integer.parseInt(in.readLine());

					int count = 0;
					
					byte[] byteArray = new byte[length];
					
					BufferedInputStream bufferedInputStream = new BufferedInputStream(socket.getInputStream());

					int a = 0;
					while(a != -1 && count < length){
						a = bufferedInputStream.read();
						System.out.println(a);
						byteArray[count] = (byte) a;
						count++;
					}
					
					FileOutputStream fileOutputStream = new FileOutputStream(fileName);
					fileOutputStream.write(byteArray);
					fileOutputStream.close();
				}
				else if(Client.CERTIFICATE_REQUEST.equals(input)){
					
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Obtains the session key from the client. Implements the entire 
	 * session key handshake with the client. Protocol is as follows:
	 * 
	 * 1.	Client generates a session key and a digest of the key
	 * 2.	Client sends session key encrypted by the server's public key
	 * 3.	Server decrypts the session key and sends back a digest of the session key
	 * 4.	Client checks that the digests match
	 * 5. 	Client acknowledges that the digests match
	 * 6.	If acknoledgement is not received, server tells client to resend session key,
	 * 		repeat from step 2.
	 * 7.	End
	 **/
	public Key acceptSessionKey(Socket socket){
		
		BufferedReader in;
		PrintWriter out;
		String sessionKeyString;
		String keyDigest;
				
		while(true){
			try{
				in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				out = new PrintWriter(socket.getOutputStream(), true);
				sessionKeyString = in.readLine();
				keyDigest = in.readLine();
				if (keyDigest.length() > sessionKeyString.length()){
					out.println(RESEND_KEY);
					continue;
				}
				
				out.println(keyDigest);
				if(in.readLine().equals(KEY_OK))
					break;
				
			}catch(IOException e){
				System.out.println(e.getMessage());
				try{
					Thread.sleep(100);
				}catch(InterruptedException e1){};
			}
		}
		
		byte[] secretKeyBytes = Base64.decode(sessionKeyString);
		return new SecretKeySpec(secretKeyBytes, "AES");
	}
}