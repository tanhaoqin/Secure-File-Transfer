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

	private static final String END_PROTOCOL = "END_PROTOCOL";
	private static final String IDENTITY_PROTOCOL = "IDENTITY_PROTOCOL";
	private static final String PUBLIC_KEY = "PUBLIC_KEY";
	
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
	 **/
	public Key acceptSessionKey(Socket socket){
		
		InputStreamReader in;
		char[] cbuf = new char[128];
				
		while(true){
			try{
				in = new InputStreamReader(socket.getInputStream());
				in.read(cbuf);
				break;
			}catch(IOException e){
				System.out.println(e.getMessage());
				try{
					Thread.sleep(100);
				}catch(InterruptedException e1){};
			}
		}
		
		byte[] keyBuffer = new byte[128];
		for(int i = 0; i < cbuf.length; i++)
			keyBuffer[i] = (byte) cbuf[i];
		SecretKeySpec sessionKey = new SecretKeySpec(keyBuffer, "AES");
		
		
	}
}