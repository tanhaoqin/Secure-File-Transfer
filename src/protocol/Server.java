package protocol;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;

import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;


public class Server {

	public static CryptoManager cryptoManager;
	private static ServerSocket serverSocket;

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		cryptoManager = new CryptoManager();
		cryptoManager.setPrivateKey(new File("certs//privateServer.der"));
		
		serverSocket = new ServerSocket(4321);
		new Thread(new Runnable() {
			
			@Override
			public void run() {
/*				while(true){
					try {
						Socket socket = serverSocket.accept();
						new Thread(new ClientHandler(socket)).start();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}*/
				try{
					Socket socket = serverSocket.accept();
					new Thread(new ClientHandler(socket)).start();
				}catch(IOException e){
					e.printStackTrace();
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
	
	public static final String CERT_TRANSFER_START = "CERT_TRANSFER_START";
	public static final String CERT_TRANSFER_END = "CERT_TRANSFER_END";
	
	Socket socket;
	
	public ClientHandler(Socket socket) throws IOException {
		System.out.println("Client connected");
		this.socket = socket;

	}
	
	/*
	 
	 * */
	/*@Override
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
	}*/

	@Override
	public void run(){
		BufferedReader in;
		PrintWriter out;
/*		while(true){
			try{
				in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				out = new PrintWriter(socket.getOutputStream());
				if(in.readLine().equals(Client.FILE_TRANSFER_START)){
					receiveFile(socket);
				}
			}catch (IOException e){
				e.printStackTrace();
			}
		}*/
		try{
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(socket.getOutputStream());
			if(in.readLine().equals(Client.FILE_TRANSFER_START)){
				receiveFile(socket);
			}
		}catch (IOException e){
			e.printStackTrace();
		}
	}
	/**
	 * Callback when the server receives Client.FILE_TRANSFER_START
	 * @param socket
	 * @throws IOException
	 */
	public void receiveFile(Socket socket) throws IOException{

		PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);

		BufferedInputStream bufferedInputStream = new 
				BufferedInputStream(socket.getInputStream());
		
		BufferedReader bufferedReader = new 
				BufferedReader(new InputStreamReader(socket.getInputStream()));
		
		printWriter.println(Client.FILE_TRANSFER_START);
		printWriter.flush();
		
		String transferParameters = bufferedReader.readLine();
		
		int fileLength = Integer.parseInt(transferParameters.split(",", 2)[0].trim());
		String fileName= transferParameters.split(",", 2)[1].trim();
		String acknowledgementParams = String.format("%d, %s", fileLength, fileName);
		
		printWriter.println(acknowledgementParams);
		printWriter.flush();
		
		File outputFile = new File(Client.DESTINATION_FILE_PATH + fileName);
		if(outputFile.exists())
			outputFile.delete();
		
		System.out.println("Receiving with parameters: " + acknowledgementParams);
		
		int totalBytesTransferred = 0, numBytesRead;
		
		CRC32 crc32 = new CRC32();
		
		while(totalBytesTransferred < fileLength){
			
			int blockSize = fileLength - totalBytesTransferred < 1000 
					? fileLength - totalBytesTransferred : 1000;

			System.out.format("Receiving bytes: %d to %d ",
					totalBytesTransferred, totalBytesTransferred + blockSize);
			
			byte[] block = new byte[blockSize];
			
			numBytesRead = bufferedInputStream.read(block);
			crc32.update(block);
			
			long crc32Value = crc32.getValue();
			printWriter.println(crc32Value);
			printWriter.flush();
			System.out.print("CRC32 value sent: " + crc32Value);
			
			String response = bufferedReader.readLine();
			System.out.println(" client: " + response);
			if(Client.OK.equals(response)){
				CryptoManager.appendBytesToFile(block, outputFile);
				totalBytesTransferred += numBytesRead;
			}
			
			else if (Client.FAIL.equals(response))
				continue;
			
			else {
				throw new IOException("CRC32 something failed");
			}
		}
		
		String ended = bufferedReader.readLine();
		printWriter.close();
		bufferedReader.close();
		bufferedInputStream.close();
		
		if(!Client.FILE_TRANSFER_END.equals(ended)){
			throw new IOException("Client did not exit transfer properly");
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
		
		
		
		
//		BufferedReader in;
//		PrintWriter out;
//		String sessionKeyString;
//		String keyDigest;
//				
//		while(true){
//			try{
//				in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
//				out = new PrintWriter(socket.getOutputStream(), true);
//				sessionKeyString = in.readLine();
//				keyDigest = in.readLine();
//				if (keyDigest.length() > sessionKeyString.length()){
//					out.println(RESEND_KEY);
//					continue;
//				}
//				
//				out.println(keyDigest);
//				if(in.readLine().equals(KEY_OK))
//					break;
//				
//			}catch(IOException e){
//				System.out.println(e.getMessage());
//				try{
//					Thread.sleep(100);
//				}catch(InterruptedException e1){};
//			}
//		}
//		
//		byte[] secretKeyBytes = Base64.decode(sessionKeyString);
//		return new SecretKeySpec(secretKeyBytes, "AES");
	}
}