package protocol;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * How to run:
 * 
 * 1.	Run program
 * 2.	Received files will be put in the "server" folder
 * 
 * @author tes
 *
 */

public class Server {

	public static final String DESTINATION_FILE_DIR = "client/";
	public static CryptoManager cryptoManager;
	private static ServerSocket serverSocket;

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InterruptedException {
		cryptoManager = new CryptoManager();
		cryptoManager.setPrivateKey(new File("certs//privateServer.der"));
		
		serverSocket = new ServerSocket(4321);
		while(true){
			try{
				Thread handleThread = new Thread(new ClientHandler(serverSocket.accept()));
				handleThread.start();
			}catch (Exception e){}
		}
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
	
	private File file;
	Socket socket;
	
	
	SecretKey sessionKey;
	
	public ClientHandler(Socket socket) throws IOException {
		System.out.println("Client connected");
		this.socket = socket;

	}
	

	@Override
	public void run(){
		BufferedReader in;
		PrintWriter out;
		try{
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(socket.getOutputStream());
			String request = in.readLine();
			boolean fileTransferred = false;
			
			if(request.contains(Client.CERTIFICATE_REQUEST)){
				if(!serverAuthenticate(request)){
					System.out.println("Authentication failed");
					return;
				}
				
				while(!fileTransferred){
					try{
						request = in.readLine();
					}catch(SocketException e){
						break;
					}
					
					if(request.equals(Client.SESSION_KEY_START)){
						acceptSessionKey();
					}
					if(request.equals(Client.FILE_TRANSFER_START)){
						receiveFile(socket);
						fileTransferred = true;
					}
				}
			}

		}catch (IOException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException e){
			e.printStackTrace();
		}
		try{
			if(sessionKey != null){
				System.out.println("Decrypting AES");
				CryptoManager.appendBytesToFile(
						Server.cryptoManager.decryptWithKey(file, sessionKey), new File("server//decrypted//"+file.getName()));
			}
			else{
				System.out.println("Decrypting RSA");
				CryptoManager.appendBytesToFile(
						Server.cryptoManager.decryptWithPrivateKey(file), new File("server//decrypted//"+file.getName()));
			}
		}catch (Exception e){
			e.printStackTrace();
		}
	}
	
	public boolean serverAuthenticate(String request) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
		PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);

		BufferedOutputStream bufferedOutputStream = new 
				BufferedOutputStream(socket.getOutputStream());
		
		BufferedReader bufferedReader = new 
				BufferedReader(new InputStreamReader(socket.getInputStream()));
		
		String encryptedRequest = Server.cryptoManager.encryptWithPrivateKey(request);
		printWriter.println(encryptedRequest);
		printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
		
		String requestTheSequel;
		while(!(requestTheSequel = bufferedReader.readLine())
				.equals(Client.CERTIFICATE_REQUEST_2));
		
		byte[] certBytes = Client.fileToBytes(new File(Client.SERVER_FILE_PATH + Client.CERTIFICATE_NAME));
		uploadCert(certBytes, socket);
		
		String response;
		while((response= bufferedReader.readLine())== null);
		
		if(response.equals(Client.OK))
			return true;
		else if(response.equals(Client.FAIL))
			return false;
		else 
			throw new IOException("Authentication failure everywhere");
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
		printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
		
		String transferParameters = bufferedReader.readLine();
		
		int fileLength = Integer.parseInt(transferParameters.split(",", 2)[0].trim());
		String fileName= transferParameters.split(",", 2)[1].trim();
		String acknowledgementParams = String.format("%d, %s", fileLength, fileName);
		
		printWriter.println(acknowledgementParams);
		printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
		
		File outputFile = new File("server//received//" + fileName);
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
			printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
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

		
		if(!Client.FILE_TRANSFER_END.equals(ended)){
			throw new IOException("Client did not exit transfer properly");
		}
		this.file = outputFile;
	}
	
	public void uploadCert(byte[] fileBytes, Socket socket) throws IOException{
		
		socket.setSoTimeout(Client.TIME_OUT_LENGTH);
		PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);

		BufferedOutputStream bufferedOutputStream = new 
				BufferedOutputStream(socket.getOutputStream());
		
		BufferedReader bufferedReader = new 
				BufferedReader(new InputStreamReader(socket.getInputStream()));
		
		printWriter.println(Client.FILE_TRANSFER_START);
		printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
		if (!Client.FILE_TRANSFER_START.equals(bufferedReader.readLine()))
			throw new IOException("Start acknowledgement not received");
		
		System.out.println("Starting the certificate transfer");
		
		String transferParams = String.valueOf(fileBytes.length);
		printWriter.println(transferParams);
		printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
		
		System.out.println("Sending with parameters: " + transferParams);
		
		if(!transferParams.equals(bufferedReader.readLine()))
			throw new IOException("Parameter acknowledgement not received");
		
		int i = 0, initialI = 0;
		byte[] block;
		CRC32 crc32 = new CRC32();
		
		while(i < fileBytes.length){
			initialI = i;

			int blockLength = i + 1000 >= fileBytes.length ? 
					fileBytes.length - i : 1000;
			
			block = new byte[blockLength];
			
			System.out.format("Bytes %d to %d ", initialI, 
					initialI + blockLength);
			
			for(; i < initialI + blockLength; i++){
				block[i - initialI] = fileBytes[i]; //writes the byte to the block first
			}
			
			crc32.update(block);
			long crc32Value = crc32.getValue();
			System.out.print("CRC32 value: " + crc32Value);
			while(true){
				bufferedOutputStream.write(block);
				bufferedOutputStream.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
				if (String.valueOf(crc32Value).equals(bufferedReader.readLine())){
					System.out.println(" Response: OK");
					printWriter.println(Client.OK);
					printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
					try{
						Thread.sleep(20);
					}catch (InterruptedException e){}
					break;
				}else{
					System.out.println(" Response: FAIL");
					printWriter.println(Client.FAIL);
					printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
					continue;					
				}
			}
		}
		printWriter.println(Client.FILE_TRANSFER_END);
		
		try{
			Thread.sleep(100);}
		catch (InterruptedException e){
			
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
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 **/
	public void acceptSessionKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);

		BufferedInputStream bufferedInputStream = new 
				BufferedInputStream(socket.getInputStream());
		
		BufferedReader bufferedReader = new 
				BufferedReader(new InputStreamReader(socket.getInputStream()));
		
		System.out.println("Accepting key");
		
		printWriter.println(Client.SESSION_KEY_START);
		printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
		
		String transferParameters = bufferedReader.readLine();
		
		int fileLength = Integer.parseInt(transferParameters);
		String acknowledgementParams = String.format("%d", fileLength);
		
		printWriter.println(acknowledgementParams);
		printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
		
		byte[] secretKeyByteArray = new byte[fileLength];
		
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
			printWriter.flush();try{Thread.sleep(20);}catch(InterruptedException e){};
			System.out.print("CRC32 value sent: " + crc32Value);
			
			String response = bufferedReader.readLine();
			System.out.println(" client: " + response);
			if(Client.OK.equals(response)){
				for(int i = 0; i < block.length; i++)
					secretKeyByteArray[i + totalBytesTransferred] = block[i];
				
				totalBytesTransferred += numBytesRead;
			}
			
			else if (Client.FAIL.equals(response))
				continue;
			
			else {
				throw new IOException("CRC32 something failed");
			}
		}
		
		String ended = bufferedReader.readLine();

		
		if(!Client.SESSION_KEY_END.equals(ended)){
			throw new IOException("Client did not exit transfer properly");
		}

		this.sessionKey = new SecretKeySpec(secretKeyByteArray, 0, secretKeyByteArray.length, "AES");
		
	}
}