package protocol;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.swing.InputMap;


public class Client {

	public static final String FAIL = "FAIL";
	public static final String OK = "OK";
	public static final String LOCALHOST = "127.0.0.1";
	public static final String FILE_TRANSFER_START = "FILE_TRANSFER_START";
	public static final String FILE_TRANSFER_END = "FILE_TRANSFER_END";
<<<<<<< HEAD
	public static final String FILE_LOCATION_DIR = "tests/";
	public static final String TRANSFER_FILE_NAME = "Coffee.jpg";
	public static final String TRANSFER_FILE_PATH = FILE_LOCATION_DIR + TRANSFER_FILE_NAME;
	public static final String DESTINATION_FILE_PATH = "tests/TRANSFERRED";
	public static final int TIME_OUT_LENGTH = 10000;
	
=======
	public static final String SESSION_KEY_START = "SESSION_KEY_START";
	public static final String SESSION_KEY_END = "SESSION_KEY_END";
	public static final int TIME_OUT_LENGTH = 1000;
>>>>>>> 0e23da52713a061028b6be25a227de6c4af17eb6
	

	public final static String CERTIFICATE_REQUEST = "Hello SecStore, please prove your identity!";
	
	private Socket socket;
	private InputStream in;
	
	private CryptoManager cryptoManager;
	
	public Socket getSocket() {
		return socket;
	}

	public void setSocket(Socket socket) {
		this.socket = socket;
	}

	byte[] buffer;
	
	public Client() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
		cryptoManager = new CryptoManager();
	}
	
	public static void main(String[] args) throws UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		
		Client client = new Client();
//		client.setSocket();
		System.out.println("Client connected");
		
		System.out.println(System.getProperty("user.dir"));
		
<<<<<<< HEAD
		client.uploadFile(fileToBytes(new File(TRANSFER_FILE_PATH))
				, new Socket(LOCALHOST, 4321), TRANSFER_FILE_NAME);
		
//		client.uploadFile(new File("certs//server_Tan Hao Qin.csr"));
=======
>>>>>>> 0e23da52713a061028b6be25a227de6c4af17eb6
		
	}

	public static byte[] fileToBytes(File file) throws IOException{
		FileInputStream fileInputStream = new FileInputStream(file);
		byte[] fileBytes;
		BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));
		fileBytes = new byte[(int) file.length()];
		bufferedInputStream.read(fileBytes);
		fileInputStream.close();
		bufferedInputStream.close();
		return fileBytes;
	}

	
	/**
	 * Uploads a given file using the given parameters according to the following protocol:
	 * 
	 * UTF-8
	 * 1. 	Client sends FILE_TRANSFER_START
	 * 2.	Server replies with FILE_TRANSFER_START
	 * 3.	Client sends the file size in bytes and intended file name to the server
	 * 		in the form <file size>, <file name>.<extension>
	 * 4.	Server replies with what it received from the client
	 * 
	 * Raw bytes
	 * 5.	Client begins sending the raw byte data to the server in chunks of 1kB
	 * 6.	Server receives bytes. When data chunk reaches 1kB, or the number of bytes 
	 * 		read matches the total expected, the server the CRC-32 of the last block
	 * 		as an acknowledgement.
	 * 7.	Client sends FILE_TRANSFER_END.
	 * 8. 	Client quits.
	 * 
	 * @param fileBytes
	 * @param fileName
	 * @throws IOException
	 */
	public void uploadFile(byte[] fileBytes, Socket socket, String fileName) throws IOException{
		
		socket.setSoTimeout(TIME_OUT_LENGTH);
		PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);

		BufferedOutputStream bufferedOutputStream = new 
				BufferedOutputStream(socket.getOutputStream());
		
		BufferedReader bufferedReader = new 
				BufferedReader(new InputStreamReader(socket.getInputStream()));
		
		printWriter.println(FILE_TRANSFER_START);
		printWriter.flush();
		if (!FILE_TRANSFER_START.equals(bufferedReader.readLine()))
			throw new IOException("Start acknowledgement not received");
		
		System.out.println("Starting the transfer");
		
		String transferParams = String.format("%d, %s", fileBytes.length, fileName);
		printWriter.println(transferParams);
		printWriter.flush();
		
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
				bufferedOutputStream.flush();
				if (String.valueOf(crc32Value).equals(bufferedReader.readLine())){
					System.out.println(" Response: OK");
					printWriter.println(OK);
					printWriter.flush();
					try{
						Thread.sleep(20);
					}catch (InterruptedException e){}
					break;
				}else{
					System.out.println(" Response: FAIL");
					printWriter.println(FAIL);
					printWriter.flush();
					continue;					
				}
			}
		}
		printWriter.println(FILE_TRANSFER_END);
		
		try{
			Thread.sleep(100);}
		catch (InterruptedException e){
			
		}
		finally{
			socket.close();
			printWriter.close();
			bufferedOutputStream.close();
			bufferedReader.close();
		}
	}

<<<<<<< HEAD
	public void uploadRSA(File file, File publicKeyFile) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException{
		byte[] fileBytes;
		try{
			BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));
			fileBytes = new byte[(int) file.length()];
			bufferedInputStream.read(fileBytes);
		}catch (IOException e){
			e.printStackTrace();
			return;
=======
	public void sendSessionKey(byte[] keyBytes, Socket socket) throws IOException{
		socket.setSoTimeout(TIME_OUT_LENGTH);
		PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);

		BufferedOutputStream bufferedOutputStream = new 
				BufferedOutputStream(socket.getOutputStream());
		
		BufferedReader bufferedReader = new 
				BufferedReader(new InputStreamReader(socket.getInputStream()));
		
		printWriter.println(SESSION_KEY_START);
		printWriter.flush();
		if (!SESSION_KEY_START.equals(bufferedReader.readLine()))
			throw new IOException("Start acknowledgement not received");
		
		String transferParams = String.format("%d", keyBytes.length);
		printWriter.println(transferParams);
		printWriter.flush();
		
		if(!transferParams.equals(bufferedReader.readLine()))
			throw new IOException("Parameter acknowledgement not received");		
		
		int i = 0, initialI = 0;
		byte[] block;
		CRC32 crc32 = new CRC32();
		
		while(i < keyBytes.length){
			initialI = i;
			block = new byte[i + 1000 >= keyBytes.length ? 
					keyBytes.length - i : 1000];
			
			for(int j = initialI; i < initialI + 1000 ; i++){
				if(i >= keyBytes.length)
					break;
				block[i - initialI] = keyBytes[i]; //writes the byte to the block first
			}
			crc32.update(block);
			long crc32Value = crc32.getValue();
			
			while(true){
				bufferedOutputStream.write(block);
				bufferedOutputStream.flush();
				if (String.valueOf(crc32Value).equals(bufferedReader.readLine())){
					printWriter.println(OK);
					printWriter.flush();
					break;
				}else{
					printWriter.println(FAIL);
					printWriter.flush();
					continue;					
				}
			}
			
>>>>>>> 0e23da52713a061028b6be25a227de6c4af17eb6
		}
		
		printWriter.println(SESSION_KEY_END);
		
		try{
			Thread.sleep(100);}
		catch (InterruptedException e){
			
		}
		finally{
			socket.close();
			printWriter.close();
			bufferedOutputStream.close();
			bufferedReader.close();
		}
	}
	
	private void initAES() throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, IOException{
		cryptoManager.generateAES();		
		SecretKey sessionKey = cryptoManager.getSessionKey();
		byte[] keyBytes = cryptoManager.encryptWithPublicKey(sessionKey.getEncoded());
		sendSessionKey(keyBytes, socket);
	}
	
	public void uploadRSA(File file) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException{
		byte[] fileBytes = cryptoManager.encryptWithPublicKey(file);
		uploadFile(fileBytes, socket, file.getName());
	}
	
	public void uploadAES(File file) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException{
		byte[] fileBytes = cryptoManager.encryptWithKey(file, cryptoManager.getSessionKey());
		uploadFile(fileBytes, socket, file.getName());
	}

}
