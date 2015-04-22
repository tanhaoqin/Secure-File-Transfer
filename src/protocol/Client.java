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
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.InputMap;


public class Client {

	public static final String FAIL = "FAIL";
	public static final String OK = "OK";
	public static final String LOCALHOST = "127.0.0.1";
	public static final String FILE_TRANSFER_START = "FILE_TRANSFER_START";
	public static final String FILE_TRANSFER_END = "FILE_TRANSFER_END";
	public static final String FILE_LOCATION_DIR = "tests/";
	public static final String TRANSFER_FILE_NAME = "Coffee.jpg";
	public static final String TRANSFER_FILE_PATH = FILE_LOCATION_DIR + TRANSFER_FILE_NAME;
	public static final String DESTINATION_FILE_PATH = "tests/TRANSFERRED";
	public static final int TIME_OUT_LENGTH = 10000;
	
	

	public final String CERTIFICATE_REQUEST = "Hello SecStore, please prove your identity!";
	
	private Socket socket;
	private InputStream in;
	public Socket getSocket() {
		return socket;
	}

	public void setSocket(Socket socket) {
		this.socket = socket;
	}

	byte[] buffer;
	
	public static void main(String[] args) throws UnknownHostException, IOException {
		Client client = new Client();
//		client.setSocket();
		System.out.println("Client connected");
		
		System.out.println(System.getProperty("user.dir"));
		
		client.uploadFile(fileToBytes(new File(TRANSFER_FILE_PATH))
				, new Socket(LOCALHOST, 4321), TRANSFER_FILE_NAME);
		
//		client.uploadFile(new File("certs//server_Tan Hao Qin.csr"));
		
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

	public void uploadRSA(File file, File publicKeyFile) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException{
		byte[] fileBytes;
		try{
			BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));
			fileBytes = new byte[(int) file.length()];
			bufferedInputStream.read(fileBytes);
		}catch (IOException e){
			e.printStackTrace();
			return;
		}
		byte[] cipherText = encodeRSA(fileBytes, new FileInputStream(publicKeyFile));
		
		BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(socket.getOutputStream());
		PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);
		

		System.out.println(file.length());
		printWriter.println(file.length());
	}
	
	public byte[] encodeRSA(byte[] plaintext, 
			FileInputStream publicKeyCertStream) throws CertificateException, NoSuchAlgorithmException, 
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)certificateFactory.
				generateCertificate(publicKeyCertStream);
		
		PublicKey publicKey = certificate.getPublicKey();
		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return rsaCipher.doFinal(plaintext);
	}

}
