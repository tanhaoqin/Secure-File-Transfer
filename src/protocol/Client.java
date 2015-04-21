package protocol;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class Client {

	public static final String LOCALHOST = "127.0.0.1";
	public static final String FILE_TRANSFER_START = "FILE_TRANSFER_START";
	public static final String FILE_TRANSFER_END = "FILE_TRANSFER_END";

	public final String CERTIFICATE_REQUEST = "Hello SecStore, please prove your identity!";
	
	private Socket socket;
	private InputStream in;
	public Socket getSocket() {
		return socket;
	}

	public void setSocket(Socket socket) {
		this.socket = socket;
	}

	private OutputStream out;
	byte[] buffer;
	
	public static void main(String[] args) throws UnknownHostException, IOException {
		Client client = new Client();
		client.setSocket(new Socket(LOCALHOST, 4321));
		System.out.println("Client connected");
		
		System.out.println(System.getProperty("user.dir"));
		
		client.uploadFile(new File("certs//server_Tan Hao Qin.csr"));
		
	}
	
	public void uploadFile(byte[] fileBytes, BufferedOutputStream bufferedOutputStream,
			PrintWriter printWriter) throws IOException{
		
		for(byte fileByte: fileBytes){
			bufferedOutputStream.write(fileByte);
			bufferedOutputStream.flush();
		}
	}

	public void uploadRSA(File file, File publicKeyFile){
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
		
		printWriter.println(FILE_TRANSFER_START);
//		printWriter.println(file.getName());
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
