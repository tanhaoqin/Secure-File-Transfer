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

	private static final String LOCALHOST = "127.0.0.1";
	
	public static final String FILE_TRANSFER_START = "FILE_TRANSFER_START";
	public static final String FILE_TRANSFER_END = "FILE_TRANSFER_END";
	
	private static Socket socket;

	private static InputStream in;

	private static OutputStream out;
	
	byte[] buffer;
	
	public static void main(String[] args) throws UnknownHostException, IOException {
		
		socket = new Socket(LOCALHOST, 4321);
		System.out.println("Client connected");
		in = socket.getInputStream();
		out = socket.getOutputStream();
		
		System.out.println(System.getProperty("user.dir"));
		
		uploadFile(new File("certs//server_Tan Hao Qin.csr"));
		
	}
	
	public static void uploadFile(File file) throws IOException{
		BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));
		BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(out);
		PrintWriter printWriter = new PrintWriter(out);
		
		printWriter.write(FILE_TRANSFER_START+"\n");
		printWriter.flush();
		printWriter.write(file.getName()+"\n");
		printWriter.flush();
		System.out.println(Long.toString(file.length())+"\n");
		printWriter.write(Long.toString(file.length())+"\n");
		printWriter.flush();

		
		int a = 0;
		while(a != -1){
			a = bufferedInputStream.read();
			bufferedOutputStream.write(a);
		}
		in.close();
		out.close();
	}
	
	public static byte[] encodeRSA(FileInputStream plaintext, 
			FileInputStream publicKeyCertStream) throws CertificateException, NoSuchAlgorithmException, 
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)certificateFactory.
				generateCertificate(publicKeyCertStream);
		PublicKey publicKey = certificate.getPublicKey();
		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return rsaCipher.doFinal();
	}
}
