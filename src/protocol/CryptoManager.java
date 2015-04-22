package protocol;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class CryptoManager {
	
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private SecretKey aesKey;
	
	public static final String AES_ENCRYPTION = "AES/ECB/PKCS5Padding";
	public static final String RSA_ENCRYPTION = "RSA/ECB/PKCS1Padding";
	
	public CryptoManager(File privateKeyFile) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		FileInputStream privateKeyFileStream = new FileInputStream(privateKeyFile);
		byte[] privateKeyArray = new byte[privateKeyFileStream.available()];
		privateKeyFileStream.read(privateKeyArray);
		privateKeyFileStream.close();
		
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyArray);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		privateKey = keyFactory.generatePrivate(privateKeySpec);
		
	}

	public void setPublicKey(File publicKeyFile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
		FileInputStream publicKeyFileStream = new FileInputStream(publicKeyFile);
		byte[] publicKeyArray = new byte[publicKeyFileStream.available()];
		publicKeyFileStream.read(publicKeyArray);
		publicKeyFileStream.close();
		
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyArray);
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		publicKey = keyFactory.generatePublic(publicKeySpec);
	}
	
	public byte[] encryptWithPrivateKey(File file) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
		BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));

		int length = (int) file.length();
		int count = 0;
		
		byte[] byteArray = new byte[length];

		int a = 0;
		while(a != -1 && count < length){
			a = bufferedInputStream.read();
			System.out.println(a);
			byteArray[count] = (byte) a;
			count++;
		}
		
		Cipher rsaCipher = Cipher.getInstance(RSA_ENCRYPTION);
		rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] finalBytes = rsaCipher.doFinal(byteArray);
        return finalBytes;
	}
	
	public byte[] decryptWithPublicKey(File file) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
		BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));

		int length = (int) file.length();
		int count = 0;
		
		byte[] byteArray = new byte[length];

		int a = 0;
		while(a != -1 && count < length){
			a = bufferedInputStream.read();
			System.out.println(a);
			byteArray[count] = (byte) a;
			count++;
		}
		
		Cipher rsaCipher = Cipher.getInstance(RSA_ENCRYPTION);
		rsaCipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] finalBytes = rsaCipher.doFinal(byteArray);
        return finalBytes;
	}
	
	public void generateAES() throws NoSuchAlgorithmException{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        aesKey = keyGen.generateKey();
	}
	
	public SecretKey getSessionKey(){
		return aesKey;
	}
	
	public byte[] encryptWithKey(File file, SecretKey key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));

		int length = (int) file.length();
		int count = 0;
		
		byte[] byteArray = new byte[length];

		int a = 0;
		while(a != -1 && count < length){
			a = bufferedInputStream.read();
			System.out.println(a);
			byteArray[count] = (byte) a;
			count++;
		}
		
		Cipher aesCipher = Cipher.getInstance(AES_ENCRYPTION);
		aesCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] finalBytes = aesCipher.doFinal(byteArray);
        return finalBytes;
	}
	
	public byte[] decryptWithKey(File file, SecretKey key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));

		int length = (int) file.length();
		int count = 0;
		
		byte[] byteArray = new byte[length];

		int a = 0;
		while(a != -1 && count < length){
			a = bufferedInputStream.read();
			System.out.println(a);
			byteArray[count] = (byte) a;
			count++;
		}
		
		Cipher aesCipher = Cipher.getInstance(AES_ENCRYPTION);
		aesCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] finalBytes = aesCipher.doFinal(byteArray);
        return finalBytes;
	}
	
	public static void appendBytesToFile(byte[] bytes, File file) throws IOException{
		FileOutputStream fileOutputStream = new FileOutputStream(file, true);
		fileOutputStream.write(bytes);
		fileOutputStream.close();
	}
}
