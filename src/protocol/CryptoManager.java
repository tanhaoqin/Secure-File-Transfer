package protocol;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;


public class CryptoManager {
	
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private SecretKey aesKey;
	private SecretKeySpec aesKeySpec;
	
	public static final String AES_ENCRYPTION = "AES";
	public static final String RSA_ENCRYPTION = "RSA";
	
	public CryptoManager() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
	}

	public void setPrivateKey(File privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
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
		
		byte[][] byteBlocks = splitArrayUp(byteArray,117);		
		byte[] finalBytes = new byte[byteArray.length];
		for(int i = 0; i< byteBlocks.length; i++){
			System.arraycopy(rsaCipher.doFinal(byteBlocks[i]), 0, finalBytes, i*128, byteBlocks[i].length);
		}
		
		
        bufferedInputStream.close();
        return finalBytes;
	}
	
	public byte[] encryptWithPublicKey(File file) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
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
		rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		
		byte[][] byteBlocks = splitArrayUp(byteArray,117);		
		byte[] finalBytes = new byte[(byteArray.length/117 + 1)*128];
		for(int i = 0; i< byteBlocks.length; i++){
			System.out.println("a: "+rsaCipher.doFinal(byteBlocks[i]).length);
			System.out.println(finalBytes.length);
			System.out.println(i*128+127);
			System.arraycopy(rsaCipher.doFinal(byteBlocks[i]), 0, finalBytes, i*128, 128);
		}
		
        bufferedInputStream.close();
        return finalBytes;
	}
	
	public byte[] encryptWithPublicKey(byte[] byteArray) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
		Cipher rsaCipher = Cipher.getInstance(RSA_ENCRYPTION);
		rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
		byte[][] byteBlocks = splitArrayUp(byteArray,117);		
		byte[] finalBytes = new byte[(byteArray.length/117 + 1)*128];
		for(int i = 0; i< byteBlocks.length; i++){
			System.arraycopy(rsaCipher.doFinal(byteBlocks[i]), 0, finalBytes, i*128, 128);
		}
		
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
		
		byte[][] byteBlocks = splitArrayUp(byteArray,128);		
		byte[] finalBytes = new byte[byteArray.length];
		for(int i = 0; i< byteBlocks.length; i++){
			System.arraycopy(rsaCipher.doFinal(byteBlocks[i]), 0, finalBytes, i*128, byteBlocks[i].length);
		}
		
        bufferedInputStream.close();
        return finalBytes;
	}
	
	public byte[] decryptWithPrivateKey(File file) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
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
		rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
		
		byte[][] byteBlocks = splitArrayUp(byteArray,128);		
		byte[] finalBytes = new byte[byteArray.length];
		for(int i = 0; i< byteBlocks.length; i++){
			byte[] decryptedBytes = rsaCipher.doFinal(byteBlocks[i]);
			System.arraycopy(decryptedBytes, 0, finalBytes, i*128, decryptedBytes.length);
		}
		
        bufferedInputStream.close();
        return finalBytes;
	}
	
	
	public String decryptWithPublicKey(String string) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{		
		byte[] byteArray = Base64.decode(string);

		Cipher rsaCipher = Cipher.getInstance("RSA");
		rsaCipher.init(Cipher.DECRYPT_MODE, publicKey);
		
		byte[][] byteBlocks = splitArrayUp(byteArray,128);		
		byte[] finalBytes = new byte[byteArray.length];
		for(int i = 0; i< byteBlocks.length; i++){
			System.out.println(byteBlocks[i].length);
			byte[] decryptedArray = rsaCipher.doFinal(byteBlocks[i]);
			System.arraycopy(decryptedArray, 0, finalBytes, i*128, decryptedArray.length);
		}
		
        return new String(finalBytes,"UTF8");
	}
	
	public String encryptWithPrivateKey(String string) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{		
		byte[] byteArray = string.getBytes("UTF8");
		
		Cipher rsaCipher = Cipher.getInstance(RSA_ENCRYPTION);
		rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
		
		byte[][] byteBlocks = splitArrayUp(byteArray,117);		
		byte[] finalBytes = new byte[(byteArray.length/128 + 1)*128];
		
		for(int i = 0; i< byteBlocks.length; i++){
			System.out.println(finalBytes.length);
			System.out.println("length: "+rsaCipher.doFinal(byteBlocks[i]).length);
			System.out.println("byteblock length: "+byteBlocks[i].length);
			System.arraycopy(rsaCipher.doFinal(byteBlocks[i]), 0, finalBytes, i*128, 128);
		}
		
        return Base64.encode(finalBytes);
	}
	
	public void generateAES() throws NoSuchAlgorithmException{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
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
		
        bufferedInputStream.close();
        return aesCipher.doFinal(byteArray);
	}
	
	public byte[] decryptWithKey(File file, SecretKeySpec key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		DataInputStream bufferedInputStream = new DataInputStream(new FileInputStream(file));

		int length = (int) file.length();
		int count = 0;
		
		byte[] byteArray = new byte[length];

//		int a = 0;
//		while(a != -1 && count < length){
//			a = bufferedInputStream.read();
//			System.out.println(a);
//			byteArray[count] = (byte) a;
//			count++;
//		}
		
		bufferedInputStream.readFully(byteArray);
		
		Cipher aesCipher = Cipher.getInstance(AES_ENCRYPTION);
		aesCipher.init(Cipher.DECRYPT_MODE, key);
		
        bufferedInputStream.close();
        return aesCipher.doFinal(byteArray);
	}
	
	public static void appendBytesToFile(byte[] bytes, File file) throws IOException{
		FileOutputStream fileOutputStream = new FileOutputStream(file, true);
		fileOutputStream.write(bytes);
		fileOutputStream.close();
	}
	
	public void addPublicKeyFromCert(File certFile) throws FileNotFoundException, CertificateException{
		FileInputStream certFileStream = new FileInputStream(certFile);
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFileStream);
		
		this.publicKey = certificate.getPublicKey();
	}

	public SecretKeySpec getAESKeyFromFile(File secretKeyFile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
		FileInputStream secretKeyFileStream = new FileInputStream(secretKeyFile);
		byte[] secretKeyByteArray = new byte[16];
		secretKeyFileStream.read(secretKeyByteArray);
		secretKeyFileStream.close();
		
		return new SecretKeySpec(secretKeyByteArray, "AES");
	}
	
//	public ArrayList<byte[]> splitBytes117(byte[] bytes){
//		int noOfBlocks = bytes.length/117 + 1;
//		ArrayList<byte[]> bytesArray = new ArrayList<byte[]>();
//		for(int i = 0; i<noOfBlocks; i++){
//			int start = (i)*117;
//			int end = (i+1)*117 - 1;
//			int blockSize = 117;
//			if(end>bytes.length)
//				blockSize = bytes.length - i*blockSize;
//			byte[] byteBlock = new byte[blockSize];
//			for(int j = 0; j < blockSize - 1; j++){
//				if(start+j<bytes.length)
//					byteBlock[j] = bytes[start+j];
//			}
//			bytesArray.add(byteBlock);
//		}
//		return bytesArray;
//	}
//	
//	public ArrayList<byte[]> splitBytes128(byte[] bytes){
//		int noOfBlocks = bytes.length/128 + 1;
//		ArrayList<byte[]> bytesArray = new ArrayList<byte[]>();
//		for(int i = 0; i<noOfBlocks; i++){
//			int start = (i)*128;
//			int end = (i+1)*128 - 1;
//			int blockSize = 128;
//			if(end>bytes.length)
//				blockSize = bytes.length - i*blockSize;
//			byte[] byteBlock = new byte[blockSize];
//			for(int j = 0; j < blockSize - 1; j++){
//				if(start+j<bytes.length)
//					byteBlock[j] = bytes[start+j];
//			}
//			bytesArray.add(byteBlock);
//		}
//		return bytesArray;
//	}
	
	public static byte[][] splitArrayUp(byte[] source, int chunksize) {
        byte[][] ret = new byte[(int)Math.ceil(source.length / (double)chunksize)][chunksize];
        int start = 0;
        for(int i = 0; i < ret.length; i++) {
            if(start + chunksize > source.length) {
                System.arraycopy(source, start, ret[i], 0, source.length - start);
            } else {
                System.arraycopy(source, start, ret[i], 0, chunksize);
            }
            start += chunksize ;
        }
        return ret;
    }
	
	public static byte[] joinTogether(byte[] a, byte[] b) {
		byte[] c = null;

		if (a == null) {
			c = new byte[b.length];
			System.arraycopy(b, 0, c, 0, b.length);
		} else {
			c = new byte[a.length + b.length];
			System.arraycopy(a, 0, c, 0, a.length);
			System.arraycopy(b, 0, c, a.length, b.length);
		}
		return c;
	}

	
}


