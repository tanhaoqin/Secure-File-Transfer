import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class CryptoManager {
	
	PrivateKey privateKey;
	PublicKey publicKey;
	
	public CryptoManager(File privateKeyFile) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		FileInputStream privateKeyFileStream = new FileInputStream(privateKeyFile);
		byte[] privateKeyArray = new byte[privateKeyFileStream.available()];
		privateKeyFileStream.read(privateKeyArray);
		privateKeyFileStream.close();
		
		X509EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(privateKeyArray);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		privateKey = keyFactory.generatePrivate(privateKeySpec);

		
	}

	public void addPublicKey(File publicKeyFile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{
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
		
		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] finalBytes = rsaCipher.doFinal(byteArray);
        return finalBytes;
	}
	
	
}
