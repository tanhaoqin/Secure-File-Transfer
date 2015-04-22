package tests;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import protocol.CryptoManager;


public class CryptoManagerTest {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, CertificateException {
		
		//Testing RSA features
		CryptoManager cryptoManager = new CryptoManager();
		cryptoManager.setPrivateKey(new File("certs//privateServer.der"));
		cryptoManager.addPublicKeyFromCert((new File("server//server.crt")));
		
//		byte[] encryptedRSATestFile = cryptoManager.encryptWithPrivateKey(new File("tests//haiku.txt"));
//		cryptoManager.appendBytesToFile(encryptedRSATestFile, new File("tests//haikuEncrypted.txt"));
//		
//		byte[] decryptedRSATestFile = cryptoManager.decryptWithPublicKey(new File("tests//haikuEncrypted.txt"));
//		cryptoManager.appendBytesToFile(decryptedRSATestFile, new File("tests//haikuDecrypted.txt"));
//		
//		cryptoManager.generateAES();
//		SecretKey sessionKey = cryptoManager.getSessionKey();
//		
//		//Testing AES features
//		byte[] encryptedAESTestFile = cryptoManager.encryptWithKey(
//				new File("tests//haiku.txt"), sessionKey);
//		cryptoManager.appendBytesToFile(encryptedAESTestFile, new File("tests//haikuEncryptedAES.txt"));
//		
//		byte[] decryptedAESTestFile = cryptoManager.decryptWithKey(
//				new File("tests//haikuEncryptedAES.txt"), sessionKey);
//		cryptoManager.appendBytesToFile(decryptedAESTestFile, new File("tests//haikuDecryptedAES.txt"));
		
		String testString = "Hello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello World";
		String encryptedRSATestString = cryptoManager.encryptWithPrivateKey(testString);
		
		String decryptedRSATestString = cryptoManager.decryptWithPublicKey(encryptedRSATestString);
		
		System.out.println(decryptedRSATestString);
		System.out.println(testString.length());
		System.out.println(decryptedRSATestString.length());
	}
	
}
