package protocol;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * How to run:
 * 
 * 1.	Place the file to be sent in the folder "client"
 * 2.	Specify the name of the file in the program arguments
 * 3.	Run program
 * 
 * @author tes
 *
 */
public class AESClient extends Client implements Runnable {
	public AESClient() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeySpecException, IOException {
		super();
	}

	public static void main(String[] args) throws UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		for(String arg: args){
			TRANSFER_FILE_NAME = arg;
			TRANSFER_FILE_PATH = CLIENT_LOCATION_DIR + TRANSFER_FILE_NAME;
			new AESClient().run();
			System.out.println("=============================");
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	@Override
	public void run(){
		System.out.println("Client connected");
		
		System.out.println(System.getProperty("user.dir"));
		try{
			File transferFile = new File(TRANSFER_FILE_PATH);
			long fileLength = transferFile.length();
			
			setSocket(new Socket(LOCALHOST, 4321));
			System.out.println("Attempting to authenticate");
			if(clientAuthenticate())
				System.out.println("Authenticated");
			else{
				System.out.println("Authentication failed");
				return;
			}
			super.cryptoManager.generateAES();
			sendSessionKey(super.cryptoManager.getSessionKey().getEncoded());
				
			long aesStart = System.currentTimeMillis();
			uploadAES(transferFile);
			
			long aesTime = System.currentTimeMillis() - aesStart;
			System.out.println("AES time taken: " + aesTime);
			FileOutputStream fileOutputStream = new FileOutputStream(new File("outputResults"), true);
			PrintWriter fileOut = new PrintWriter(fileOutputStream);
			fileOut.format("AES\t\tTime: %d\t\tSize: %d\n", aesTime, transferFile.length());
			fileOut.close();
		}catch (Exception e){
			e.printStackTrace();
		}
	}
}
