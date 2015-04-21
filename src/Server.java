import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;


public class Server {

	
	private static ServerSocket serverSocket;

	public static void main(String[] args) throws IOException {
		
		serverSocket = new ServerSocket(4321);
		new Thread(new Runnable() {
			
			@Override
			public void run() {
				while(true){
					try {
						Socket socket = serverSocket.accept();
						new Thread(new ClientHandler(socket)).start();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}).start();
	}
}

class ClientHandler implements Runnable{

	private static final String END_PROTOCOL = "END_PROTOCOL";
	private static final String IDENTITY_PROTOCOL = "IDENTITY_PROTOCOL";
	Socket socket;
	BufferedReader in;
	PrintWriter out;
	
	public ClientHandler(Socket socket) throws IOException {
		System.out.println("Client connected");
		this.socket = socket;
		this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		this.out = new PrintWriter(socket.getOutputStream());
	}
	
	@Override
	public void run() {
		String input;
		try {
			while(!(END_PROTOCOL).equals(input = in.readLine())){
//				Handle file transfer
				if(Client.FILE_TRANSFER_START.equals(input)){
					
					String fileName = "server//"+in.readLine();
					System.out.println("File name: "+fileName);
					
					int length = Integer.parseInt(in.readLine());

					int count = 0;
					
					byte[] byteArray = new byte[length];
					
					BufferedInputStream bufferedInputStream = new BufferedInputStream(socket.getInputStream());

					int a = 0;
					while(a != -1 && count < length){
						a = bufferedInputStream.read();
						System.out.println(a);
						byteArray[count] = (byte) a;
						count++;
					}
					
					FileOutputStream fileOutputStream = new FileOutputStream(fileName);
					fileOutputStream.write(byteArray);
					fileOutputStream.close();
				}
				else if(Client.CERTIFICATE_REQUEST.equals(input)){
					
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void accept
}