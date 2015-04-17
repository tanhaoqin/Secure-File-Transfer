import java.io.BufferedReader;
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
		this.socket = socket;
		this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		this.out = new PrintWriter(socket.getOutputStream());
	}
	
	@Override
	public void run() {
		String input;
		try {
			while((input = in.readLine()) != END_PROTOCOL){
				if(input.equals(IDENTITY_PROTOCOL)){
					
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}