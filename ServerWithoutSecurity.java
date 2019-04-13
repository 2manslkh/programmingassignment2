package com.example.lib_probset2;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerWithoutSecurity {

	public static void main(String[] args) throws Exception{
		System.out.println("Started Server...");
		String certname = "server.crt";
		String encryptedMessage = Auth.encryptString("Hello, this is SecStore!");
		InputStream serverCert = new FileInputStream(certname);

		int numBytes = 0;

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			//TODO: Send serverCert to Client upon request (established connection)
			sendCertificateToClient(toClient,certname);

			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

	public static void sendCertificateToClient(DataOutputStream toClient, String filename) throws IOException {
		int numBytes = 0;

		// Send the filename
		toClient.writeInt(0); //packettype
		toClient.writeInt(filename.getBytes().length); //numbytes
		toClient.write(filename.getBytes());
		toClient.flush();

		// Open the file
		FileInputStream fileInputStream = new FileInputStream(filename);
		BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

		byte [] fromFileBuffer = new byte[117];

		// Send the file
		for (boolean fileEnded = false; !fileEnded;) { // sets file ended to false everytime it loops
			numBytes = bufferedFileInputStream.read(fromFileBuffer);
			fileEnded = numBytes < 117;

			toClient.writeInt(1);
			toClient.writeInt(numBytes);
			toClient.write(fromFileBuffer);
			toClient.flush();
		}
		System.out.println("Server: Sent Certificate");
	}
}
