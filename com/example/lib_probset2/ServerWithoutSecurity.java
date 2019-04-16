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
import java.security.PrivateKey;

import javax.xml.bind.DatatypeConverter;

public class ServerWithoutSecurity {

	public static void main(String[] args) throws Exception{
		System.out.println("Started Server...");
		String certname = "server.crt";
		String privatekeyname = "privateServer.der";
		PrivateKey privateKey = Auth.readPrivateKey(privatekeyname);
		byte[] encryptedMessage = Auth.encryptString("Hi", privateKey);
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

			// AUTHENTICATION PROTOCOL (START) //
			// Receive Nonce
			int nonce = readNonce(fromClient);
			System.out.println(nonce);

			// Encrypt Nonce
			byte [] encryptedNonce = Auth.encryptNonce(nonce, privateKey);

			// Send encrypted message w/ nonce (encrypted using private key)
			toClient.writeInt(encryptedMessage.length);
			toClient.write(encryptedMessage);
			toClient.writeInt(encryptedNonce.length);
			toClient.write(encryptedNonce);

			// Send serverCert to Client upon request (established connection)
			sendCertificateToClient(toClient,certname);
			// AUTHENTICATION PROTOCOL (END) //

			// TODO: CP2: Receive Session Key

			// TODO: CP2: Decrypt Session Key

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
					
					// CP1: Decrypt Filename using Private Key
					byte[] decryptedFilename = ClientCP1.decrypt(filename, privateKey);

					// TODO:CP2: Decrypt Filename using Session Key
					numBytes = decryptedFilename.length;
					
					fileOutputStream = new FileOutputStream("recv_"+new String(decryptedFilename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1 || packetType == 2) {

					numBytes = fromClient.readInt();
					System.out.println("CLIENT SENT:"+numBytes);
					byte[] encryptedBlock = new byte[numBytes]; // encrypted block from client
					fromClient.readFully(encryptedBlock, 0, numBytes);
					System.out.println("received encryptedBlock: " + DatatypeConverter.printBase64Binary(encryptedBlock));

					// CP1: Decrypt File Blocks using Private Key
					byte[] decryptedBlock = ClientCP1.decrypt(encryptedBlock, privateKey);
					int decryptednumBytes = decryptedBlock.length;

					// TODO:CP2: Decrypt File Blocks using Session Key

					bufferedFileOutputStream.write(decryptedBlock, 0, decryptednumBytes);

					if (packetType ==  2) {
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

	private static int readNonce(DataInputStream fromClient) throws IOException {
		System.out.println("Server: Nonce Received");
		return fromClient.readInt();
	}

	public static void sendCertificateToClient(DataOutputStream toClient, String filename) throws IOException {
		int numBytes = 0;

		System.out.println("Server: Sending Certificate");
		// Send the filename
		toClient.writeInt(0); //packettype
		toClient.writeInt(filename.getBytes().length); //numbytes
		toClient.write(filename.getBytes());

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
