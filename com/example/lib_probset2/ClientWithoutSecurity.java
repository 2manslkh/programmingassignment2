package com.example.lib_probset2;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

public class ClientWithoutSecurity {

	public static void main(String[] args) throws Exception {
		// Client Certificate
		int CPMODE = 1;
		InputStream clientCert = new FileInputStream("cacse.crt");
		X509Certificate clientCertX509 = Auth.getX509Certificate(clientCert);
		PublicKey publicKey = null;
		SecretKey sessionKey = null;

    	String filename = "longtext.txt";
    	if (args.length > 0) filename = args[0];

    	String serverAddress = "10.12.154.107";
    	if (args.length > 1) filename = args[1];

    	int port = 4321;
    	if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		long timeStarted = System.nanoTime();


		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// AUTHENTICATION PROTOCOL (START) //
			//Send Nonce to server
			int nonce = Nonce.getInt();
			sendNonce(toServer, nonce);

			//Receive Encrypted Nonce and Message from Server
			byte[] encryptedM = readEncryptedMessage(fromServer);
			byte[] encryptedNonce = readEncryptedMessage(fromServer);

			// Read Certificate sent by server
			String certname = readCertificate(fromServer);

			// Check if Server is verified
			if(!Auth.verifiedServer(certname)) // always returns true for now
				System.out.println("Authentication Failed. Closing Connections");
//				bufferedFileInputStream.close();
//				fileInputStream.close();
			else{
				publicKey = Auth.getPublicKey("recv_server.crt"); // extract public key from cert
			}

			// Check if Nonce is Verifiable
			if(!Auth.verifiedNonce(encryptedNonce,nonce,publicKey))
				System.out.println("Nonce is not correct, Closing Connections");
//				bufferedFileInputStream.close();
//				fileInputStream.close();
			else{
				System.out.println("Client: Nonce Verified");
			}

			// AUTHENTICATION PROTOCOL (END) //

			System.out.println("Client: Sending filename...");

			byte[] filename_bytes = filename.getBytes();
			byte[] encryptedFilename = new byte[128];
			if (CPMODE == 1) {
				// CP1: Encrypt Filename using Public Key
				encryptedFilename = ClientCP1.encrypt(filename_bytes, publicKey);
			} else if (CPMODE == 2) {
				// TODO:CP2: Generate Session Key
				sessionKey = ClientCP2.generateSessionKey();
				byte[] sessionKeyBytes = sessionKey.getEncoded();
				// TODO:CP2: Encrypt Session Key
				byte[] encryptedbytesKs = ClientCP2.encryptSessionKey(sessionKeyBytes, publicKey);

				// TODO:CP2: Encrypt Filename using Session Key
				encryptedFilename = ClientCP2.encrypt(filename_bytes, sessionKey);

				// TODO:CP2: Send Encrypted Session Key
				toServer.writeInt(encryptedbytesKs.length);
				toServer.write(encryptedbytesKs);
			}

			// Send the encrypted filename (filename should be changed to encryptedfilename)
			toServer.writeInt(0); // this is just to tell the server that we are sending a filename next
			toServer.writeInt(encryptedFilename.length); // tells the server how many bytes we are sending
			toServer.write(encryptedFilename);

			System.out.println("Encrypted Filename sent:" + encryptedFilename.length + "bytes");

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);
			// Make File Buffers
	        byte[] fromFileBuffer = new byte[117]; // file buffer for reading
			byte[] fromFileBufferEncrypted = null; // byte array to hold encrypted bytes
	        // Send the file
	        for (boolean fileEnded = false; !fileEnded;) { // constantly sends chunks of 117 bytes
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				System.out.println("Block Contains: " + new String(fromFileBuffer));
				fileEnded = numBytes < 117; // if the chunk is less than 117 bytes, it signifies the end of file (EOF)

				if (CPMODE == 1) {
					// CP1: Encrypt File Blocks using Public Key
					fromFileBufferEncrypted = ClientCP1.encrypt(fromFileBuffer, publicKey);
				}else if (CPMODE == 2) {
					// TODO:CP2: Encrypt File Blocks using Session Key
					fromFileBufferEncrypted = ClientCP2.encryptSessionKey(fromFileBuffer, sessionKey);
				}

				if (!fileEnded) {  
					toServer.writeInt(1); // Tells the server that we are sending a file
				}else{
					toServer.writeInt(2); // Tells the server that we sent the last chunk
				}
				int numBytesEncrypted = fromFileBufferEncrypted.length;
				toServer.writeInt(numBytesEncrypted); // Tells the server how many bytes we are sending over
				toServer.write(fromFileBufferEncrypted); // sends the chunk of file
			}

	        bufferedFileInputStream.close();
	        fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}

	private static void sendNonce(DataOutputStream toServer, int nonce) throws IOException{
		System.out.println("Client: Nonce Sent");
		toServer.writeInt(nonce);
	}

	private static byte[] readEncryptedMessage(DataInputStream fromServer) throws IOException {
		int length = fromServer.readInt();
		byte[] m = new byte[length];
		fromServer.read(m,0,length);
		return m;
	}

	private static String readCertificate(DataInputStream fromServer) throws IOException {
		int packetType = fromServer.readInt();
		int numBytes = fromServer.readInt();
		boolean certReceieved = false;
		byte[] filename = new byte[numBytes];
		String certname = "";

		BufferedOutputStream bufferedFileOutputStream = null;
		FileOutputStream fileOutputStream = null;

		System.out.println("Client: Receiving Certificate...");

		while(!certReceieved){
			if (packetType == 0) {
				fromServer.readFully(filename, 0, numBytes);
				certname = "recv_" + new String(filename, 0, numBytes);
				fileOutputStream = new FileOutputStream(certname);
				bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
			}

			packetType = fromServer.readInt();

			if (packetType == 1) {
				numBytes = fromServer.readInt();
				byte[] block = new byte[numBytes];
				fromServer.readFully(block, 0, numBytes);
				if (numBytes > 0)
					bufferedFileOutputStream.write(block, 0, numBytes);
				if (numBytes < 117) {
					if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
					if (bufferedFileOutputStream != null) fileOutputStream.close();
					System.out.println("Client: Server Certificate Received.");
					certReceieved = true;
				}
			}
		}
		return certname;
	}
}

