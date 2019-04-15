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
import javax.crypto.Cipher;

public class ClientWithoutSecurity {

	public static void main(String[] args) throws Exception {
		// Client Certificate
		InputStream clientCert = new FileInputStream("cacse.crt");
		X509Certificate clientCertX509 = Auth.getX509Certificate(clientCert);
		PublicKey publicKey = null;

    	String filename = "test.txt";
    	if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
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

			//Send Nonce to server
			int nonce = Nonce.getInt();
			sendNonce(toServer, nonce);

			//Receive Encrypted Nonce and Message from Server
			// TODO: Make into a function?
			
			
			int encyptedmlength = fromServer.readInt();
//			System.out.println(encyptedmlength);
			byte[] encryptedm = new byte[encyptedmlength];
			fromServer.read(encryptedm,0,encyptedmlength);

			int encyptednoncelength = fromServer.readInt();
//			System.out.println(encyptednoncelength);
			byte[] encryptedNonce = new byte[encyptednoncelength];
			fromServer.read(encryptedNonce,0,encyptednoncelength);

			// Read Certificate sent by server
			readCertificate(fromServer);

			// Check if Server is verified
			if(!Auth.verifiedServer("recv_server.crt")) // always returns true for now
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
				System.out.println("Nonce Verified");
			}

			System.out.println("Sending file...");

			///////////////////////////////////////////////////////////////////////////

			// TODO: Encrypt Filename USING PUBLICKEY (publicKey)
			Cipher rsaCipherEncrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, publicKey);
	        
			// TODO: Write the encryption procedure in ClientCP1



			// Send the encrypted filename (filename should be changed to encryptedfilename)
			toServer.writeInt(0); // this is just to tell the server that we are sending a filename next
			toServer.writeInt(filename.getBytes().length); // tells the server how many bytes we are sending
			toServer.write(filename.getBytes());
			toServer.flush();
			
			byte [] filenameBytes = filename.getBytes();
			byte [] filenameBytesEncrypted = null;

			toServer.write(filenameBytesEncrypted); // sends the file name in byte array
//			toServer.flush(); // dont need to use just put here first

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        byte [] fromFileBuffer = new byte[117]; //holds 117 bytes of data before being transferred

	        // Send the file
	        for (boolean fileEnded = false; !fileEnded;) { // constantly sends chunks of 117 bytes
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117; // if the chunk is less than 117 bytes, it signifies the end of file (EOF)

				// TODO: Encrypt fromFileBuffer before sending PUBLICKEY (publicKey)
				// it only matters that we are sending encrypted bytes
				// we could encrypt the whole file first then send but that will take longer

				toServer.writeInt(1); // Tells the server that we are sending a file
				toServer.writeInt(numBytes); // Tells the server how many bytes we are sending over
				toServer.write(fromFileBuffer); // sends the chunk of file
				toServer.flush();
			}

	        bufferedFileInputStream.close();
	        fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}

	private static void sendNonce(DataOutputStream toServer, int nonce) throws IOException{
		System.out.println("Nonce Sent");
		toServer.writeInt(nonce);
	}

	private static void readCertificate(DataInputStream fromServer) throws IOException {
		int packetType = fromServer.readInt();
		BufferedOutputStream bufferedFileOutputStream = null;
		FileOutputStream fileOutputStream = null;
		boolean certReceieved = false;

		// If the packet is for transferring the filename
		while(!certReceieved){
			if (packetType == 0) {

				System.out.println("Receiving Certificate...");

				int numBytes = fromServer.readInt();
				byte[] filename = new byte[numBytes];
				// Must use read fully!
				// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
				fromServer.readFully(filename, 0, numBytes);

				fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
				bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
			}

			packetType = fromServer.readInt();
			if (packetType == 1) {

				int numBytes = fromServer.readInt();
				byte[] block = new byte[numBytes];
				fromServer.readFully(block, 0, numBytes);

				if (numBytes > 0)
					bufferedFileOutputStream.write(block, 0, numBytes);

				if (numBytes < 117) {
					System.out.println("Closing connection...");

					if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
					if (bufferedFileOutputStream != null) fileOutputStream.close();
//					fromServer.close();
	//                toClient.close();
	//                connectionSocket.close();
					System.out.println("Client: Server Certificate Received.");
					certReceieved = true;
				}
			}
		}
	}
}

