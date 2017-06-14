package securityproject;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;
public class UserKeys {
	
	
	public SecretKey secretKey;
	
	
	//file path of USB
	private String keyPath;
	
	//Public-Private key pair ID's
	private List<String> keyPairIDs= new ArrayList<String>();
	
	//initialization of user
	public UserKeys(String keyPath) throws Exception
	
	{

		this.keyPath=keyPath;
		
		
	}
	
	
	
	//create new public-private key.Encrypt key pair with password and place it in USB. 
	public void createKeys(String keyPairID,int keySize, String password) throws IOException, Exception
	{
		//create public and private key pairs
		keyPairIDs.add(keyPairID);
		KeyPair pair = AsymmetricKeyUtils.createKeys(keySize);
				/* Key test
        byte[] publicKey = pair.getPublic().getEncoded();
        StringBuffer retString = new StringBuffer();
        for (int i = 0; i < publicKey.length; ++i) {
            retString.append(Integer.toHexString(0x0100 + (publicKey[i] & 0x00FF)).substring(1));
        }
        System.out.println(retString);
        */

        
        
        
        
        /////////////////////////////////
		//encrypt and write private key to USB
		FileOpsUtils.writeToFile(keyPath+"/privateKey"+keyPairID, SymmetricKeyUtils.encrypt(pair.getPrivate().getEncoded(),password+new StringBuffer(password).reverse().toString()));
		//encrypt and write public key to USB
		FileOpsUtils.writeToFile(keyPath+"/publicKey"+keyPairID, SymmetricKeyUtils.encrypt(pair.getPublic().getEncoded(),password+new StringBuffer(password).reverse().toString()));
		
	}
	
	//Recursively encrypt a folder with symmetric key.Put _encrypted extension to folder.
	public void SymmetricEncrypt(String dirName,String password,String KeyPairID) throws Exception
	
	{
		
		//symmetric key generation
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128); // for example
		SecretKey secretKey = keyGen.generateKey();
		this.secretKey=secretKey;
		//recursively encrypt given directory with symmetric key
		SymmetricKeyUtils.encryptDirectory(dirName, secretKey);
		//encrypt symmetric key with BURAYI UNUTMA
		placeSymmetricKey(password,KeyPairID, secretKey, dirName);
		
		
		
		
		
		
	}
	

	
	//Decrypt given directory. Read symmetric key from file 

	public void SymmetricDecrypt(String dirName,String password) throws Exception
	
	{
		//symmetric key encrypted with public
		byte[] encKey = FileOpsUtils.getFileInBytes(new File(dirName + "/configkey"));


		

		
		String ID = FileOpsUtils.readStringfromFile(dirName + "/configID");
		//fetch private key from USB
		byte [] privateKey = getKeyFromUSB(password, ID, "private");
		//from byte array to PrivateKey
		PrivateKey pKey = AsymmetricKeyUtils.bytetoPrivateKey(privateKey);
		//decrypt sessionKey
		byte[] sessionKey = AsymmetricKeyUtils.decryptFile(encKey, pKey);

		SecretKey sKey = new SecretKeySpec(sessionKey, "AES"); 
		SymmetricKeyUtils.decryptDirectory(dirName, sKey);
		
		
	}
	
	// read and decrypt key with password from USB
	private byte[] getKeyFromUSB(String password,String ID, String mode) throws Exception
	{
		String filePath;
		//for private
		if(mode.equals("private"))
			filePath = keyPath+"/privateKey"+ ID;
		//for public
		else
			filePath = keyPath+"/publicKey"+ ID;
		//read encrypted key
		byte[] encKey = FileOpsUtils.getFileInBytes(new File(filePath));
		

		
		//decrypt it
		byte[] key = SymmetricKeyUtils.decrypt(encKey,password+new StringBuffer(password).reverse().toString());
		
		return key;
		
	} 
	
	
	private void placeSymmetricKey(String password, String ID,SecretKey secretKey, String dirname) throws Exception
	{
		//get public and private key from USB
		byte [] publicKey = getKeyFromUSB(password, ID,"public");

		
		byte [] encryptedKey =  AsymmetricKeyUtils.encryptWithPublic(secretKey.getEncoded(), publicKey);
		

		FileOpsUtils.writeToFile(new File(dirname+"_encrypted/configkey"), encryptedKey);
		FileOpsUtils.writeToFile(new File(dirname+"_encrypted/configID"), ID.getBytes());

	}
	
	
	
	
	
	
	
	
	
	
}
