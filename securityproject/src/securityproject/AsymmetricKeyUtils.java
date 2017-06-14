package securityproject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.FileUtils;




public class AsymmetricKeyUtils {

		//create public-private key pairs
	public static KeyPair createKeys(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(keylength,random);
		return keyGen.generateKeyPair();
		
	}
	//encrypt single file and write it to destination
	public static void encryptFile(byte[] input, File output, PublicKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException, NoSuchPaddingException
			 {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			FileOpsUtils.writeToFile(output, cipher.doFinal(input));
		}
	
	//encrypt file with public key
	public static byte[] encryptWithPublic(byte[] input,byte[] key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException
	 {
		
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		
		
		
	Cipher cipher = Cipher.getInstance("RSA");
	cipher.init(Cipher.ENCRYPT_MODE, pubKey);
	return cipher.doFinal(input);
}
	//encrypt file with private key(for authentication)
	public static byte[] encryptWithPrivate(byte[] input,byte[] key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException
	 {
		
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey priKey = keyFactory.generatePrivate(keySpec);
		
		
		
	Cipher cipher = Cipher.getInstance("RSA");
	cipher.init(Cipher.ENCRYPT_MODE, priKey);
	return cipher.doFinal(input);
}	
	public static PrivateKey bytetoPrivateKey(byte[] input) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(input);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey priKey = keyFactory.generatePrivate(keySpec);
		return priKey;
		
	}
	
	
	//decrypt single file and write it to dest
	public static void decryptFile(byte[] input, File output, PrivateKey key)
			throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		    Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			FileOpsUtils.writeToFile(output, cipher.doFinal(input));
		}
	//decrypt single file and return it
	public static byte[] decryptFile(byte[] input, PrivateKey key)
			throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		    Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(input);
		}
	


	
	
}
