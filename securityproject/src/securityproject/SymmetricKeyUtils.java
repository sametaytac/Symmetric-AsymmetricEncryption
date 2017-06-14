package securityproject;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.FileUtils;

public class SymmetricKeyUtils {

    private static final String ALGORITHM = "AES";

	
	
	
    public static byte[] encrypt(byte[] plainText,String keyString) throws Exception
    {
    	
    	byte[] key = keyString.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(plainText);
    }
    
    
    public static byte[] encrypt(byte[] plainText,SecretKey key) throws Exception
    {
    	
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(plainText);
    }
    
    
    

    /**
     * Decrypts the given byte array
     *
     * @param cipherText The data to decrypt
     */
    public static byte[] decrypt(byte[] cipherText,String keyString) throws Exception
    {
    	
    	
    	byte[] key = keyString.getBytes(StandardCharsets.UTF_8);
    	
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(cipherText);
    }
    
    
    
    
    public static byte[] decrypt(byte[] cipherText,SecretKey key) throws Exception
    {
    	


        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(cipherText);
    }
    
    
    
    
    
	
	
    
    public static void encryptDirectory(String dirName, SecretKey publicKey) throws Exception
	{
		FileOpsUtils.copyDirectory(dirName,"enc");
		//get paths of files
		
		
		
		////////

		String[] files = dirName.toString().split("/") ;
		
		int flag=files.length-1;
		//////////
		Collection filePaths=FileOpsUtils.getFilePaths(dirName);
		
		
		
		
		
		/*deneme
		AsymmetricKeyUtils.encryptFile(AsymmetricKeyUtils.getFileInBytes(new File("example//ex1.txt")),
				new File("example_encrypted//ex1.txt"),samet.getPublicKey());
		*/
		
		for(Object f : filePaths)
		{
			
			String[] parts = f.toString().split(Pattern.quote(File.separator)) ;
			parts[0+flag]=parts[0+flag]+ "_encrypted";
			String encryptedFiles=new String(parts[0+flag]);
			for (int i=1+flag;i<parts.length;i++)
			{
				encryptedFiles +="//" + parts[i];
				
				
			}
			////
			String temp=new String();
			for(int i=0;i<files.length-1;i++)
				temp+= files[i] + "//"; 
			
			if(files.length>1)
			encryptedFiles = temp + encryptedFiles; 
					
					
					
			///
		FileOpsUtils.writeToFile(new File(encryptedFiles), encrypt(FileOpsUtils.getFileInBytes(new File(f.toString())),publicKey));

			
		}
		FileUtils.deleteDirectory(new File(dirName));

		
	}
    
    
    
    
    public static void decryptDirectory(String dirName, SecretKey publicKey) throws Exception
	{
		FileOpsUtils.copyDirectory(dirName,"dec");
		//get paths of files
		/////////////
		String[] files = dirName.toString().split("/") ;
		
		int flag=files.length-1;
		/////////////
		Collection filePaths=FileOpsUtils.getFilePaths(dirName);
		
		
		
		
		
		/*deneme
		AsymmetricKeyUtils.encryptFile(AsymmetricKeyUtils.getFileInBytes(new File("example//ex1.txt")),
				new File("example_encrypted//ex1.txt"),samet.getPublicKey());
		*/
		
		for(Object f : filePaths)
		{
			
			String[] parts = f.toString().split(Pattern.quote(File.separator)) ;
			parts[0+flag]=parts[0+flag].replace("_encrypted","");
			//parts[0+flag]=parts[0+flag].replace("_encrypted","_decrypted");
			if(parts[parts.length-1].equals("configkey") || parts[parts.length-1].equals("configID"))
				continue;
			String decryptedFiles=new String(parts[0+flag]);
			for (int i=1+flag;i<parts.length;i++)
			{
				decryptedFiles +="//" + parts[i];
				
				
			}
			
			String temp=new String();
			for(int i=0;i<files.length-1;i++)
				temp+= files[i] + "//"; 
			
			if(files.length>1)
			decryptedFiles = temp + decryptedFiles; 
			
			
		FileOpsUtils.writeToFile(new File(decryptedFiles), decrypt(FileOpsUtils.getFileInBytes(new File(f.toString())),publicKey));

			
		}
		
		FileUtils.deleteDirectory(new File(dirName));

		
		
		
	}
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
	
	
}
