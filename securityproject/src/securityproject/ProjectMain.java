package securityproject;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.FileUtils;

public class ProjectMain {

	public static void main(String[] args) throws Exception {

		
////////////////////////////////
		
/////////////FOR DEMO	
		
		
		String input = new String();
		String input2 = new String();
		String input3 = new String();
		String input4 = new String();
		UserKeys samet=new UserKeys("DEMO/sametUSB");

		while(true)
		{
			

		    System.out.println("1. Create new key pair\n"
		    		+		   "2. Encrypt a directory\n"
		    		+		   "3. Decrypt a directory\n"
		    		+ 		   "4. Exit");
		    System.out.println("Enter a choice");
	        BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
	        input4 = bufferRead.readLine();

	        


	    
	    
		//create new key
		if(input4.equals("1"))
		{
			System.out.println("Enter keyname");
			//keyname
	        input = bufferRead.readLine();
	        System.out.println("Enter password");
			//password
			input2 = bufferRead.readLine();
			samet.createKeys(input, 1024,input2);
		}
		if(input4.equals("2"))
		{
			System.out.println("Enter filename");
	        input = bufferRead.readLine();
			System.out.println("Enter keyname");
	        input2 = bufferRead.readLine();
			System.out.println("Enter password");
	        input3 = bufferRead.readLine();
			samet.SymmetricEncrypt(input,input3,input2);

			
		}
		
		if(input4.equals("3"))
		{
			System.out.println("Enter filename");
	        input = bufferRead.readLine();
			System.out.println("Enter password");
	        input2 = bufferRead.readLine();
			samet.SymmetricDecrypt(input,input2);

			
		}
		
		if(input4.equals("4"))
		{
			
			break;
		}

		
		
		}
		
////////////////////////////////		
		
		
		
////////////////////////////////
///////////////// FOR PERFORMANCE EVALUATION
		/*
		UserKeys samet=new UserKeys("DEMO/sametUSB");


		long startTime = System.nanoTime();
		
		samet.createKeys("schoole", 1024, "password");
		
		long stopTime = System.nanoTime();
		System.out.println("Key creation duration is:");
		System.out.println(stopTime - startTime);

		
		startTime = System.nanoTime();

		samet.SymmetricEncrypt("DEMO/example100gb","password","schoole");

		
		stopTime = System.nanoTime();
		System.out.println("Encryption duration is:");

		System.out.println(stopTime - startTime);
		
		startTime = System.nanoTime();

		samet.SymmetricDecrypt("DEMO/example100gb_encrypted","password");
		stopTime = System.nanoTime();
		
		System.out.println("Decryption duration is:");
		System.out.println(stopTime - startTime);
		
		*/
////////////////////////////////	
		

		
	}


}
