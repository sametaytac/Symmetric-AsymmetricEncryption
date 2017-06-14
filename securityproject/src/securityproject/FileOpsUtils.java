package securityproject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Scanner;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;

public class FileOpsUtils {

public static void writeToFile(File output, byte[] toWrite) throws IOException
	{
FileOutputStream fos = new FileOutputStream(output);
fos.write(toWrite);
fos.flush();
fos.close();
}


public static void writeToFile(String path, byte[] key) throws IOException
{
File f = new File(path);
f.getParentFile().mkdirs();

FileOutputStream fos = new FileOutputStream(f);
fos.write(key);
fos.flush();
fos.close();
}






public static byte[] getFileInBytes(File f) throws IOException {
FileInputStream fis = new FileInputStream(f);
byte[] fbytes = new byte[(int) f.length()];
fis.read(fbytes);
fis.close();
return fbytes;
}


public static Collection getFilePaths(String source){
File dir = new File(source);
Collection files = FileUtils.listFiles(
		  dir, null, true);

return files;

}


public static void copyDirectory(String source,String mode) throws IOException
{
	

String dest = new String();
if(mode.equals("enc"))
dest = source + "_encrypted";
else
dest = source.replace("_encrypted","");
//dest = source.replace("_encrypted","_decrypted");


File destDir = new File(dest);
File sourceDir = new File(source);
FileUtils.forceMkdir(destDir);

FileUtils.copyDirectory(sourceDir ,destDir);

for(File file: FileUtils.listFiles(destDir, null, true)) 
    if (!file.isDirectory()) 
        file.delete();




}

public static String readStringfromFile(String path) throws FileNotFoundException
{
	Scanner scanner = new Scanner( new File(path) );
	String str = scanner.useDelimiter("\\A").next();
	scanner.close(); // Put this call in a finally block
		return str;

}






}
