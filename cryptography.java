package cs433_sec;


import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.nio.file.*;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.logging.*;

class RSA_HASHING {

    private Cipher m_chiper;

    public RSA_HASHING() throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {
        m_chiper = Cipher.getInstance("RSA");   
    }
    
    public Object LoadKey(String dirctory,boolean is_public)throws IOException, NoSuchAlgorithmException,InvalidKeySpecException {
		
                //read file
		File m_file = new File(dirctory);
		FileInputStream m_file_stream = new FileInputStream(dirctory);
		byte[] encodedKey = new byte[(int) m_file.length()];
		m_file_stream.read(encodedKey);
		m_file_stream.close();

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                
                // Public Key
                if(is_public){
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
                return publicKey;      
                }
                //private key
                else {
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
                return privateKey;
                }
		
	}

    public void GenerateKeys(String dirctory ) throws NoSuchAlgorithmException, IOException  {
        
        //Create key pair for  RSA 
        KeyPairGenerator rsa_key = KeyPairGenerator.getInstance("RSA") ;
        
        //set lengtb to 1024
        rsa_key.initialize(1024);
        
        //Generate key pairs
        KeyPair key_pair = rsa_key.generateKeyPair();
        
        //split keypair
        PrivateKey privateKey = key_pair.getPrivate();
        PublicKey publicKey = key_pair.getPublic();

        // Public Key
        X509EncodedKeySpec m_x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        FileOutputStream m_file_stream = new FileOutputStream(dirctory + "/Pub.pub");
        m_file_stream.write(m_x509EncodedKeySpec.getEncoded());
        m_file_stream.close();

        // Private Key
        PKCS8EncodedKeySpec m_pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        m_file_stream = new FileOutputStream(dirctory + "/Priv.key");
        m_file_stream.write(m_pkcs8EncodedKeySpec.getEncoded());
        m_file_stream.close();
    }
    

    public void PerformOperation(File m_file,String dirctory,boolean is_encrypt)throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException {
    
        String output = "encrypted";
        
        //set the mode either encryption or decryption
        if(is_encrypt)
        m_chiper.init(Cipher.ENCRYPT_MODE,(PublicKey)LoadKey(dirctory,true));
        else{
        m_chiper.init(Cipher.DECRYPT_MODE,(PrivateKey)LoadKey(dirctory,false));
        output = "decrypted";
        }
                
        FileInputStream i_stream = new FileInputStream(m_file);
        
        //read data from file
        byte[] data = new byte[(int) m_file.length()];
        i_stream.read(data);
        i_stream.close();

        //remove extension
        String fileName[] = m_file.getPath().split("[.]");
        File o_file = new File(fileName[0] + "." + output);
        
        //write to file
        FileOutputStream out = new FileOutputStream(o_file);
        out.write(this.m_chiper.doFinal(data));

        //close file connection
        out.flush();
        out.close();


        //Display result
        System.out.println("----------------------");
     	System.out.printf("Done! File %s is %s using RSA \n",m_file.getName(),output);
     	System.out.println("Output file is " + o_file.getName()  );
        
    }

    
    public void hash_function(String dirctory,String algo) throws NoSuchAlgorithmException, IOException {
        
            if("SHA512".equals(algo)) algo = "SHA-512";
            else algo = "SHA-256";
            
            //Change the name of the file
            String fileName[] = dirctory.split("[.]");
            File o_file = new File(fileName[0] + ".msgdigest");
            

            //hash the data and store it in digest
            MessageDigest SHADigest = MessageDigest.getInstance(algo);
            byte[] digest = SHADigest.digest(Files.readAllBytes(Paths.get(dirctory)));
            

            //write to file
            Files.write(Paths.get(o_file.getPath()), digest);
            
            //Display results
            System.out.printf("Done! The message digest of the file %s is generated using %s "
                    + " \n",dirctory,algo);
            System.out.println("Output file is " + o_file.getName());
            
        
    }

}

public class CS433_Sec {


    public static void main(String[] args) throws IOException {
     
         //Create Scanner object
    	Scanner input = new Scanner(System.in);
        
        int oper = 0;  //choice of user
   
        try {
        	
            RSA_HASHING m_module = new RSA_HASHING() ;

            m_module.GenerateKeys("./");
            
            while (oper != 3) {
            	
            	System.out.println("MAIN MENU");
            	System.out.println("==========================================================================");
            	System.out.println("What do  you need to implement?\n");
                
                System.out.println("1. Encryption");
                System.out.println("2. Hashing");
                System.out.println("3. Exit\n");
                
                System.out.print("Enter your choice: ");
                oper = input.nextInt();
            	if(oper == 3) 
            	{
                input.close();
                break;
            	}
                
                if(oper == 1){
            	System.out.println("----------------------");
            	System.out.println("1. Encrypt");
            	System.out.println("2. Decrypt");
            	System.out.println("3. Back to main menu");
            	System.out.println("----------------------");
            	System.out.print("Enter your choice: ");
            	
            	oper = input.nextInt();
            	if(oper == 3) 
            	{
                oper = 0;
                continue;
            	}
            	
            	System.out.println("(1) File (2) Folder");
            	System.out.print("Enter your choice: ");
            	int target = input.nextInt();
            	
            	System.out.print("Type your file name: ");
            	String fileName = input.next();
                
                File dirctory = new File(fileName);

                //Create list of files based o user choice
            	File[] list;    
            	if(target == 1) 
                list = new File[] {dirctory} ;   
            	else 
            	list = dirctory.listFiles();   

                
                
                if(oper==1)
                System.out.print("Enter the Public key filename: ");

                else if(oper==2)
                System.out.print("Enter the Private key filename: ");
                
            	String path = input.next(); 
                                
                switch (oper) {
                case 1:
                    Arrays.asList(list).forEach(file -> 
                    {
                        try 
                        {
                        //split name
                        int index = file.getName().lastIndexOf('.');
                        String fileExtension = file.getName().substring(index + 1);
                        
                        //search for the extension we want and perform encryption
                        if(fileExtension.contains("txt")) 
                        m_module.PerformOperation(file,path,true);
                        
                        
                        } 
                        catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) 
                        {
                         System.err.println("Couldn't encrypt " + file.getName() + ": " + e.getMessage());
                        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                            Logger.getLogger(CS433_Sec.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                    );
                    
                    break;
                    
                case 2:
                    Arrays.asList(list).forEach(file -> {
                        try 
                        { 
                            //split name
                            int index = file.getName().lastIndexOf('.');
                            String fileExtension = file.getName().substring(index + 1);
                            
                            //search for the extension we want and perform decryption
                            if(fileExtension.contains("encrypted")) 
                            m_module.PerformOperation(file,path,false);

                         
                        }
                        
                        catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) 
                        {
                        System.err.println("Couldn't decrypt " + file.getName() + ": " + e.getMessage());
                        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                            Logger.getLogger(CS433_Sec.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                    );
                    break;
            
                default:
                	System.out.println("Please enter a vaild choice");
                    break;
                }
            	System.out.println("--------------------------------------------------------------------------");
            }
             
            else if(oper == 2){
            	
            	System.out.print("Type your file name: ");
                String fileName = input.next();
                
                      
                System.out.print("Choose the Algorithm (SHA256, SHA512): ");

                //split name
                int index = fileName.lastIndexOf('.');
                String fileExtension = fileName.substring(index + 1);
                
                
                if(fileExtension.contains("txt")) 
                m_module.hash_function(fileName,input.next());
                  
                }
            }
        } 
        catch (UnsupportedEncodingException ex) 
        {
        System.err.println("Couldn't create key: " + ex.getMessage());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(CS433_Sec.class.getName()).log(Level.SEVERE, null, ex);
        } 
      
        input.close();
    }
    
    }
    

