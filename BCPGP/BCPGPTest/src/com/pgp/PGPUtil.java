package com.pgp;

import java.io.IOException;
import java.security.NoSuchProviderException;

import org.bouncycastle.openpgp.PGPException;

public class PGPUtil {
	
	private String privateKeyPath;  //Address for storing the public key file
	private String publicKeyPath;   //Address for storing the private key file
	private String passWord;        //Possible passwords
	
	
	public String getPrivateKeyPath() {
		return privateKeyPath;
	}

	public void setPrivateKeyPath(String privateKeyPath) {
		this.privateKeyPath = privateKeyPath;
	}

	public String getPublicKeyPath() {
		return publicKeyPath;
	}
	public void setPublicKeyPath(String publicKeyPath) {
		this.publicKeyPath = publicKeyPath;
	}
	public String getPassWord() {
		return passWord;
	}
	public void setPassWord(String passWord) {
		this.passWord = passWord;
	}
	
	public PGPUtil(String privateKeyPath, String publicKeyPath, String passWord) {
		super();
		this.privateKeyPath = privateKeyPath;
		this.publicKeyPath = publicKeyPath;
		this.passWord = passWord;
	}
	public PGPUtil() {
		super();
	}
	

	/***
	 * 
	 * @param filePath  Files to be encrypted  For example D://test.txt
	 * @param outPutFilePath  Output path of the encrypted file  For example D://test.gpg
	 */
	public void encryptFile(String filePath,String outPutFilePath)  {
		try {
			final Encrypt encrypt = new Encrypt();
			encrypt.setArmored(true);
			encrypt.setCheckIntegrity(true);
			encrypt.setPublicKeyFilePath(publicKeyPath);  //Set the path where the public key is saved
			
			encrypt.setSigning(true);
			encrypt.setPrivateKeyFilePath(privateKeyPath); //Set the path to save the private key
			encrypt.setPrivateKeyPassword(passWord); // Example Set the private key password

			final BCPGPEncryptor bcpgpEnryptor = new BCPGPEncryptor(encrypt);

			final String plainInputFile = filePath; ////To be modify
			final String encryptedOutputFile = outPutFilePath; ////To be modify
			bcpgpEnryptor.encryptFile(plainInputFile, encryptedOutputFile);
			
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
	
	/***
	 * 
	 * @param filePath  Files to be decrypted  For example D://test.gpg
	 * @param outPutFilePath  Output path of the decrypted file  For example D://test.txt
	 */
	public void decryptFile(String filePath,String outPutFilePath)  {
		try {
			final Decrypt decrypt = new Decrypt();
			decrypt.setPublicKeyFilePath(publicKeyPath); //To be modify
			decrypt.setVerify(true);
			decrypt.setPrivateKeyFilePath(privateKeyPath); ////To be modify
			decrypt.setPrivateKeyPassword(passWord); //Enter your private key password

			final BCPGPDecryptor bcpgpDecryptor = new BCPGPDecryptor(decrypt);
				
			bcpgpDecryptor.decryptFile(filePath, outPutFilePath);
			
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
	
	public static void main(String[] args) {
		
		PGPUtil pu=new PGPUtil("D:\\keys\\private.key","D:\\keys\\key0xCF2DC1E70447A86D.asc","123456789");
		
//		pu.decryptFile("D:\\Keys\\test.gpg", "D:\\Keys\\test.txt");
		pu.encryptFile("D:\\Keys\\test.txt", "D:\\Keys\\test.PGP");
		
		
	}
	
	 
	
	
	
	
	
}
