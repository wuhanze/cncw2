package com;

import java.util.Iterator;
import java.util.Scanner;

import com.pgp.PGPUtil;

public class RunTime {
	
	
	public static void main(String[] args) {
		
		String signName=args[0];
		
		switch(signName){
	    case "GPG" :
	    	GPGRun(args[1]);
	       break;
	    case "x509" :
	    	X509Run();
	       break; 
	    default : 
	      
	    	System.out.println("Not in the specified encryption algorithm");
	  }
	}
	private static void X509Run() {
		
		
		
		
		
		
	}

	private static void GPGRun(String method) {
		switch(method){
	    case "encode" :
	    	GPGEncode();
	       break; 
	    case "decode" :
	    	GPGDecode();
	       break; 
	    default : 
	    	System.out.println("Not in the specified encryption algorithm");
	  }
	}
	private static void GPGEncode() {
		System.out.println("Start using GPG to encrypt files");
		
		Scanner sc = new Scanner(System.in);  
		System.out.println("Enter the path of the PGP public key file");
		String PublicPath = sc.next();
		System.out.println("Enter the path of the PGP private key file");
		String PrivatePath = sc.next();
		
		System.out.println("Please enter the PGP password ");
		String PassWord = sc.next();
		
		System.out.println("Enter the path of the file to be encrypted");
		String filePath = sc.next();
		
		System.out.println("Enter the encrypted output path");
		String outPutPath = sc.next();
		
		sc.close();
		
		System.out.println("Starting to encrypt");
		PGPUtil pu=new PGPUtil(PrivatePath,PublicPath,PassWord);
		
		pu.encryptFile(filePath, outPutPath);
		
		System.out.println("Encryption completed");
	}
	
	private static void GPGDecode() {
		System.out.println("Start decrypting files using GPG");
		
		Scanner sc = new Scanner(System.in);  
		System.out.println("Enter the path of the PGP public key file");
		String PublicPath = sc.next();
		System.out.println("Enter the path of the PGP private key file");
		String PrivatePath = sc.next();
		
		System.out.println("Please enter the PGP password");
		String PassWord = sc.next();
		
		System.out.println("Enter the path of the file to be decrypted");
		String filePath = sc.next();
		
		System.out.println("Enter the decrypted output path");
		String outPutPath = sc.next();
		
		sc.close();
		
		System.out.println("Starting to decrypt");
		PGPUtil pu=new PGPUtil(PrivatePath,PublicPath,PassWord);
		
		pu.decryptFile(filePath, outPutPath);
		
		System.out.println("Encryption completed");
		
	}
	
	
	
}
