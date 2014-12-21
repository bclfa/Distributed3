package SecureAlgorithm;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


/**
 * MD5��AES��RSA�㷨
 * @author guohz
 *
 */
public class SecureAlgorithm {
	
	/**
	 * MD5
	 * @param content
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] testMD5(String content) throws NoSuchAlgorithmException, UnsupportedEncodingException  {
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] bytes = md.digest(content.getBytes("UTF8"));
		return bytes;
	}
	
	/**
	 * ����AES��Կ������BASE64����
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public static String getKeyAES() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key =  keyGen.generateKey();
		return byte2base64(key.getEncoded());
	}
	
	/**
	 * ��BASE64�����ַ�����������AES��Կ
	 * @param base64Key
	 * @return
	 * @throws IOException 
	 */
	public static SecretKey loadKeyAES(String base64Key) throws IOException {
		 byte[] bytes =  base642byte(base64Key);
		 SecretKey key = new SecretKeySpec(bytes,"AES");
		 return key;
	}
	
	/**
	 * ���ֽ�������AES��Կ����
	 * @param source
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptAES(byte[] source,SecretKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(source);
		
		return bytes;
	}
	
	/**
	 * ���ֽ�������AES��Կ����
	 * @param source
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptAES(byte[] source,SecretKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(source);
		
		return bytes;
	}
	
	/**
	 * ����RSA��Կ��˽Կ
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public static KeyPair getKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator =  KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(512);
		return keyPairGenerator.generateKeyPair(); 
	}
	
	/**
	 * ��BASE64����RSA��Կ
	 * @param keyPair
	 * @return
	 */
	public static String getPublicKey(KeyPair keyPair) {
		PublicKey key =  keyPair.getPublic();
		byte[] bytes =  key.getEncoded();
		return byte2base64(bytes);
	}
	
	/**
	 * ��BASE64����˽Կ
	 * @param keyPair
	 * @return
	 */
	public static String getPrivateKey(KeyPair keyPair) {
		PrivateKey key =  keyPair.getPrivate();
		byte[] bytes =  key.getEncoded();
		return byte2base64(bytes);
	}
	
	/**
	 * ���ַ�����BASE64���������RSA��Կ
	 * @param pubStr
	 * @return
	 * @throws IOException 
	 */
	public static PublicKey string2PublicKey(String pubStr) throws Exception{
		byte[] bytes =  base642byte(pubStr);
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
		KeyFactory keyFactory =  KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(keySpec);
	}
	
	/**
	 * ���ַ�����BASE64���������RSA˽Կ
	 * @param priStr
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey string2PrivateKey(String priStr) throws Exception{
		byte[] bytes =  base642byte(priStr);
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
		KeyFactory keyFactory =  KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}
	
	/**
	 * ���ֽ�������RSA˽Կ����
	 * @param source
	 * @param key
	 * @return
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static byte[] privateEncrypt(byte[] source,PrivateKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(source);
	}
	
	/**
	 * ���ֽ�������RSA��Կ����
	 * @param content
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] publicDecrypt(byte[] content,PublicKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(content);
	}
	
	
	/**
	 * �������Ƶ��ֽ�����ת��Ϊʮ�����Ƶ��ַ���
	 * @param bytes
	 * @return
	 */
	public static String bytes2hex(byte[] bytes) {
		StringBuilder hex = new StringBuilder() ;
		
		for(int i=0;i<bytes.length;i++) {
			byte b = bytes[i];
			boolean negative = false;//�Ƿ�Ϊ����
			if(b<0) negative = true;
			int inte = Math.abs(b);
			if(negative) inte = inte | 0x80;
			String temp = Integer.toHexString(inte & 0xFF);
			
			if(temp.length() == 1) {
				hex.append("0");
			}
			hex.append(temp.toLowerCase());
		}
		return hex.toString();
	}
	
	/**
	 * ���ֽ�������base64����Ϊ�ַ���
	 * @param bytes
	 * @return
	 */
	public static String byte2base64(byte[] bytes) {
		BASE64Encoder base64Encoder =  new  BASE64Encoder();
		return base64Encoder.encode(bytes);
	}
	
	/**
	 * ���ַ�����base64����Ϊ�ֽ�����
	 * @param content
	 * @return
	 * @throws IOException 
	 */
	public static byte[] base642byte(String content) throws IOException{
		BASE64Decoder base64Decoder = new BASE64Decoder() ;
		return  base64Decoder.decodeBuffer(content);
	}
	
	public static void main(String[] args) throws Exception {
		String content = "HELLO,WORLD!";
		System.out.println("����ǰ������Ϊ��"+content);
		
		byte[] bytes =  testMD5(content);
		System.out.println("MD5���ܺ���ֽ�����Ϊ��"+Arrays.toString(bytes));
		System.out.println("MD5���ܺ��ʮ�������ַ���Ϊ��"+bytes2hex(bytes));
		
		String aesKeyForBase64 =  getKeyAES();
		System.out.println("AES��Կ����BASE64�㷨�����"+aesKeyForBase64);
		bytes =  encryptAES(content.getBytes("UTF8"), loadKeyAES(aesKeyForBase64));
		System.out.println("AES���ܺ���ֽ�����Ϊ��"+Arrays.toString(bytes));
		String encryptContent = byte2base64(bytes);
		System.out.println("AES���ܺ������Ϊ����BASE64�㷨�����"+encryptContent);
		
		bytes = decryptAES(base642byte(encryptContent), loadKeyAES(aesKeyForBase64));
		content = new String(bytes,"UTF8");
		System.out.println("AES����ǰ������Ϊ��"+content);
		
		KeyPair keyPair =  getKeyPair();
		String rsaPublicKeyForBase64  = getPublicKey(keyPair);
		System.out.println("RSA��Կ����BASE64�㷨�����"+rsaPublicKeyForBase64);
		String rsaPrivateKeyForBase64 = getPrivateKey(keyPair);
		System.out.println("RSA˽Կ��(BASE64�㷨�����)"+rsaPrivateKeyForBase64);
		
		bytes = privateEncrypt(content.getBytes("UTF8"), string2PrivateKey(rsaPrivateKeyForBase64));
		System.out.println("RSA˽Կ���ܺ���ֽ�����Ϊ��"+Arrays.toString(bytes));
		encryptContent =  byte2base64(bytes);
		System.out.println("RSA˽Կ���ܺ������Ϊ����BASE64�㷨�����"+encryptContent);
		
		bytes = publicDecrypt(base642byte(encryptContent), string2PublicKey(rsaPublicKeyForBase64));
		content = new String(bytes,"UTF8");
		System.out.println("RSA��Կ���ܺ������Ϊ��"+content);
	}
}
