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
 * MD5、AES、RSA算法
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
	 * 生成AES密钥，并用BASE64编码
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
	 * 用BASE64解码字符串，并生成AES密钥
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
	 * 将字节数组用AES密钥加密
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
	 * 将字节数组用AES密钥解密
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
	 * 生成RSA公钥与私钥
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public static KeyPair getKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator =  KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(512);
		return keyPairGenerator.generateKeyPair(); 
	}
	
	/**
	 * 用BASE64编码RSA公钥
	 * @param keyPair
	 * @return
	 */
	public static String getPublicKey(KeyPair keyPair) {
		PublicKey key =  keyPair.getPublic();
		byte[] bytes =  key.getEncoded();
		return byte2base64(bytes);
	}
	
	/**
	 * 用BASE64编码私钥
	 * @param keyPair
	 * @return
	 */
	public static String getPrivateKey(KeyPair keyPair) {
		PrivateKey key =  keyPair.getPrivate();
		byte[] bytes =  key.getEncoded();
		return byte2base64(bytes);
	}
	
	/**
	 * 将字符串用BASE64解码后生成RSA公钥
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
	 * 将字符串用BASE64解码后生成RSA私钥
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
	 * 将字节数组用RSA私钥加密
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
	 * 将字节数组用RSA公钥解密
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
	 * 将二进制的字节数组转换为十六进制的字符串
	 * @param bytes
	 * @return
	 */
	public static String bytes2hex(byte[] bytes) {
		StringBuilder hex = new StringBuilder() ;
		
		for(int i=0;i<bytes.length;i++) {
			byte b = bytes[i];
			boolean negative = false;//是否为负数
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
	 * 将字节数组用base64编码为字符串
	 * @param bytes
	 * @return
	 */
	public static String byte2base64(byte[] bytes) {
		BASE64Encoder base64Encoder =  new  BASE64Encoder();
		return base64Encoder.encode(bytes);
	}
	
	/**
	 * 将字符串用base64解码为字节数组
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
		System.out.println("加密前的明文为："+content);
		
		byte[] bytes =  testMD5(content);
		System.out.println("MD5加密后的字节数组为："+Arrays.toString(bytes));
		System.out.println("MD5加密后的十六进制字符串为："+bytes2hex(bytes));
		
		String aesKeyForBase64 =  getKeyAES();
		System.out.println("AES密钥：（BASE64算法编码后）"+aesKeyForBase64);
		bytes =  encryptAES(content.getBytes("UTF8"), loadKeyAES(aesKeyForBase64));
		System.out.println("AES加密后的字节数组为："+Arrays.toString(bytes));
		String encryptContent = byte2base64(bytes);
		System.out.println("AES加密后的密文为：（BASE64算法编码后）"+encryptContent);
		
		bytes = decryptAES(base642byte(encryptContent), loadKeyAES(aesKeyForBase64));
		content = new String(bytes,"UTF8");
		System.out.println("AES解密前的明文为："+content);
		
		KeyPair keyPair =  getKeyPair();
		String rsaPublicKeyForBase64  = getPublicKey(keyPair);
		System.out.println("RSA公钥：（BASE64算法编码后）"+rsaPublicKeyForBase64);
		String rsaPrivateKeyForBase64 = getPrivateKey(keyPair);
		System.out.println("RSA私钥：(BASE64算法编码后)"+rsaPrivateKeyForBase64);
		
		bytes = privateEncrypt(content.getBytes("UTF8"), string2PrivateKey(rsaPrivateKeyForBase64));
		System.out.println("RSA私钥加密后的字节数组为："+Arrays.toString(bytes));
		encryptContent =  byte2base64(bytes);
		System.out.println("RSA私钥加密后的密文为：（BASE64算法编码后）"+encryptContent);
		
		bytes = publicDecrypt(base642byte(encryptContent), string2PublicKey(rsaPublicKeyForBase64));
		content = new String(bytes,"UTF8");
		System.out.println("RSA公钥解密后的明文为："+content);
	}
}
