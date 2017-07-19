package org.apache.cordova.techm;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.cordova.*;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

import android.annotation.SuppressLint;
import android.util.Base64;

public class EncryptionAndroidPlugin extends CordovaPlugin{

	public static final String ENCRYPT_DATA = "encrypt_data";
	public static final String DECRYPT_DATA = "decrypt_data";
	
	
	@SuppressLint("NewApi")
	@Override
	public boolean execute(String action, String args, CallbackContext callbackContext) throws JSONException {
	 try {
		 	args = args.substring(1);
			args = args.substring(0, args.length() - 1);
		 	
			if (ENCRYPT_DATA.equals(action)) { 
			   String encrypted_str=encryptPlainText(args);
			   //System.out.println("Encrypted String java- "+encrypted_str);
			   callbackContext.success(encrypted_str);
			   return true;
			}else{
				String decrypted_str=decryptCipherText(args);
				//System.out.println("Decrypted String - "+decrypted_str);
				callbackContext.success(decrypted_str);
				return true;
			}
		} catch(Exception e) {
			System.err.println("Exception: " + e.getMessage());
			callbackContext.error(e.getMessage());
			return false;
		} 
	}
	

	public static String encryptPlainText(final String t_stringToEncrypt) {

		String encryptedString = "";
		try {
			String key = "M_SWAGATAM_KEY_17";
			byte[] keyBytes;
			byte[] keyBytes16 = null;
			byte[] plainBytes = null;

			try {
				keyBytes = key.getBytes("UTF-8");
				keyBytes16 = new byte[16];
				System.arraycopy(keyBytes, 0, keyBytes16, 0,
						Math.min(keyBytes.length, 16));
				plainBytes = t_stringToEncrypt.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e2) {
				e2.printStackTrace();
			}

			SecretKeySpec skeySpec = new SecretKeySpec(keyBytes16, "AES");
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				byte[] iv = new byte[16]; // initialization vector with all 0
				cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(
						iv));
				byte[] encrypted = cipher.doFinal(plainBytes);
				//byte[] encodedBytes = Base64.encode(encrypted, Base64.DEFAULT);
				byte[] encodedBytes = Base64.encode(encrypted, Base64.NO_WRAP);

				encryptedString = new String(encodedBytes);
				// Log.d("Encryption string final:", encryptedString);

			} catch (InvalidKeyException e1) {
				e1.printStackTrace();
			} catch (InvalidAlgorithmParameterException e1) {
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				e1.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}

		} catch (Exception ex) {
			// Log.d("Caught exception in encryptPlainText","");
			ex.printStackTrace();
		}
		
		return encryptedString;
	}
	
	
	public static String decryptCipherText(final String t_stringToDecrypt){
		String decryptedString = "";
		try {
			String key = "M_SWAGATAM_KEY_17";
			byte[] keyBytes;
			byte[] keyBytes16 = null;
			byte[] plainBytes = null;

			try {
				keyBytes = key.getBytes("UTF-8");
				keyBytes16 = new byte[16];
				System.arraycopy(keyBytes, 0, keyBytes16, 0,
						Math.min(keyBytes.length, 16));

				plainBytes = Base64.decode(t_stringToDecrypt, Base64.NO_WRAP); // t_stringToDecrypt.getBytes("UTF-8");

			} catch (UnsupportedEncodingException e2) {
				e2.printStackTrace();
			}

			SecretKeySpec skeySpec = new SecretKeySpec(keyBytes16, "AES");
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				byte[] iv = new byte[16]; // initialization vector with
											// all 0
				cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(
						iv));
				byte[] decrypted = cipher.doFinal(plainBytes);
				// byte[] encodedBytes = Base64.encodeBase64(decrypted);
				decryptedString = new String(decrypted);
				// Log.d("DE cryption string final:", decryptedString);

			} catch (InvalidKeyException e1) {
				e1.printStackTrace();
			} catch (InvalidAlgorithmParameterException e1) {
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				e1.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				System.out.println("BadPaddingException - "+e);
				e.printStackTrace();
			}

		} catch (Exception ex) {
			 System.out.println("Exception - "+ex);
			// Log.d("Caught exception in encryptPlainText","");
		}
		//System.out.println("Decrypted String - "+decryptedString);
		return decryptedString;
	}
	
	
	

	public static String encryptPlainText(final String t_stringToEncrypt, String key) {
		String encryptedString = "";
		try {
			// Log.d("CALERT","ENTER encryptPlainText  ");
			byte[] keyBytes;
			byte[] keyBytes16 = null;
			byte[] plainBytes = null;

			try {
				keyBytes = key.getBytes("UTF-8");
				keyBytes16 = new byte[16];
				System.arraycopy(keyBytes, 0, keyBytes16, 0,
						Math.min(keyBytes.length, 16));
				plainBytes = t_stringToEncrypt.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e2) {
				e2.printStackTrace();
			}

			SecretKeySpec skeySpec = new SecretKeySpec(keyBytes16, "AES");
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				byte[] iv = new byte[16]; // initialization vector with all 0
				cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(
						iv));
				byte[] encrypted = cipher.doFinal(plainBytes);
				byte[] encodedBytes = Base64.encode(encrypted, Base64.DEFAULT);
				encryptedString = new String(encodedBytes);
				// Log.d("Encryption string final:", encryptedString);

			} catch (InvalidKeyException e1) {
				e1.printStackTrace();
			} catch (InvalidAlgorithmParameterException e1) {
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				e1.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}

		} catch (Exception ex) {
			// Log.d("Caught exception in encryptPlainText","");
			ex.printStackTrace();
		}
		return encryptedString;
	}

	
	
	
	public static String decryptCipherText(final String t_stringToDecrypt, String key) {
		String decryptedString = "";
		try {
			// Log.d("CALERT","ENTER decryptCipherText  ");

			byte[] keyBytes;
			byte[] keyBytes16 = null;
			byte[] plainBytes = null;

			try {
				keyBytes = key.getBytes("UTF-8");
				keyBytes16 = new byte[16];
				System.arraycopy(keyBytes, 0, keyBytes16, 0,
						Math.min(keyBytes.length, 16));

				plainBytes = Base64.decode(t_stringToDecrypt, Base64.DEFAULT); // t_stringToDecrypt.getBytes("UTF-8");

			} catch (UnsupportedEncodingException e2) {
				e2.printStackTrace();
			}

			SecretKeySpec skeySpec = new SecretKeySpec(keyBytes16, "AES");
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				byte[] iv = new byte[16]; // initialization vector with
				// all 0
				cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(
						iv));
				byte[] decrypted = cipher.doFinal(plainBytes);
				// byte[] encodedBytes = Base64.encodeBase64(decrypted);
				decryptedString = new String(decrypted);
				// Log.d("DE cryption string final:", decryptedString);

			} catch (InvalidKeyException e1) {
				e1.printStackTrace();
			} catch (InvalidAlgorithmParameterException e1) {
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				e1.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}

		} catch (Exception ex) {
			// Log.d("Caught exception in encryptPlainText","");
		}
		return decryptedString;
	}
}