import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Implement your attack in this class

public class Attack1 {

	private static Cipher dcipher;
	private static SecretKeySpec sharedKey;
	private static Cipher sessionCipher;
	private static String finalData;


	public static void main(String[] args) {

		try {

			// For decrypting the cipher is initialised
			dcipher = Cipher.getInstance("DES/ECB/NoPadding");

			// Alice is initialised
			Alice a = new Alice();
			// Bob is initialised
			Bob b = new Bob();

			// Alice sends data to Bob which is taken by the intruder			
			byte[] random64B = a.Step1();
			// Bob send back session key encoded data back to Alice, which is
			// also taken by the intruder			
			byte[] bobData1 = b.Step2(random64B);
			// attacker --> B : (r+1) XOR s' = z (<----- 64 bits, my session
			// key)
			// B --> attacker : E (k,z || (z+1) XOR s)
			byte[] randomPlusOne = CommonFunctions.incrementByValue(random64B,
					(byte) 1);
			byte[] mySessionKey = { 0, 0, 0, 0, 0, 0, 0, 0 };
			byte[] s = CommonFunctions.XOR(mySessionKey, randomPlusOne);

			byte[] bobData2 = b.Step2(s);

			byte[] alicepackage = new byte[bobData1.length];
			System.arraycopy(bobData1, 0, alicepackage, 0, alicepackage.length/2);
			System.arraycopy(bobData2, 0, alicepackage, alicepackage.length/2, alicepackage.length/2);
			
			
			String encryptedData = a.Step3(alicepackage);

			// regenerating the session key
			SecretKey sessionKey = new SecretKeySpec(mySessionKey, "DES");
			sessionCipher = Cipher.getInstance("DES");
			// encrypting the important message
			sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);

			// Since we already have the session key, use it to decrypt the
			// data.
			finalData = CommonFunctions.decrypt(sessionCipher, encryptedData);

			System.out.println("Final Data is " + finalData);

		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalStateException
				| IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
