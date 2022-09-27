import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Implement your attack in this class

public class Attack2 {

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

			byte[] alicepackage = new byte[random64B.length * 2];
			System.arraycopy(random64B, 0, alicepackage, 0,
					alicepackage.length / 2);
			System.arraycopy(random64B, 0, alicepackage,
					alicepackage.length / 2, alicepackage.length / 2);

			String encryptedData = a.Step3(alicepackage);

			byte[] sKey = { 0, 0, 0, 0, 0, 0, 0, 0 };
			for (int i = 1; i < 5; i++) {
				try {
					sKey[7] = (byte) (Math.pow(2, i) - 1);

					SecretKey sessionKey = new SecretKeySpec(sKey, "DES");
					sessionCipher = Cipher.getInstance("DES");
					// encrypting the important message
					sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);

					// Since we already have the session key, use it to decrypt
					// the
					// data.
					finalData = CommonFunctions.decrypt(sessionCipher,
							encryptedData);
					if (finalData.startsWith("[SECRET]")) {
						System.out.println("The message is : " + finalData);
						break;
					}
				} catch (Exception e) {

				}
			}

			// regenerating the session key

		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalStateException
				| IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
