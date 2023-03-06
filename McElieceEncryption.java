import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceCipher;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceKeyGenerationParameters;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceKeyPairGenerator;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceParameters;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McEliecePublicKeyParameters;

//***************************************************************************************************
//	NOTES
//	m = >12 -> >1s Run Time
//	m = 12  -> ~1s Run Time
//	m = 13  -> ~7s Run Time
//	m = 14  -> ~87s Run Time
//	m = 15  -> ~653s Run Time
//	...
//
//	RULES
//	
//	t : ( 0 <= t <= n ) ( t must be less than n )
//	m : ( 1 <= m <= 32 )
//	n : ( n = 2^m )
//
//	Variables k and m are used to specify the number of information bits and parity-check bits respectively in the McEliece cryptosystem.
//	The McEliece cryptosystem is a public-key encryption system based on the hardness of decoding a linear code.
//	In this system, the sender encodes a message into a codeword, which is then encrypted using the public key of the recipient.
//	The recipient can then decode the message using their private key.
//
//	The parameters k and m are used to specify the dimensions of the generator matrix for the linear code used in the McEliece cryptosystem.
//	The generator matrix is used to encode the message into a codeword.
//	The total length n of the codeword is determined by n = k + m.
//	The parameter t specifies the error-correcting capability of the code, which determines the number of errors that can be corrected during the decoding process.
//
//

public class McElieceEncryption {
    public static void main(String[] args) throws Exception {
    	long startTime = System.currentTimeMillis();
    	String message = "Hello, World!";
        int t = 8;   	// The default error correcting capability of the code
        int m = 12;   	// The default extension degree of the finite field GF(2^m)
        //  n  			// The length of the code - Vector Space Dimension - Calculated by McElieceParameters
        
        // Generate the public and private keys
        McElieceParameters params = new McElieceParameters(m, t);
        McElieceKeyPairGenerator keyPairGenerator = new McElieceKeyPairGenerator();
        McElieceKeyGenerationParameters keyGenParams = new McElieceKeyGenerationParameters(new SecureRandom(), params);
        keyPairGenerator.init(keyGenParams);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        McEliecePublicKeyParameters publicKey = (McEliecePublicKeyParameters) keyPair.getPublic();
        McEliecePrivateKeyParameters privateKey = (McEliecePrivateKeyParameters) keyPair.getPrivate();

        // Encrypt the message using McElieceCipher
        McElieceCipher encryptor = new McElieceCipher();
        encryptor.init(true, publicKey);	// True if we are encrypting a signature, false otherwise.
        byte[] plaintext = message.getBytes();
        byte[] ciphertext = encryptor.messageEncrypt(plaintext);

        // Decrypt the message using McElieceCipher
        McElieceCipher decryptor = new McElieceCipher();
        decryptor.init(false, privateKey);
        byte[] decrypted = decryptor.messageDecrypt(ciphertext);

        // Print the results
        String decryptedMessage = new String(decrypted);
        long endTime = System.currentTimeMillis();
        long elapsedTime = endTime - startTime;
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max Key Size for AES : " + maxKeySize);
        //System.out.println("Generator Matrix : " + publicKey.getG());
        System.out.println("Original message : " + message);
        System.out.println("(T) Error Correlation Capability : " + params.getT());
        System.out.println("(M) Extension Degree : " + params.getM());
        System.out.println("(N) Length of Code : " + params.getN());
        System.out.println("Field Polynomial : " + params.getFieldPoly());
        System.out.println("Encrypted message : " + new String(ciphertext));
        System.out.println("Decrypted message : " + decryptedMessage);
        System.out.println("Total Run-Time : " + (elapsedTime / 1000) + " Seconds");
    }
}