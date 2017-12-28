package testutils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

public class KeyFactory {

    public static KeyPair getKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        return keyGen.generateKeyPair();
    }

}
