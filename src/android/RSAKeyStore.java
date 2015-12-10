package com.crypho.plugins;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.util.Calendar;

/**
 * Created by michael on 10/12/15.
 */
public class RSAKeyStore implements RSA {

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";

    private Context ctx;

    RSAKeyStore(Context ctx){
        this.ctx = ctx;
    }

    @Override
    public byte[] encrypt(byte[] buf, String alias) throws Exception {
        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, alias);
        return cipher.doFinal(buf);
    }

    @Override
    public byte[] decrypt(byte[] encrypted, String alias) throws Exception {
        Cipher cipher = createCipher(Cipher.DECRYPT_MODE, alias);
        return cipher.doFinal(encrypted);
    }

    @Override
    public void createKeyPair(String alias) throws Exception {
        Calendar notBefore = Calendar.getInstance();
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 100);
        String principalString = String.format("CN=%s, OU=%s", alias, ctx.getPackageName());
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(ctx)
                .setAlias(alias)
                .setSubject(new X500Principal(principalString))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(notBefore.getTime())
                .setEndDate(notAfter.getTime())
                .setEncryptionRequired()
                .setKeySize(2048)
                .setKeyType("RSA")
                .build();
        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_PROVIDER);
        kpGenerator.initialize(spec);
        kpGenerator.generateKeyPair();
    }

    @Override
    public Cipher createCipher(int cipherMode, String alias) throws Exception {
        KeyStore.PrivateKeyEntry keyEntry = getKeyStoreEntry(alias);

        if (keyEntry == null) {
            throw new Exception("Failed to load key for " + alias);
        }
        Key key;
        switch (cipherMode) {
            case Cipher.ENCRYPT_MODE:
                key = keyEntry.getCertificate().getPublicKey();
                break;
            case  Cipher.DECRYPT_MODE:
                key = keyEntry.getPrivateKey();
                break;
            default : throw new Exception("Invalid cipher mode parameter");
        }
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(cipherMode, key);
        return cipher;
    }

    @Override
    public boolean isEntryAvailable(String alias) {
        try {
            return getKeyStoreEntry(alias) != null;

        } catch (Exception e) {
            return false;
        }
    }

    private KeyStore.PrivateKeyEntry getKeyStoreEntry(String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);
        return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
    }
}
