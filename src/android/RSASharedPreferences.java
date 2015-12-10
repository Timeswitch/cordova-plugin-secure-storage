package com.crypho.plugins;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by michael on 10/12/15.
 */
public class RSASharedPreferences implements RSA{
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private Context ctx;

    RSASharedPreferences(Context ctx){
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

        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA");
        kpGenerator.initialize(2048);
        KeyPair kp = kpGenerator.generateKeyPair();

        byte[] publicKey = kp.getPublic().getEncoded();
        byte[] privateKey = kp.getPrivate().getEncoded();

        String publicStr = Base64.encodeToString(publicKey, Base64.DEFAULT);
        String privateStr = Base64.encodeToString(privateKey, Base64.DEFAULT);

        SharedPreferences pref = ctx.getSharedPreferences(alias,Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString("public",publicStr);
        editor.putString("private",privateStr);
        editor.commit();

    }

    @Override
    public Cipher createCipher(int cipherMode, String alias) throws Exception {
        KeyPair kp = getPrefEntry(alias);

        if (kp == null) {
            throw new Exception("Failed to load key for " + alias);
        }
        Key key;
        switch (cipherMode) {
            case Cipher.ENCRYPT_MODE:
                key = kp.getPublic();
                break;
            case  Cipher.DECRYPT_MODE:
                key = kp.getPrivate();
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

            return getPrefEntry(alias) != null;

        } catch (Exception e) {
            return false;
        }
    }

    private KeyPair getPrefEntry(String alias) throws Exception {
        SharedPreferences pref = ctx.getSharedPreferences(alias,Context.MODE_PRIVATE);
        String dataPublic = pref.getString("public",null);
        String dataPrivate = pref.getString("private",null);
        if(dataPublic == null || dataPrivate == null){
            return null;
        }


        byte[] bytesPublic = Base64.decode(dataPublic, Base64.DEFAULT);
        byte[] bytesPrivate = Base64.decode(dataPrivate, Base64.DEFAULT);

        PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytesPublic));
        PrivateKey priv = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytesPrivate));

        return new KeyPair(pub,priv);

    }
}
