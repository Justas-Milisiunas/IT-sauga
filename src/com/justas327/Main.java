package com.justas327;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;

public class Main {
    private static final String digits = "0123456789ABCDEF";
    static Provider bc = new BouncyCastleProvider();

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // write your code here
        try {
            doDecryptSerpent();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public static void doDecryptSerpent() throws Exception {
        byte[] keyBytes = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] input = Hex.decode("B940B2EAB8AFEF99 D8C3A451BA3A7B4A A40CE3937CCBE8A3 D5D3B0F6C74F854C");

        System.out.println(keyBytes.length);
        System.out.println("Duotoji tekstograma : " + toHex(input) + " bytes: " + input.length);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "cast6");
        Cipher cipher = Cipher.getInstance("CAST6/ECB/NoPadding", bc);

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] output = cipher.doFinal(input);
        String actual = toHex(output);
        System.out.println("CAST6 sifrograma : " + actual);

        //Patikrinimas
        cipher.init(Cipher.DECRYPT_MODE, key);
//        output[0] = Hex.decode("B9")[0];
        byte[] checkOutput = cipher.doFinal(output);

        String checkString = toHex(checkOutput);
        System.out.println("Tekstograma po patikrinimo : " + checkString);
    }

    /**
     * Test to make sure the unrestricted policy files are installed.
     */
    public static void doSimplePolicyTest() throws Exception {
        byte[] data = {0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

        // create a 64 bit secret key from raw bytes

        SecretKey key64 = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07}, "Blowfish");

        // create a cipher and attempt to encrypt the data block with our key

        Cipher c = Cipher.getInstance("Blowfish/ECB/NoPadding");

        c.init(Cipher.ENCRYPT_MODE, key64);
        c.doFinal(data);
        System.out.println("64 bit test: passed");

        // create a 128 bit secret key from raw bytes

        SecretKey key128 = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f}, "Blowfish");

        // now try encrypting with the larger key

        c.init(Cipher.ENCRYPT_MODE, key128);
        System.out.println("128 bit test: passed [" + ((byte[]) c.doFinal(data)).toString() + "]");

        // create a 192 bit secret key from raw bytes

        SecretKey key192 = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                0x17}, "Blowfish");

        // now try encrypting with the larger key

        c.init(Cipher.ENCRYPT_MODE, key192);
        c.doFinal(data);
        System.out.println("192 bit test: passed");

        System.out.println("Tests completed");
    }

    /**
     * List the available capabilities for ciphers, key agreement, macs, message
     * digests, signatures and other objects in the BC provider.
     */
    public static void doListBCCapabilities() throws Exception {
        Provider provider = Security.getProvider("BC");
        Iterator it = provider.keySet().iterator();

        while (it.hasNext()) {
            String entry = (String) it.next();
            // this indicates the entry refers to another entry
            if (entry.startsWith("Alg.Alias.")) {
                entry = entry.substring("Alg.Alias.".length());
            }
            String factoryClass = entry.substring(0, entry.indexOf('.'));
            String name = entry.substring(factoryClass.length() + 1);

            System.out.println(factoryClass + ": " + name);
        }
    }

    /**
     * Du pagalbiniai metodai skirti "graziai" atvaizduoti baitu masyvus
     */
    public static String toHex(byte[] data, int length) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));

            if (((i + 1) % 8 == 0) && (i > 0)) buf.append(" ");

        }
        return buf.toString();
    }

    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }
}
