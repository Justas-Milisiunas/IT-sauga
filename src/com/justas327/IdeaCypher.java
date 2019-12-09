package com.justas327;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

public class IdeaCypher {
    private static final String	digits = "0123456789ABCDEF";

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // write your code here
        try {
            doDecryptSerpent();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    public static void doDecryptSerpent() throws Exception
    {
        byte[]  keyBytes = new byte[] {
                0x66, 0x65, 0x56, 0x66, 0x66, 0x65, 0x56, 0x66,
                0x33, 0x31, 0x13, 0x33, 0x33, 0x31, 0x13, 0x33};
        byte[]  input = Hex.decode ("B9C1793C8B131869 B50A70335F644B5B B6210991B5E2F4FD");
        byte[]	ivBytes = Hex.decode ("0806050403020100");

        System.out.println("Duotoji šifrograma : " + toHex(input));
        SecretKeySpec   key = new SecretKeySpec(keyBytes, 0, 16, "IDEA");
        // IV turi buti lygiai tiek baitu, koks yra bloko ilgis
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("IDEA/CBC/PKCS7Padding", "BC");

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = new byte[cipher.getOutputSize(input.length)];

        int ptLength = cipher.update(input, 0, input.length, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
//        plainText[ptLength-1]= Hex.decode("B9")[0];
        System.out.println("IDEA iššifruota tekstograma : " + toHex(plainText, ptLength) + " bytes: " + ptLength);
        byte[] raktas = key.getEncoded();
        System.out.println("Naudotas raktas : " + toHex(raktas));
        System.out.println("Naudotas IV : " + toHex(ivSpec.getIV()));

        //Patikrinimas
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(ptLength)];

        int ctLength = cipher.update(plainText, 0, ptLength, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("Vėl užšifruota tekstograma : " + toHex(cipherText, ctLength) + " bytes: " + ctLength);
    }

    /**
     * Du pagalbiniai metodai skirti "graziai" atvaizduoti baitu masyvus
     */
    public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));

            if (((i+1) % 8 == 0) && (i>0)) buf.append(" ");

        }
        return buf.toString();
    }

    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }

}
