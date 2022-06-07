package Authy;
//package com.ehelpy.brihaspati4.authenticate ;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Client_Main_Test_AM extends Thread {

//    private String updated_time="";
//    private X509Certificate client_cert = null;
//    private X509Certificate server_cert = null;
//    private PublicKey client_pubkey = null;
//    private boolean flagset = false;


    public static void main(String args[]) throws Exception {

        Authenticator auth = Authenticator.getInstance();

        if( auth.isAlive() != true) {
            auth.start();
        } else {
            System.out.println("authenticator thread already running.");
        }


        String test = "hello 123";
        System.out.println("starting AM checks");


        System.out.println("validity flag: "+auth.FlagCheck());
        System.out.println("self cert is: "+auth.getSelfCert());
        System.out.println("self public key is: "+auth.getSelfPubKey());
        System.out.println("digital signature is: "+new String(auth.getSignature(test.getBytes(StandardCharsets.UTF_8))));
        System.out.println("hash value:"+auth.getStringHash(test));
        System.out.println("plain data is:"+test);
        System.out.println("encrypted data is:");
        String outMessage = Base64.getEncoder().encodeToString(auth.getEncrypted(test.getBytes(StandardCharsets.UTF_8)));

        System.out.println("encrypted msg is:"+outMessage);


        String decryptedMessage = new String(auth.getDecrypted(auth.getEncrypted(test.getBytes(StandardCharsets.UTF_8))));
        System.out.println("decrypted data is: "+decryptedMessage);










    }
}
