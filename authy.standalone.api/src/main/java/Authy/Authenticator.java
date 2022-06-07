package Authy;
//package com.ehelpy.brihaspati4.authenticate ;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;


/* last update: 05/06/22
author: anupamv20
Authenticator API class
it is called by ClientMainNew class
 *
 * */
 class Authenticator extends Thread {

    private static Authenticator auth;

    private  X509Certificate self_cert;
    private  static long time_offset=0;
    private  PublicKey self_pubkey;
    private X509Certificate server_cert;
    private boolean auth_verify_flag=false;

    /*
    * returns the object of Authenticator.
    * Only one Instance will be created.
    * */
    public static synchronized Authenticator getInstance() throws Exception {
        System.out.println("i am in AM instance");

        if (auth == null) {
            auth = new Authenticator();
        }
        return auth;
    }
/*
* Constructor of authenticator
* - it starts processing thread to read query or request coming from GC
* - it calculates and stores the time-offset by comparing B4 server time and system current time,
*   this offset will later be used to get user's correct time
* */
    Authenticator() throws Exception {

        System.out.println("i am in AM");

        time_offset = UpdatedDateTime.getTimeOffset(); // calculates time-offset

    }


    /*
    * -this function is called by ClientMainNew: to check the status of Valid Certificate
    * -it will check the availability of keystore
    * -if available: it will call VerifyCerts class to get alias and password from user and checks validity of user certificate
    * -if not available: it will call KeystoreGeneration class to either retrieve keystore from IA (registered user)
    *  or generate new keystore
    *  -after validation this function will return true
    * */

    boolean FlagCheck() throws Exception {
        if (!IntegrityChecks.checkKeyStoreExists()) // keystore does not exist, we create new keystore
        {
            System.out.println("keystore not detected in local storage");
            String email_id = Test_webUI_Inputs.getEmail();

            // KeystoreGeneration : will create keystore
            if (KeystoreGeneration.generateKeystore(email_id)) // if KS successfully generated and stored
            {
                System.out.println("KS generated ");
                System.out.println("now will do verification check");
                while(!auth_verify_flag) // runs until flag becomes true
                {
                    auth_verify_flag = VerifyCerts.verifyCert(); // re-run option page :::
                }
            }
        }
        else // when keystore  exist: we can directly do verification check
        {
            System.out.println("found keystore in local storage: continuing with verification check");
            while(!auth_verify_flag) // runs until flag becomes true
            {
                auth_verify_flag = VerifyCerts.verifyCert(); // re-run option page :::
            }
        }

        System.out.println("your cert is valid");
        server_cert = VerifyCerts.returnServerCert();
        self_cert = VerifyCerts.returnClientCert();
        self_pubkey = self_cert.getPublicKey();

        System.out.println("your pubic key is::"+self_pubkey);
        System.out.println("cert period is : ");
        System.out.println(self_cert.getNotBefore());

        System.out.println(self_cert.getNotAfter());


        System.out.println("....flag for Am is true....other services can start");

        //testing
//        String s = Test_webUI_Inputs.getDevice_Id();
//        String ss = Test_webUI_Inputs.getNode_Id();
//
//
//        System.out.println("got response from test webui for getDevice_Id : "+s);
//        System.out.println("got response from test webui for getNode_Id : "+ss);
//        System.out.println("###################################################################");
//        System.out.println(getUpdatedTime());
//        System.out.println(getSelfCert());
//        System.out.println(getSelfPubKey());
            //testing ends

        return auth_verify_flag;

    }

    /*  role:    - this function returns user's own certificate,
       arg : nothing
       return : X509Certificate
   */
    X509Certificate getSelfCert() {
        return self_cert;
    }

    /*  role:    - this function calculates user's corrected time based on the offset,
        arg : nothing
        return : latest corrected date-time in Date format
    */
    static Date getUpdatedTime() throws ParseException {

        SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm");
        Date date;
        date = sdf.parse(UpdatedDateTime.getCurrentDateTime());
        long system_in_mills = date.getTime();
        String updated_user_time = sdf.format(system_in_mills + time_offset);
        date = sdf.parse(updated_user_time);
        return date;
    }

  /* role:    - this function returns user's public key,
     arg : nothing
     return : public key as PublicKey */

    PublicKey getSelfPubKey() {
        return self_pubkey;
    }

    /* role:    - this function calculates hash of the data,
              - this function uses IntegrityChecks class
              - Algo used : SHA-256
     arg : input data as String
     return : hash value as string */
    String getStringHash (String data) throws NoSuchAlgorithmException {
        return IntegrityChecks.stringHash(data);
    }

   /*  role:    - this function extracts the public key attached to the cert,
              - this function first converts string format to X509 format
              - the function will carry out two checks before extracting the public key:
              - Identity server's signature verification check and certificate expiry date.
              - once both checks are true, it will return the public key, else returns null
     arg : certificate as string
     return : Public Key */
    PublicKey getPubKeyFromCert(String cert) throws IOException {

        X509Certificate othercert = ChangeCertFormat.convertToX509Cert(cert);
        try{
            othercert.verify(server_cert.getPublicKey()); // signature check
            othercert.checkValidity(Authenticator.getUpdatedTime()); // expiry check
        }
        catch (Exception e1)
        {
            System.out.println(" submitted certificate signature doesn't matches or expired");
            return null;
        }

        return othercert.getPublicKey();

    }


 /*  role: - this function will decrypt the msg with its own private key, which was encrypted by its public key,
           - used for one-to-one encryption-decryption process,
     arg: encrypted data as byte array
     returns: plain data as byte[], if exception occurs: it will return null. */
    byte[] getDecrypted (byte[] encrypted_input)
    {
        Cipher cipher = null;
        byte[] decrypt_output = null;

        // this will call my priv key for encryption purpose
        PrivateKey self_privkey = VerifyCerts.returnMyPK();

        try {
            //System.out.println("The length of input stream is" + encrypted_input.length);
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            System.out.println("starting decryption");
            cipher.init(Cipher.DECRYPT_MODE, self_privkey);

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {

            decrypt_output = cipher.doFinal(encrypted_input);
            System.out.println("Decryption completed");

        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return decrypt_output;

    }


/*   role: - this function will encrypt the msg with its own private key,
           - so that others peers can decrypt using public key : for broadcast/multicast,
           - one to many encryption process.
     arg: data as byte array
     returns: encrypted output as byte[], if exception occurs: it will return null. */
    byte[] getEncrypted(byte[] input)
    {
        byte[] output = null;
        Cipher cipher = null;

        // this will call my priv key for encryption purpose
        PrivateKey self_privkey = VerifyCerts.returnMyPK();
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            System.out.println("starting encyption");
            cipher.init(Cipher.ENCRYPT_MODE, self_pubkey);
           // cipher.init(Cipher.ENCRYPT_MODE, self_pubkey); // for checking encryption with pub key


            output = cipher.doFinal(input);
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
            return null;

        } catch (NoSuchPaddingException e2) {
            e2.printStackTrace();
            return null;

        }
        catch (InvalidKeyException e3) {
            e3.printStackTrace();
            return null;

        }

        catch (IllegalBlockSizeException e4) {
            e4.printStackTrace();
            return null;

        } catch (BadPaddingException e5) {
            e5.printStackTrace();
            return null;

        }
        System.out.println("  msg encrpted using own private key msg completed");

        return output;
    }

 /*    role: this function calculates the digital signature
     arg: data as byte array
     returns: signature as byte[], if exception occurs: it will return null. */
    byte[] getSignature(byte[] input)  {


        Signature sign;
        try {
            sign = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        PrivateKey self_privkey = VerifyCerts.returnMyPK();

        try {
            sign.initSign(self_privkey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
        byte[] signature;
        try {
            sign.update(input);
            signature = sign.sign();

        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }

        return signature;
    }


}







