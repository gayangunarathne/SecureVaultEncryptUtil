package org.wso2.custom.crypto.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.CipherOperationMode;
import org.wso2.securevault.EncodingType;
import org.wso2.securevault.EncryptionProvider;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.definition.IdentityKeyStoreInformation;
import org.wso2.securevault.definition.KeyStoreInformationFactory;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;

import javax.crypto.Cipher;
import java.io.File;
import java.security.Security;
import java.util.Properties;

/**
 * Class which does the encryption and if provided, encoding part as well
 */
public class EncryptionHelper {
    private static Log log = LogFactory.getLog(VaultEncryptDecrypt.class);
    /**
     * Method to run encryption.
     *
     * @param args
     * @throws Exception
     */
    public static void encrypt(String[] args) {
        log.info("******************************** Start encryption ********************************");
        if (args.length != 2 && args.length != 3) {
            log.error("Invalid number of parameters, found - " + args.length + ", required - 4");
            return;
        }
        String propertiesFile = null;
        if (args.length >= 3) {
            propertiesFile = args[2];
        }

        if (propertiesFile == null || propertiesFile.isEmpty()) {
            log.warn("Properties file(secureVault.properties) path not provided, hence defaulting to 'secureVault.properties'");
            propertiesFile = Constants.PROPERTIES_FILE_PATH_DEFAULT;
        }

        Properties properties = Util.loadProperties(propertiesFile);

        String keyStoreFile = null;
        String provider = null;
        String algorithm = null;
        String cipherType = null;
        EncodeDecodeTypes inType = null;
        EncodeDecodeTypes outType = null;

        keyStoreFile = properties.getProperty(Constants.IDENTITY_KEY_STORE);

        if (keyStoreFile == null) {
            log.error("Keystore file path cannot be null");
            return;
        }

        File keyStore = new File(keyStoreFile);

        if (!keyStore.exists()) {
            log.error("Cannot find given keystore file - " + keyStore);
            return;
        }

        // Create a KeyStore Information for private key entry KeyStore
        IdentityKeyStoreInformation identityInformation =
                KeyStoreInformationFactory.createIdentityKeyStoreInformation(properties);


        try {

            String identityKeyPass = null;
            String identityStorePass = null;
            if (identityInformation != null) {
                identityKeyPass = identityInformation
                        .getKeyPasswordProvider().getResolvedSecret();
                identityStorePass = identityInformation
                        .getKeyStorePasswordProvider().getResolvedSecret();
            }

            if (!Util.validatePasswords(identityStorePass, identityKeyPass)) {
                log.error("Either Identity or Trust keystore password is mandatory" +
                          " in order to initialized secret manager.");
                return;
            }

            IdentityKeyStoreWrapper identityKeyStoreWrapper = new IdentityKeyStoreWrapper();
            identityKeyStoreWrapper.init(identityInformation, identityKeyPass);

            algorithm = MiscellaneousUtil.getProperty(properties, Constants.CIPHER_ALGORITHM,
                                                      Constants.CIPHER_ALGORITHM_DEFAULT);

            provider = MiscellaneousUtil.getProperty(properties, Constants.SECURITY_PROVIDER,
                                                     null);
            cipherType = MiscellaneousUtil.getProperty(properties, Constants.CIPHER_TYPE,
                                                       null);
            String inTypeString = MiscellaneousUtil.getProperty(properties, Constants.INPUT_ENCODE_TYPE,
                                                                null);
            inType = Util.getEncodeDecodeType(inTypeString, null);


            String outTypeString = MiscellaneousUtil.getProperty(properties, Constants.OUTPUT_ENCODE_TYPE,
                                                                 null);
            outType = Util.getEncodeDecodeType(outTypeString, EncodeDecodeTypes.BASE64);

            CipherInformation cipherInformation = new CipherInformation();
            cipherInformation.setAlgorithm(algorithm);
            cipherInformation.setCipherOperationMode(CipherOperationMode.ENCRYPT);
            cipherInformation.setInType(EncodingType.BASE64); //TODO
            cipherInformation.setType(cipherType);
            cipherInformation.setInType(null);
            cipherInformation.setOutType(null);

            if (provider != null && !provider.isEmpty()) {
                if (provider.equals("BC")) {
                    Security.addProvider(new BouncyCastleProvider());
                    cipherInformation.setProvider(provider);
                }
                //todo need to add other providers if there are any.
            }
            byte[] toEncrypt = args[1].getBytes();
            if (inType != null) {
                toEncrypt = EncodeDecodeHelper.decode(toEncrypt, inType);
            }

            EncryptionProvider baseCipher = CipherFactory.createCipher(cipherInformation, identityKeyStoreWrapper);
            byte[] encryptedPassword;
//            if (algorithm !=null && !algorithm.isEmpty() && algorithm.equals(Constants.CIPHER_ALGORITHM_DEFAULT)) {
//                encryptedPassword = blockCipher(baseCipher, toEncrypt, Cipher.ENCRYPT_MODE);
//            } else {
                encryptedPassword = baseCipher.encrypt(toEncrypt);
//            }

            if (outType != null) {
                encryptedPassword = EncodeDecodeHelper.encode(encryptedPassword, outType);
            }

            String encodedValue = new String(encryptedPassword);//new String(encryptedPassword);
            log.info("Encrypted (and may be encoded) - " + encodedValue);
            log.info("******************************** End encryption ********************************");
        } catch (SecureVaultException e) {
            log.error("SecureVault exception, " + e.getMessage(), e);
        }
    }


    private static byte[] blockCipher(EncryptionProvider baseCipher, byte[] bytes, int mode) {
        // hold temp results
        byte[] temp = new byte[0];
        // full response
        byte[] response = new byte[0];
        //For encryption length required for RSA is 100 (for decryption it is 128)
        int length = (mode == Cipher.ENCRYPT_MODE)? 100 : 128;

        //temp encryption bufffer
        byte[] buffer;
        if (bytes.length < length) {
            buffer = new byte[bytes.length];
        } else {
            buffer = new byte[length];
        }

        for (int i=0; i< bytes.length; i++){
            //when buffer is filled, then encrypt
            if ((i > 0) && (i % length == 0)){
                temp = baseCipher.encrypt(buffer);
                // append results
                response = Util.append(response, temp);
                int newLength = length;

                // if remaining byte array size is smaller than buffer size, then use smaller buffer
                if (i + length > bytes.length) {
                    newLength = bytes.length - i;
                }
                //create new buffer for that size
                buffer = new byte[newLength];
            }
            //fill the temp buffer
            buffer[i%length] = bytes[i];
        }
        //encrypt the last remaining part
        temp = baseCipher.encrypt(buffer);
        response = Util.append(response, temp);
        return response;
    }

}
