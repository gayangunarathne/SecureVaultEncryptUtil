package org.wso2.custom.crypto.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.CipherOperationMode;
import org.wso2.securevault.DecryptionProvider;
import org.wso2.securevault.EncodingType;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.definition.IdentityKeyStoreInformation;
import org.wso2.securevault.definition.KeyStoreInformationFactory;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Security;
import java.util.Properties;

/**
 * Class which does the decryption and if provided, encoding part as well
 */
public class DecryptionHelper {
    private static Log log = LogFactory.getLog(sample.class);

    /**
     * Method to run encryption.
     *
     * @param args
     * @throws Exception
     */
    public static void decrypt(String[] args) {
        log.info("******************************** Start decryption ********************************");
        if (args.length != 2 && args.length != 3) {
            log.error("Invalid number of parameters, found - " + args.length + ", required - 3");
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
            inType = Util.getEncodeDecodeType(inTypeString, EncodeDecodeTypes.BASE64);


            String outTypeString = MiscellaneousUtil.getProperty(properties, Constants.OUTPUT_ENCODE_TYPE,
                                                                 null);
            outType = Util.getEncodeDecodeType(outTypeString, null);

            CipherInformation cipherInformation = new CipherInformation();
            cipherInformation.setAlgorithm(algorithm);
            cipherInformation.setCipherOperationMode(CipherOperationMode.DECRYPT);
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

            DecryptionProvider baseCipher = CipherFactory.createCipher(cipherInformation, identityKeyStoreWrapper);

            byte[] toDecrypt = args[1].getBytes();
            if (inType != null) {
                toDecrypt = EncodeDecodeHelper.decode(toDecrypt, inType);
            }

            byte[] decrypted;
            if (algorithm !=null && !algorithm.isEmpty() && algorithm.equals(Constants.CIPHER_ALGORITHM_DEFAULT)) {
                decrypted = blockCipher(baseCipher, toDecrypt, Cipher.DECRYPT_MODE);
            } else {
                decrypted = baseCipher.decrypt(toDecrypt);
            }

            if (outType != null) {
                decrypted = EncodeDecodeHelper.encode(decrypted, outType);
            }
            String encodedValue = new String(decrypted);
            log.info("Decrypted (may be encoded) - " + encodedValue);

            log.info("******************************** End decryption ********************************");
        } catch (SecureVaultException e) {
            log.error("SecureVault exception, " + e.getMessage(), e);
        }
    }

    private static byte[] blockCipher(DecryptionProvider baseCipher, byte[] bytes, int mode) {
        // hold temp results
        byte[] scrambled = new byte[0];
        // full response
        byte[] toReturn = new byte[0];
        // if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
        int length = (mode == Cipher.ENCRYPT_MODE)? 100 : 128;
        //temp decryption bufffer
        byte[] buffer;
        if (bytes.length < length) {
            buffer = new byte[bytes.length];
        } else {
            buffer = new byte[length];
        }

        for (int i=0; i< bytes.length; i++){
            //when buffer is filled, then decrypt
            if ((i > 0) && (i % length == 0)){
                scrambled = baseCipher.decrypt(buffer);
                // append results
                toReturn = Util.append(toReturn, scrambled);
                // here we calculate the length of the next buffer required
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

        //decrypt the last remaining part
        scrambled = baseCipher.decrypt(buffer);
        toReturn = Util.append(toReturn, scrambled);

        return toReturn;
    }

}
