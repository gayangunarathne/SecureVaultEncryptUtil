package org.wso2.custom.crypto.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * This class is the main class which runs encryption or decryption
 */
public class VaultEncryptDecrypt {
    private static Log log = LogFactory.getLog(VaultEncryptDecrypt.class);

    /**
     * Main method.
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
//        String[] arg = {"encrypt", "smb://user1:pass@smb.host/project", "temp/secureVault.properties"};
        String[] arg = {"decrypt", "IzaL649JwXeRpRIgXGmVGCJBmJ6m1Dxlb0+0b4fgMyHBITJF/aItZKjAVy/glzGVFZD0+Nrfc5nbOHq1J8tm1I011Zv6wEPpwtdiRRLPzxKkaVzhtcyZppZbmzQ/u34gEYJd59q0S0WOPL2bQuqhTJEmglGyEALrPBei8mpCZuo=", "temp/secureVault.properties"};
//        String[] arg = {"[B@20c92ed6", "temp/secureVault.properties"};
//        String[] arg = {"vfs:sftp://test:123@localhost/media/rajith/Office/Wso2/support/source/projects/projects/carbon/turing/platform/trunk/products/esb/4.8.1/modules/integration/tests-patches/src/test/resources/artifacts/ESB/synapseconfig/vfsTransport/SFTP_Location/in", "temp/secureVault.properties"};
        encryptOrDecrypt(args);
    }

    /**
     * Helper method to differentiate encrypt and decrypt paths.
     * @param args
     */
    private static void encryptOrDecrypt(String[] args) {
        if (args[0] != null && !args[0].isEmpty() && args[0].equals("encrypt")) {
            EncryptionHelper.encrypt(args);
        } else if (args[0] != null && !args[0].isEmpty() && args[0].equals("decrypt")) {
            DecryptionHelper.decrypt(args);
        } else {
            log.error("Invalid first argument type, required either 'encrypt' or 'decrypt', provided - " + args[0]);
        }
    }
}
