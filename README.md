# SecureVaultEncryptUtil

custom util to get encrypted password for WSO2

### How to build and run
run `mvn clean install`

run the *encrypt* script as follows

`./encrypt <mode(encrypt|decrypt)> <plainTextPassword> <propertiesFilePath>`

**Security Tip:** when executing the encrypt script, start with a *whitespace* so that this command will not be available in the .bash_history file
and the plain text password can not be seen

####Note
 The encrypted password will be written to the log file as well. (log file will get created in "<PROJECT_HOME>/log" folder by default and if you need you can change that behavior using a log4j.properties file)

####Note
 If you doesn't provide a properties file, it will take the default one which is in project folder, so you can use that to mention required properties
Below are the properties you can configure through properties file

keystore.identity.location=keystore location<br />
keystore.identity.store.username=keystore user name<br />
keystore.identity.store.password=keystore password<br />
keystore.identity.alias=key alias<br />
keystore.identity.type=(JKS etc)<br />
keystore.identity.parameters=enableHostnameVerifier=false;keyStoreCertificateFilePath=/home/esb.cer<br />
keystore.identity.key.username=key user name<br />
keystore.identity.key.password=key password<br />
cipher.algorithm=defaults to RSA<br />
cipher.type=('symmetric' or 'asymmetric')<br />
security.provider=(BC etc)<br />
input.encode.type=says whether input is in which encoding type, defaults to BASE64 in decrypt path and defaults to null(no encoding) in encrypt path<br />
output.encode.type=says output should be in which encoding type, defaults to null(no encoding) in decrypt path and defaults to BASE64 in encrypt path<br />
