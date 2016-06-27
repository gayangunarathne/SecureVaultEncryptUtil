# SecureVaultEncryptUtil

custom util to get encrypted password for WSO2

### How to build and run
run `mvn clean install`

run the *encrypt* script as follows

`./encrypt <mode(encrypt|decrypt)> <plainTextPassword> <propertiesFilePath>`

**Security Tip:** when executing the encrypt script, start with a *whitespace* so that this command will not be available in the .bash_history file
and the plain text password can not be seen

Note that encrypted password will be written to the log file as well. (log file will get created in "<PROJECT_HOME>/log" folder by default and if you need you can change that behavior using a log4j.properties file)
