

keytool -genkey -keyalg RSA -keysize 2048 -keystore NONE \
-storetype PKCS11 -storepass 123456 \
-providername SunPKCS11-CryptoServer -alias authdemo \
-dname "CN=www.test.cepsacorp.es, OU=System Engineering HSM, \
O=Cepsa,L=Madrid, S=NRW,C=ES"



keytool -v -genkeypair -keyalg RSA -keysize 2048 -alias authdemo \
-keystore NONE -storetype PKCS11 -storepass 123456 \
-providername SunPKCS11-CryptoServer



# cert 

keytool -v -genkeypair -keyalg RSA -keysize 2048 -alias pcks11demo \
-keystore NONE -storetype PKCS11 -storepass 123456 \
-providername SunPKCS11-CryptoServer


keytool -v -certreq -alias pcks11demo -file pcks11demo.csr \
-keystore NONE -storetype PKCS11 -storepass 123456 \
-providername SunPKCS11-CryptoServer




        keytool -gencert -alias ca \
            -validity 3650 -sigalg SHA512withRSA \
            -infile "pcks11demo.csr" -outfile "pcks11demo.crt" -rfc \
            -keystore keystore.jks -storepass changeit
            
            
keytool -import -trustcacerts -alias pcks11demo \
-file "pcks11demo.crt" \
-keystore NONE -storetype PKCS11 -storepass 123456 \
-providername SunPKCS11-CryptoServer


!!!!!

keytool -v -importkeystore -srckeystore cid.p12 -srcstoretype PKCS12 -destkeystore NONE -deststoretype PKCS11 -deststorepass 123456 -destprovidername SunPKCS11-CryptoServer 

!!!!!



p11tool2 slot=9 Login=JCE,ask CertAttr="CKA_LABEL=P12 CID Cert" PubKeyAttr="CKA_LABEL=P12 Public Key" PrvKeyAttr="CKA_LABEL=P12 Private Key,CKA_ID=0x503132" ImportP12=cid.p12,ask  

CertAttr=CKA_LABEL="CA Cert",CKA_ID=CA PubKeyAttr=CKA_LABEL="CA Public Key",CKA_ID=0x414243 ImportCert=
 
 
 
p11tool2 slot=9 Login=JCE,ask  CertAttr=CKA_LABEL="P12 CID Cert",CKA_ID=P12 PubKeyAttr=CKA_LABEL="P12 Public Key",CKA_ID=P12 PrvKeyAttr= CKA_LABEL="P12 Private Key",CKA_ID=0x503132 ImportP12=cid.p12,ask 