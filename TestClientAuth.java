/**
 * 
 */
package com.cepsa.sign.client;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.net.util.TrustManagerUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import CryptoServerAPI.CryptoServerException;
import CryptoServerJCE.CryptoServerPrivateKey;
import CryptoServerJCE.CryptoServerProvider;

/**
 * @author nico
 *
 */
public class TestClientAuth {

	 CryptoServerProvider provider = null;
		
	/**
	 * 
	 */
	public TestClientAuth() {
		// TODO Auto-generated constructor stub
	}

	
	
	public void testConnect() throws Exception{
		
		 CryptoServerProvider provider = null;
		    
		    try
		    {
		      provider = new CryptoServerProvider("CryptoServer.cfg");
		      System.out.println("Device  : " + provider.getCryptoServer().getDevice());

		      // authenticate
		      provider.loginPassword("JCE", "123456");
		      
		      // open key store                                                            
		      KeyStore keyStore = KeyStore.getInstance("CryptoServer", provider);       
		      keyStore.load(null, null);    
		      LoggerFactory.getLogger(getClass()).info("KeyStore: " + keyStore.getType() + "\n");

				SSLContext sslContext = SSLContexts.custom()
				        .loadKeyMaterial(keyStore, null)
				        .build();


		      // list keys    
		      Enumeration<String> kl = keyStore.aliases();
		      
		      LoggerFactory.getLogger(getClass()).info(String.format("%-12s %-20s %s", "type", "name", "creation date"));          
		      LoggerFactory.getLogger(getClass()).info("----------------------------------------------------------------------");
		      
		      while (kl.hasMoreElements())
		      {
		        String name = kl.nextElement();      
		        Date date = keyStore.getCreationDate(name);
		        String type;
		        
		        if (keyStore.isKeyEntry(name))       
		          type = "Key";      
		        else if (keyStore.isCertificateEntry(name))      
		          type = "Certificate";      
		        else       
		          type = "???";      
		        LoggerFactory.getLogger(getClass()).info(String.format("%-12s %-20s %s", type, name, date));      
		        
		        
		        CryptoServerPrivateKey key = (CryptoServerPrivateKey)keyStore.getKey(name, null);
		        
		        LoggerFactory.getLogger(getClass()).info(String.format("private %s public %s", key.toString(),keyStore.getCertificate(name) ));
		      }
		      
				HttpClient httpClient = HttpClients.custom().setSslcontext(sslContext).build();
				HttpResponse response = httpClient.execute(new HttpGet("https://example.com"));

		    }
		    catch (Exception ex)
		    {
		      throw ex;
		    }
		    finally
		    {
		      // logoff
		      if (provider != null)
		        provider.logoff();
		    }

	}
	
	@Test
	public final  void requestTimestamp() throws Exception {
		
			
		SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(
	            createSslCustomContext(),
	            new String[]{"TLSv1"}, // Allow TLSv1 protocol only
	            null,
	            new NoopHostnameVerifier());//SSLConnectionSocketFactory.getDefaultHostnameVerifier()
	    try (CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(csf).build()) {
	    	HttpGet req = new HttpGet("https://localhost:8443/user");
	        req.setConfig(configureRequest());
//	        HttpEntity ent = new InputStreamEntity(new FileInputStream("./bytes.bin"));
//	        req.setEntity(ent);
	        try (CloseableHttpResponse response = httpclient.execute(req)) {
	            HttpEntity entity = response.getEntity();
	            
				LoggerFactory.getLogger(getClass()).info( "*** Reponse status: {}", response.getStatusLine());
	            EntityUtils.consume(entity);
	            LoggerFactory.getLogger(getClass()).info( "*** Response entity: {}", entity.toString());
	        }
	    }catch (Exception e) {
	    	e.printStackTrace();
			throw e;
		}finally {
		      if (provider != null)
			        provider.logoff();

		}
	}

	public static RequestConfig configureRequest() {
	    HttpHost proxy = new HttpHost("localhost", 8443, "http");
	    RequestConfig config = RequestConfig.custom()
//	            .setProxy(proxy)
	            .build();
	    return config;
	}

		public  SSLContext createSslCustomContext() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException, NumberFormatException, CryptoServerException {
//	    // Trusted CA keystore
//	    KeyStore tks = KeyStore.getInstance("JKS");
//	    tks.load(new FileInputStream("/home/nico/java/examples/tutorials-master/spring-security-x509/keystore/truststore.jks"), "changeit".toCharArray());
//
		KeyStore tks = KeyStore.getInstance("JKS");
	    tks.load(new FileInputStream("/home/nico/java/examples/tutorials-master/spring-security-x509/keystore/keystore.jks"), "changeit".toCharArray());
//
		// Client keystore
//	    KeyStore cks = KeyStore.getInstance("JKS");
//	    cks.load(new FileInputStream("/home/nico/java/examples/tutorials-master/spring-security-x509/keystore/keystore.jks"), "changeit".toCharArray());

//	    KeyStore cks = KeyStore.getInstance("PKCS12");
//	    cks.load(new FileInputStream("/home/nico/java/examples/tutorials-master/spring-security-x509/keystore/cid.p12"), "changeit".toCharArray());

//	    cks.set
//	    cks.load(new FileInputStream("/home/nico/java/examples/tutorials-master/spring-security-x509/keystore/cid.p12"), "changeit".toCharArray());

//	    keystore="NONE" keystorePass="123456" keystoreType="PKCS11"
//	    		keystoreProvider="SunPKCS11-CryptoServer"
//	    
//	    provider = new CryptoServerProvider("CryptoServer.cfg");
//	    System.out.println("Device  : " + provider.getCryptoServer().getDevice());
//      // authenticate
//      provider.loginPassword("JCE", "123456");
//	      
//      for (Provider provider : Security.getProviders()){
//    	    System.out.println(provider);
//    	}
//	      // open key store                                                            
//	      KeyStore cks = KeyStore.getInstance("CryptoServer", provider); 
//	      cks.load(null, null);    
//	      LoggerFactory.getLogger(getClass()).info("KeyStore: " + cks.getType() + "\n");

	    Logger LOG =  LoggerFactory.getLogger(getClass());
//	    
	    LOG.debug("Trust");
	    debugCerts(tks, LOG);
	    
	    
	    Provider provider = Security.getProvider("SunPKCS11-CryptoServer");
	    LOG.debug("{}",provider.getServices());
	    
	    KeyStore cks = KeyStore.getInstance("PKCS11-CryptoServer", provider);  //works fine. he asks for a right pin - cancels when pin is wrong
	    cks.load(null, "123456".toCharArray());                                                                                                         // load private keystore
	    //SunPKCS11-CryptoServer: KeyStore.PKCS11 -> sun.security.pkcs11.P11KeyStore
//	    aliases: [PKCS11-CryptoServer]
//	    		 (KeyStore)]

	    LOG.debug("Key");
	    debugCerts(cks, LOG);

	    KeyManagerFactory kmf =  
	            KeyManagerFactory.getInstance("SunX509");
	    
	    kmf.init(cks, "123456".toCharArray());    
	   
	    
	    System.out.println("init truststore");
	    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());            // init truststore
	    tmf.init(tks);

//	    CryptoServerProvider provider = null;
//   	    provider = new CryptoServerProvider("CryptoServer.cfg");
//	    System.out.println("Device  : " + provider.getCryptoServer().getDevice());
//
//	      // authenticate
//	      provider.loginPassword("JCE", "123456");
//	      
//	      // open key store                                                            
//	      KeyStore keyStore = KeyStore.getInstance("CryptoServer", provider);       
//	      keyStore.load(null, null);    
//	      LoggerFactory.getLogger(ClientCustomSSL.class).info("KeyStore: " + keyStore.getType() + "\n");

	    TrustStrategy trustStrategy = new TrustStrategy() {

	        public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
	            for (X509Certificate cert: chain) {
	                System.err.println(cert);
	            }
	            return true;
	        }

	    };


	    SSLContext sslcontext = SSLContexts.custom()
	            .loadTrustMaterial(tks,trustStrategy) // new TrustSelfSignedStrategy() // use it to customize
	            .loadKeyMaterial(cks, "123456".toCharArray()) // load client certificate
	            .build();
	    
//	    SSLContext ctx = SSLContext.getInstance("TLS");
//	    ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
	    SSLContext.setDefault(sslcontext);

	    
	    
	    return sslcontext;
	}


//	@Test
	public SSLContext installSSLContextPKCS11() throws Exception {
//	    PKCS11Provider provider = new PKCS11Provider("/usr/lib/opensc-pkcs11.so.BAK");
	    
	    
      
	    System.out.println("loading truststore");
//	    KeyStore tks = KeyStore.getInstance(KeyStore.getDefaultType());
//	    tks.load(new FileInputStream("/home/dan/Dokumente/Zertifikate/store"), "xxx".toCharArray());                   // load truststore
	    KeyStore tks = KeyStore.getInstance("JKS");
	    tks.load(new FileInputStream("/home/nico/java/examples/tutorials-master/spring-security-x509/keystore/truststore.jks"), "changeit".toCharArray());

	    
	    
//	    provider = new CryptoServerProvider("CryptoServer.cfg");
//	    System.out.println("Device  : " + provider.getCryptoServer().getDevice());
//	      // authenticate
//	       provider.loginPassword("JCE", "123456");
//	       Security.addProvider(provider);
//	    System.out.println("loading keystore");
//	    
//	    S
	    KeyStore iks = KeyStore.getInstance("PKCS11-CryptoServer", Security.getProvider("SunPKCS11-CryptoServer"));  //works fine. he asks for a right pin - cancels when pin is wrong
	    iks.load(null, "123456".toCharArray());                                                                                                         // load private keystore


	    
	    
//	    Builder builder = Builder.newInstance("PKCS11", provider, new KeyStore.CallbackHandlerProtection(){});
//	    KeyManagerFactory kmf = KeyManagerFactory.getInstance("sunx509", "SunPKCS11-CryptoServer"); //sunx509
//	    kmf.init(iks, "123456".toCharArray());
//	    kmf.init(new KeyStoreBuilderParameters(builder));
//	    
	    KeyManagerFactory kmf =  
	            KeyManagerFactory.getInstance("SunX509");
	    
	    kmf.init(iks, "123456".toCharArray());    
	   
	    
	    System.out.println("init truststore");
	    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());            // init truststore
	    tmf.init(tks);

//	    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");  // here is the problem. It seems that the pin is ignored. and if i overgive the provider (like KeyStore.getInstance-Method)i get an NoSuchAlgorithmException (for stacktrace see below)
//	    kmf.init(null, "834950".toCharArray());  //The debugger shows in kmf.getKeyManagers()-Array no priv. Key or anything. It contains nothing but an empty hashmap (or something like this) with p12 it contains the priv. key and the certificate from the smart card

	    System.out.println("setting sslcontext");
	    SSLContext ctx = SSLContext.getInstance("TLS");
	    ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
	    SSLContext.setDefault(ctx);

	    
	    return ctx;
//	    System.out.println("doing handshake");
//	    final SSLSocketFactory factory = ctx.getSocketFactory();
//	    final SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 8443);
//	    socket.setUseClientMode(true);
//	    socket.startHandshake();   // here i try to do the handshake. it works with a p12-keystore... like ahead. with pkcs11 i get an SSLHandshakeException (Received fatal alert: handshake_failure)
//	    System.out.println("done");
	}
	
	
	private static CallbackHandler myCallbackHandler = new CallbackHandler() {
	    @Override
	    public void handle(Callback[] callbacks) throws IOException,
	            UnsupportedCallbackException {
	        for (Callback callback : callbacks) {
	            if (callback instanceof PasswordCallback) {
	                PasswordCallback passwordCallback = (PasswordCallback) callback;
	                System.out.println(passwordCallback.getPrompt() + "123456");
	                passwordCallback.setPassword("123456".toCharArray());
	            }
	        }
	    }
	};
	
	public void setUpProvider() throws IOException, GeneralSecurityException{
		String pkcs11config;
		Logger LOG =  LoggerFactory.getLogger(getClass());
//	    
//		pkcs11config = "name = Cryptoki";
//		pkcs11config += "\nlibrary = /SCDriver/libbit4ipki.dylib";
//		InputStream confStream = new ByteArrayInputStream(pkcs11config.getBytes());
//		SunPKCS11 sunpkcs11 = new SunPKCS11(confStream);
//		Security.addProvider(sunpkcs11);

	    Provider provider = Security.getProvider("SunPKCS11-CryptoServer");
	    LOG.debug("{}",provider.getServices());
	    KeyStore cks = KeyStore.getInstance("PKCS11-CryptoServer", provider);  //works fine. he asks for a right pin - cancels when pin is wrong
	    cks.load(null, "123456".toCharArray());                                                                                                         // load private keystore

		// Specify keystore builder parameters for PKCS#11 keystores
		Builder scBuilder = Builder.newInstance("PKCS11", provider, new KeyStore.CallbackHandlerProtection(myCallbackHandler));

		// Create and init KeyManagerFactory
		KeyManagerFactory factory = KeyManagerFactory.getInstance("NewSunX509");
		factory.init(new KeyStoreBuilderParameters(scBuilder));

		TrustManagerUtils.getDefaultTrustManager(cks);
			
		// create and init ssl context
//		m_ssl_context = SSLContext.getInstance("TLS");
//		m_ssl_context.init(factory.getKeyManagers(), new TrustManager[] {new DummyX509TrustManager()}, null);      
//		SSLContext.setDefault(m_ssl_context);
	}
	/**
	 * @param tks
	 * @param LOG
	 * @throws KeyStoreException
	 */
	private void debugCerts(KeyStore tks, Logger LOG) throws KeyStoreException {
		if (LOG.isDebugEnabled()) {
            Enumeration aliases = tks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String)aliases.nextElement();                        
                Certificate[] certs = tks.getCertificateChain(alias);
                if (certs != null) {
                    LOG.debug("Certificate chain '" + alias + "':");
                    for (int c = 0; c < certs.length; c++) {
                        if (certs[c] instanceof X509Certificate) {
                            X509Certificate cert = (X509Certificate)certs[c];
                            LOG.debug(" Certificate " + (c + 1) + ":");
                            LOG.debug("  Subject DN: " + cert.getSubjectDN());
                            LOG.debug("  Signature Algorithm: " + cert.getSigAlgName());
                            LOG.debug("  Valid from: " + cert.getNotBefore() );
                            LOG.debug("  Valid until: " + cert.getNotAfter());
                            LOG.debug("  Issuer: " + cert.getIssuerDN());
                        }
                    }
                }
            }
        }
	}
}
