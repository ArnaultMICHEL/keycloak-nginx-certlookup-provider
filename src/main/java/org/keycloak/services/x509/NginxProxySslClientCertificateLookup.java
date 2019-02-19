package org.keycloak.services.x509;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jboss.logging.Logger;
import org.jboss.logging.Logger.Level;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.common.util.PemException;
import org.keycloak.common.util.PemUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.truststore.TruststoreProvider;
import org.keycloak.truststore.TruststoreProviderFactory;

/**
 * The NGINX Provider extract end user X.509 certificate send during TLS mutual authentication,
 * and forwarded in an http header.
 * 
 * NGINX configuration must have : 
 * <code>
 * server { 
 *    ...
 *    ssl_client_certificate                  path-to-my-trustyed-cas-for-client-auth.pem;
 *    ssl_verify_client                       on|optional_no_ca;
 *    ssl_verify_depth                        2;
 *    ...
 *    location / {
 *    ...
 *      sproxy_set_header ssl-client-cert        $ssl_client_escaped_cert;
 *    ...
 *  }
 * </code>
 * 
 * Note that $ssl_client_cert is deprecated, use only $ssl_client_escaped_cert with this implementation
 * 
 * @author <a href="mailto:arnault.michel@toad-consulting.com">Arnault MICHEL</a>
 * @version $Revision: 1 $
 * @since 10/09/2018
 */

public class NginxProxySslClientCertificateLookup extends AbstractClientCertificateFromHttpHeadersLookup {

	private static final Logger log = Logger.getLogger(NginxProxySslClientCertificateLookup.class);

	private static boolean isTruststoreLoaded = false;
	
	private static KeyStore  truststore = null;
	private static Set<X509Certificate> trustedRootCerts = null;
	private static Set<X509Certificate> intermediateCerts = null;
	
    
    public NginxProxySslClientCertificateLookup(String sslCientCertHttpHeader,
                                                 String sslCertChainHttpHeaderPrefix,
                                                 int certificateChainLength,
                                                 KeycloakSession kcsession) {
        super(sslCientCertHttpHeader, sslCertChainHttpHeaderPrefix, certificateChainLength);

    	if (!loadKeycloakTrustStore(kcsession)) {
            log.warn("Keycloak Truststore is null or empty, but it's required for NGINX x509cert-lookup provider");
            log.warn("   see Keycloak documentation here : https://www.keycloak.org/docs/latest/server_installation/index.html#_truststore");
    	}
    }

    /**
     * Removing PEM Headers and end of lines
     * 
     * @param pem
     * @return
     */
    private static String removeBeginEnd(String pem) {
        pem = pem.replace("-----BEGIN CERTIFICATE-----", "");
        pem = pem.replace("-----END CERTIFICATE-----", "");
        pem = pem.replace("\r\n", "");
        pem = pem.replace("\n", "");
        return pem.trim();
    }

    /**
     * Decoding end user certificate, including URL decodeding due to ssl_client_escaped_cert nginx variable.
     */
    @Override
    protected X509Certificate decodeCertificateFromPem(String pem) throws PemException {

        if (pem == null) {
        	log.warn("End user TLS Certificate is NULL! ");
            return null;
        }
    	try {
			pem = java.net.URLDecoder.decode(pem, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			log.error("Cannot URL decode the end user TLS Certificate : " + pem,e);
		}
    	
        if (pem.startsWith("-----BEGIN CERTIFICATE-----")) {
            pem = removeBeginEnd(pem);
        }

        return PemUtils.decodeCertificate(pem);
    }

    @Override
    public X509Certificate[] getCertificateChain(HttpRequest httpRequest) throws GeneralSecurityException {
        List<X509Certificate> chain = new ArrayList<>();

        // Get the client certificate
        X509Certificate clientCert = getCertificateFromHttpHeader(httpRequest, sslClientCertHttpHeader);
        log.debugf("End user certificate found : Subject DN=[%s]  SerialNumber=[%s]", clientCert.getSubjectDN().toString(), clientCert.getSerialNumber().toString() );
        
        if (clientCert != null) {
            
        	// Rebuilding the end user certificate chain using Keycloak Truststore
            X509Certificate[] certChain = buildChain(clientCert);
            if ( certChain == null || certChain.length == 0 ) {
            	log.info("Impossible to rebuild end user cert chain : client certificate authentication will fail." );
            	chain.add(clientCert);
            } else {
            	for (X509Certificate cacert : certChain) {
            		chain.add(cacert);
            		log.debugf("Rebuilded user cert chain DN : %s", cacert.getSubjectDN().toString() );
            	}
            }
        }
        return chain.toArray(new X509Certificate[0]);
    }

    /**
     *  As NGINX cannot actually send the CA Chain in http header(s), 
     *  we are rebuilding here the end user certificate chain with Keycloak truststore.
     *  <br>
     *  Please note that Keycloak truststore must contain root and intermediate CA's certificates.
     * @param end_user_auth_cert
     * @return
     */
	public X509Certificate[] buildChain(X509Certificate end_user_auth_cert) {
		
		X509Certificate[] user_cert_chain = null;
		
        try {
        	
        	// No truststore : no way!
            if (truststore == null) {
                log.warn("Keycloak Truststore is null, but it is required !");
                log.warn("  see https://www.keycloak.org/docs/latest/server_installation/index.html#_truststore");
                return null;
            }

            // Create the selector that specifies the starting certificate
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(end_user_auth_cert);

            // Create the trust anchors (set of root CA certificates)
            Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
            for (X509Certificate trustedRootCert : trustedRootCerts) {
                trustAnchors.add(new TrustAnchor(trustedRootCert, null));
            }
            // Configure the PKIX certificate builder algorithm parameters
            PKIXBuilderParameters pkixParams = new PKIXBuilderParameters( trustAnchors, selector);
            
            // Disable CRL checks, as it's possibly done after depending on Keycloak settings
            pkixParams.setRevocationEnabled(false);
            pkixParams.setExplicitPolicyRequired(false);
            pkixParams.setAnyPolicyInhibited(false);
            pkixParams.setPolicyQualifiersRejected(false);
            pkixParams.setMaxPathLength(certificateChainLength);
            
            // Adding the list of intermediate certificates + end user certificate
            intermediateCerts.add(end_user_auth_cert);
            CollectionCertStoreParameters intermediateCA_userCert = new CollectionCertStoreParameters(intermediateCerts);
            CertStore intermediateCertStore = CertStore.getInstance("Collection", intermediateCA_userCert, "BC");
            pkixParams.addCertStore(intermediateCertStore);

            // Build and verify the certification chain (revocation status excluded)
            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX","BC");
            CertPath certPath = certPathBuilder.build(pkixParams).getCertPath();
            log.debug("Certification path building OK, and contains " + certPath.getCertificates().size() + " X509 Certificates");
            
            user_cert_chain = convertCertPathtoX509CertArray( certPath );
            
        } catch (NoSuchAlgorithmException e) {
        	log.error(e.getLocalizedMessage(),e);
        } catch (CertPathBuilderException e) {
            if ( log.isEnabled(Level.TRACE) )
            	log.debug(e.getLocalizedMessage(),e);
            else
            	log.warn(e.getLocalizedMessage());
        } catch (InvalidAlgorithmParameterException e) {
        	log.error(e.getLocalizedMessage(),e);
        } catch (NoSuchProviderException e) {
        	log.error(e.getLocalizedMessage(),e);
		} finally {
	        //Remove end user certificate
	        intermediateCerts.remove(end_user_auth_cert);
		}
        
        return user_cert_chain;
	}


	public X509Certificate[] convertCertPathtoX509CertArray( CertPath certPath ) {
        
		X509Certificate[] x509certchain = null;
				
		if (certPath!=null) {
            List<X509Certificate> trustedX509Chain = new ArrayList<X509Certificate>();
            for (Certificate certificate : certPath.getCertificates() )
        	    if ( certificate instanceof X509Certificate )
        		    trustedX509Chain.add((X509Certificate)certificate);
            x509certchain = trustedX509Chain.toArray(new X509Certificate[0]);
		}

		return x509certchain;
		
	}
	
	/**  Loading truststore @ first login
	 * 
	 * @param kcsession
	 * @return
	 */
	public boolean loadKeycloakTrustStore(KeycloakSession kcsession) {

		if (!isTruststoreLoaded) {
			log.debug(" Loading Keycloak truststore ...");
			KeycloakSessionFactory factory = kcsession.getKeycloakSessionFactory();
	        TruststoreProviderFactory truststoreFactory = (TruststoreProviderFactory) factory.getProviderFactory(TruststoreProvider.class, "file");
	        
	        TruststoreProvider provider = truststoreFactory.create(kcsession);
	        
	        if ( provider != null && provider.getTruststore() != null ) {
	        	truststore = provider.getTruststore();
	        	readTruststore();
				log.debug("Keycloak truststore loaded for NGINX x509cert-lookup provider.");
	
	        	isTruststoreLoaded = true;
	        }
        }

		return isTruststoreLoaded;
	}

	/**
	 * Get all certificates from Keycloak Truststore, and classify them in two lists : root CAs and intermediates CAs
	 */
	private void readTruststore() {
		
    	//Reading truststore aliases & certificates
    	Enumeration enumeration;
    	
    	trustedRootCerts  = new HashSet<X509Certificate>();
    	intermediateCerts = new HashSet<X509Certificate>();
    	
		try {

			enumeration = truststore.aliases();
			log.trace("Checking " + truststore.size() + " entries from the truststore.");
            while(enumeration.hasMoreElements()) {

                String alias = (String)enumeration.nextElement();
                Certificate certificate = truststore.getCertificate(alias);

                if (certificate instanceof X509Certificate) {
                	X509Certificate cax509cert = (X509Certificate) certificate;
                	if (isSelfSigned(cax509cert)) {
                        trustedRootCerts.add(cax509cert);
                        log.debug("Trusted root CA found in trustore : alias : "+alias + " | Subject DN : " + ((X509Certificate) certificate).getSubjectDN() );
                    } else {
                        intermediateCerts.add(cax509cert);
                        log.debug("Intermediate CA found in trustore : alias : "+alias + " | Subject DN : " + ((X509Certificate) certificate).getSubjectDN() );
                    }
                } else
                	log.info("Skipping certificate with alias ["+ alias + "] from truststore, because it's not an X509Certificate");
                
            }
		} catch (KeyStoreException e) {
			log.error("Error while reading Keycloak truststore "+e.getMessage(),e);
		} catch (CertificateException e) {
			log.error("Error while reading Keycloak truststore "+e.getMessage(),e);
		} catch (NoSuchAlgorithmException e) {
			log.error("Error while reading Keycloak truststore "+e.getMessage(),e);
		} catch (NoSuchProviderException e) {
			log.error("Error while reading Keycloak truststore "+e.getMessage(),e);
		}
	}
	
	/**
     * Checks whether given X.509 certificate is self-signed.
     */
    public boolean isSelfSigned(X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
        	log.trace("certificate " + cert.getSubjectDN() + " detected as root CA");
            return true;
        } catch (SignatureException sigEx) {
            // Invalid signature --> not self-signed
        	log.trace("certificate " + cert.getSubjectDN() + " detected as intermediate CA");
        } catch (InvalidKeyException keyEx) {
            // Invalid key --> not self-signed
        	log.trace("certificate " + cert.getSubjectDN() + " detected as intermediate CA");
        }
        return false;
    }

}
