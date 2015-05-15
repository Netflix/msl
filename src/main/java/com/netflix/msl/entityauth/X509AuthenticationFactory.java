/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.netflix.msl.entityauth;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.json.JSONObject;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.EccCryptoContext;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>X.509 asymmetric keys entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class X509AuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * Construct a new X.509 asymmetric keys authentication factory instance.
     * 
     * @param store X.509 certificate authority store.
     * @param authutils entity authentication utilities.
     */
    public X509AuthenticationFactory(final X509Store store, final AuthenticationUtils authutils) {
        super(EntityAuthenticationScheme.X509);
        this.caStore = store;
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, org.json.JSONObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final JSONObject entityAuthJO) throws MslCryptoException, MslEncodingException {
        return new X509AuthenticationData(entityAuthJO);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslCryptoException, MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof X509AuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final X509AuthenticationData x509ad = (X509AuthenticationData)authdata;
    	final String identity = x509ad.getIdentity();

    	// Check for revocation.
    	if (authutils.isEntityRevoked(identity))
    		throw new MslEntityAuthException(MslError.ENTITY_REVOKED, x509ad.getX509Cert().toString()).setEntity(x509ad);

    	// Verify the scheme is permitted.
    	if (!authutils.isSchemePermitted(identity, getScheme()))
    		throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + getScheme()).setEntity(x509ad);

    	// Verify the cert(s) and return the crypto context.
        if (x509ad.getSize() == 1) {
        	final X509Certificate cert = x509ad.getX509Cert();
        	
        	try {
        		if (!caStore.isAccepted(cert))
        			throw new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED, cert.toString()).setEntity(x509ad);
        	} catch (final CertificateExpiredException e) {
        		throw new MslEntityAuthException(MslError.X509CERT_EXPIRED, cert.toString(), e).setEntity(x509ad);
        	} catch (final CertificateNotYetValidException e) {
        		throw new MslEntityAuthException(MslError.X509CERT_NOT_YET_VALID, cert.toString(), e).setEntity(x509ad);
        	}

        	// Return the crypto context.
        	return createCryptoContext(ctx, identity, cert);
        } else {
        	List<X509Certificate> certList = x509ad.getX509Certs();

        	// Identify root certificate
        	X509Certificate root = null;
        	for (X509Certificate cert : certList) {
        		if (isSelfSigned(cert)) {
        			root = cert;
        			break;
        		}
        	}
        	if (root == null) {
        		throw new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED, "No Root in Certificate Chain").setEntity(x509ad);
        	}
        	
        	// Assuming no order in the incoming certificate list, build an
        	// ordered certificate chain from leaf to root by linking subject to
        	// issuer.
        	int listSize = certList.size();
        	LinkedList<X509Certificate> chain = new LinkedList<>();
        	chain.add(root);
        	certList.remove(root);
        	//System.out.println(root.getSubjectX500Principal().getName());
        	int i = 1; // already added root to the chain
        	X500Principal issuerTarget = root.getSubjectX500Principal();
        	while (i++ < listSize) {
        		for (Iterator<X509Certificate> it = certList.iterator(); it.hasNext();) {
        			X509Certificate curCert = it.next();
        			X500Principal curIssuer = curCert.getIssuerX500Principal();
        			if (curIssuer.equals(issuerTarget)) {
        				chain.add(curCert);
        	        	//System.out.println(curCert.getSubjectX500Principal().getName());
        				issuerTarget = curCert.getSubjectX500Principal();
        				it.remove(); // safe with this collection/iterator
        				break;
        			}
        		}
        	}
        	if (chain.size() != listSize) {
        		throw new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED, "Certificate Chain Is Disjoint").setEntity(x509ad);
        	}
        	//System.out.println("root: " + chain.getFirst().getSubjectX500Principal().getName());
        	//System.out.println("leaf: " + chain.getLast().getSubjectX500Principal().getName());
        	//System.out.println();
        	
        	X509Certificate leaf = chain.getLast();

        	// Validate each certificate in the chain, starting from the root.
        	// The root certificate must validate against the system certificate
        	// store, and all others must validate against either the system
        	// store or one of the others in the chain. Note the logic below
        	// requires root-to-leaf ordering of the chain.
        	X509Store localStore = new X509Store();
    		for (Iterator<X509Certificate> it = chain.iterator(); it.hasNext();) {
    			X509Certificate cert = it.next();
    			//System.out.println(cert.getSubjectX500Principal().getName());
            	try {
            		if (caStore.isAccepted(cert)) {
            			localStore.addTrusted(cert);
            		} else {
            			if (localStore.isAccepted(cert)) {
            				if (!cert.equals(leaf)) {
            					localStore.addTrusted(cert);
            				}
            			} else {
            				throw new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED, cert.toString()).setEntity(x509ad);
            			}
            		}
            	} catch (CertificateExpiredException e) {
            		throw new MslEntityAuthException(MslError.X509CERT_EXPIRED, cert.toString(), e).setEntity(x509ad);
            	} catch (CertificateNotYetValidException e) {
            		throw new MslEntityAuthException(MslError.X509CERT_NOT_YET_VALID, cert.toString(), e).setEntity(x509ad);
            	} catch (InvalidKeyException|CertificateException|SignatureException|NoSuchAlgorithmException|NoSuchProviderException e) {
    				throw new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED, e.getMessage() + "\n" +
    						cert.toString()).setEntity(x509ad);
				}
    		}
        	
        	// Return the crypto context built from the leaf certificate.
        	return createCryptoContext(ctx, identity, chain.getLast());
        }
    }
    
    private ICryptoContext createCryptoContext(MslContext ctx, String identity, X509Certificate cert) throws MslEntityAuthException {
    	switch (cert.getSigAlgName()) {
	    	case "SHA1withRSA":
	    	case "SHA256withRSA":
	    		return new RsaCryptoContext(ctx, identity, null, cert.getPublicKey(), RsaCryptoContext.Mode.SIGN_VERIFY);
	    	case "SHA1withECDSA":
	    		return new EccCryptoContext(identity, null, cert.getPublicKey(), EccCryptoContext.Mode.SIGN_VERIFY);
	    	default:
	    		throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Signature Algorithm Name Not Suported: " + cert.getSigAlgName());
    	}
    }
    
    /**
     * <p>Return true if the certificate is self-signed.</p>
     * 
     * @param cert the certificate.
     * @return true if the certificate is self-signed.
     */
    private boolean isSelfSigned(final X509Certificate cert) {
        final X500Principal subject = cert.getSubjectX500Principal();
        final X500Principal issuer = cert.getIssuerX500Principal();
        return subject.equals(issuer);
    }

    /** X.509 CA store. */
    private final X509Store caStore;
    /** Entity authentication utilities. */
    private final AuthenticationUtils authutils;
}
