/**
 * Copyright (c) 1997-2013 Netflix, Inc.  All rights reserved.
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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import com.netflix.msl.util.Base64;

/**
 * <p>An X.509 certificate store.</p>
 * 
 * <p>This class provides a clearing house of X.509 certificate validation. It
 * contains individual trusted certificates, trusted certificate chains, and
 * may support CRLs in the future. It provides X.509 certificate signature
 * verification, certificate chaining, validity (time) checks, and trust store
 * management functionality.</p>
 */
public class X509Store {
    /**
     * <p>Return the issuing certificate for the provided certificate. The
     * certificate will only be returned if the provided certificate signature
     * is verified by the issuing certificate.</p>
     * 
     * @param cert the certificate.
     * @return the issuing certificate or {@code null} if not found.
     */
    private X509Certificate getIssuer(final X509Certificate cert) {
        final X500Principal issuerDn = cert.getIssuerX500Principal();
        final List<X509Certificate> issuers = store.get(issuerDn);
        if (issuers == null)
            return null;
        for (final X509Certificate issuer : issuers) {
            try {
                cert.verify(issuer.getPublicKey());
                return issuer;
            } catch (final Exception e) {
                // Ignore failures.
            }
        }
        return null;
    }

    /**
     * <p>Returns the chain of issuer certificates for the provided
     * certificate.</p>
     * 
     * <p>The first certificate in the chain will be self-signed and will be
     * ordered with the root certificate in the first position.</p>
     * 
     * @param cert the certificate.
     * @return the ordered chain of issuer certificates.
     * @throws CertificateException if an issuer certificate cannot be found.
     */
    private List<X509Certificate> getIssuerChain(final X509Certificate cert) throws CertificateException {
        final List<X509Certificate> chain = new ArrayList<X509Certificate>();
        X509Certificate current = cert;
        do {
            final X509Certificate issuer = getIssuer(current);
            if (issuer == null)
                throw new CertificateException("No issuer found for certificate: " + Base64.encode(current.getEncoded()));
            chain.add(0, issuer);
            current = issuer;
        } while (!isSelfSigned(current));
        return chain;
    }

    /**
     * <p>Return true if the certificate is self-signed.</p>
     * 
     * @param cert the certificate.
     * @return true if the certificate is self-signed.
     */
    private static boolean isSelfSigned(final X509Certificate cert) {
        final X500Principal subject = cert.getSubjectX500Principal();
        final X500Principal issuer = cert.getIssuerX500Principal();
        return subject.equals(issuer);
    }
    
    /**
     * @param cert the certificate.
     * @return true if the certificate is verified by a trusted certificate.
     */
    private boolean isVerified(final X509Certificate cert) {
        final X509Certificate issuer = getIssuer(cert);
        return (issuer != null);
    }
    
    /**
     * <p>Verifies that the provided certificate is allowed to be a CA
     * certificate based on the issuer chain's path lengths.</p>
     * 
     * @param cert the certificate.
     * @return true if the certificate distance from its issuers is acceptable.
     * @throws CertificateException if an issuer certificate cannot be found.
     */
    private boolean isPermittedByIssuer(final X509Certificate cert) throws CertificateException {
        // Get the issuer chain. It should never be empty.
        final List<X509Certificate> issuerChain = getIssuerChain(cert);
        if (issuerChain.isEmpty())
            return false;
        
        // If at any point in the chain we see a path length set, we use "lazy"
        // chain enforcement: the path length field is optional for all
        // subordinate CA certificates as long the path length has not been
        // exceeded and any path lengths of subordinate certificates are equal
        // to or less than the expected path length.
        int expectedPathLength = -1;
        for (final X509Certificate issuer : issuerChain) {
            final int nextPathLength = issuer.getBasicConstraints();
                        
            // There is no path length in this issuing certificate...
            if (nextPathLength == -1) {
                // If there is no path length from a superior certificate then
                // fail.
                if (expectedPathLength == -1)
                    return false;
                
                // Otherwise decrement the current path length.
                --expectedPathLength;
            }
            
            // Otherwise if this is our first path length then start using it.
            else if (expectedPathLength == -1) {
                expectedPathLength = nextPathLength;
            }
            
            // Otherwise if this certificate's path length is too large then
            // fail.
            else if (nextPathLength > expectedPathLength) {
                return false;
            }
            
            // Otherwise the new path length is acceptable.
            else {
                expectedPathLength = nextPathLength;
            }
            
            // Make sure the path length is not zero.
            if (expectedPathLength == 0)
                return false;
        }
        
        // Make sure this certificate's path length is equal to or less than
        // the expected path length.
        final int next = cert.getBasicConstraints();
        if (next != -1 && next > expectedPathLength)
            return false;
        
        // Success.
        return true;
    }
    
    /**
     * <p>Add one or more trusted certificates (in DER format, binary or Base64-
     * encoded) to this X509Store.</p>
     * 
     * <p>This method calls {@link #addTrusted(X509Certificate)} on each
     * certificate found. If an exception is thrown, any certificates
     * parsed prior to the error will still be in the trust store.</p>
     * 
     * @param input the input stream.
     * @throws IOException if there is an error reading the input stream.
     * @throws CertificateExpiredException if the certificate is expired.
     * @throws CertificateNotYetValidException if the certificate is not yet
     *         valid.
     * @throws CertificateException if a certificate is not a CA certificate, a
     *         certificate is not self-signed and not trusted by an existing
     *         trusted certificate, a certificate is not permitted as a
     *         subordinate certificate, a certificate is malformed, or there is
     *         no X.509 certificate factory.
     * @throws SignatureException if the certificate signature cannot be or
     *         fails to verify for any reason including a malformed certificate.
     * @throws NoSuchAlgorithmException if the signature algorithm is
     *         unsupported.
     * @throws InvalidKeyException if a certificate public key is invalid.
     * @throws NoSuchProviderException if there is no X.509 certificate
     *         provider.
     */
    public void addTrusted(final InputStream input) throws CertificateExpiredException, CertificateNotYetValidException, CertificateException, IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        final BufferedInputStream bis = new BufferedInputStream(input);
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        while (bis.available() > 0) {
            final X509Certificate cert = (X509Certificate)factory.generateCertificate(bis);
            addTrusted(cert);
        }
    }

    /**
     * <p>Add a chain of trusted certificates to this X509Store.</p>
     * 
     * <p>The first certificate in the chain must be self-signed, and all
     * certificates must be CA certificates. The list must be ordered with the
     * root certificate in the first position and the leaf certificate in the
     * last position.</p> 
     * 
     * @param chain the ordered chain of certificates.
     * @throws NoSuchAlgorithmException if the signature algorithm is
     *         unsupported.
     * @throws InvalidKeyException if an certificate's public key is invalid.
     * @throws NoSuchProviderException if there is no signature provider.
     * @throws SignatureException if a certificate signature verification fails.
     * @throws CertificateExpiredException if the certificate is expired.
     * @throws CertificateNotYetValidException if the certificate is not yet
     *         valid.
     * @throws CertificateException if a certificate is malformed or the first
     *         certificate is not a self-signed certificate.
     */
    public void addTrusted(final List<X509Certificate> chain) throws CertificateExpiredException, CertificateNotYetValidException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        // Do nothing if the chain is null or empty.
        if (chain == null || chain.isEmpty())
            return;
        
        // Verify that the root certificate is self-signed and add it.
        X509Certificate issuer = chain.get(0);
        if(!isSelfSigned(issuer))
            throw new CertificateException("First certificate is not self-signed: " + Base64.encode(issuer.getEncoded()));
        addTrusted(issuer);
        
        // Add subordinate certificates.
        for (int i = 1; i < chain.size(); ++i) {
            final X509Certificate cert = chain.get(i);
            cert.verify(issuer.getPublicKey());
            addTrusted(cert);
            issuer = cert;
        }
    }
    
    /**
     * <p>Add a trusted certificate (in DER format, binary or Base64-encoded)
     * to this X509Store.</p>
     * 
     * <p>This method verifies the certificate. That has the effect of
     * requiring the CA root certificate to be added before any subordinate
     * CA certificates.</p>
     * 
     * <p>To add a certificate chain, use {@link #addTrusted(List)} instead.</p>
     * 
     * @param cert the X.509 certificate to add.
     * @throws CertificateExpiredException if the certificate is expired.
     * @throws CertificateNotYetValidException if the certificate is not yet
     *         valid.
     * @throws CertificateException if the certificate is not a CA certificate,
     *         the certificate is not self-signed and not trusted by an
     *         existing trusted certificate, or the certificate is not
     *         permitted as a subordinate certificate, or the certificate is
     *         malformed.
     * @throws SignatureException if the certificate signature cannot be or
     *         fails to verify for any reason including a malformed certificate.
     * @throws NoSuchAlgorithmException if the signature algorithm is
     *         unsupported.
     * @throws InvalidKeyException if a certificate public key is invalid.
     * @throws NoSuchProviderException if there is no X.509 certificate
     *         provider.
     */
    public void addTrusted(final X509Certificate cert) throws CertificateExpiredException, CertificateNotYetValidException, CertificateException, SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        // Verify the certificate not-yet-valid and expiration dates.
        cert.checkValidity();
        
        // Verify this is a CA certificate.
        final int pathlen = cert.getBasicConstraints();
        if (pathlen < 0)
            throw new CertificateException("Certificate is not a CA certificate: " + Base64.encode(cert.getEncoded()));

        // Verify the certificate signature.
        if (isSelfSigned(cert)) {
            cert.verify(cert.getPublicKey());
        } else {
            if (!isVerified(cert))
                throw new CertificateException("Certificate is not self-signed and not trusted by any known CA certificate: " + Base64.encode(cert.getEncoded()));
            
            // Subordinate certificates must have their path length validated.
            if (!isPermittedByIssuer(cert))
                throw new CertificateException("Certificate appears too far from its issuing CA certificate: " + Base64.encode(cert.getEncoded()));
        }

        // Add the certificate.
        final X500Principal subjectName = cert.getSubjectX500Principal();
        if (!store.containsKey(subjectName))
            store.put(subjectName, new ArrayList<X509Certificate>());
        final List<X509Certificate> certs = store.get(subjectName);
        if (!certs.contains(cert))
            certs.add(cert);
    }

    /**
     * <p>Add a trusted certificate (in DER format, binary or Base64-encoded)
     * and its corresponding private key to this X509Store.</p>
     * 
     * <p>This method verifies the certificate. That has the effect of
     * requiring the CA root certificate to be added before any subordinate
     * CA certificates.</p>
     * 
     * <p>To add a certificate chain, use {@link #addTrusted(List)} instead.</p>
     * 
     * @param cert the X.509 certificate to add.
     * @param privkey matching private key to add.
     * @throws CertificateExpiredException if the certificate is expired.
     * @throws CertificateNotYetValidException if the certificate is not yet
     *         valid.
     * @throws CertificateException if the certificate is not a CA certificate,
     *         the certificate is not self-signed and not trusted by an
     *         existing trusted certificate, or the certificate is not
     *         permitted as a subordinate certificate, or the certificate is
     *         malformed.
     * @throws SignatureException if the certificate signature cannot be or
     *         fails to verify for any reason including a malformed certificate.
     * @throws NoSuchAlgorithmException if the signature algorithm is
     *         unsupported.
     * @throws InvalidKeyException if a certificate public key is invalid.
     * @throws NoSuchProviderException if there is no X.509 certificate
     *         provider.
     * @see #getPrivateKey(X509Certificate)
     */
    public void addTrusted(final X509Certificate cert, final PrivateKey privkey) throws CertificateExpiredException, CertificateNotYetValidException, CertificateException, SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        // Add the certificate.
        addTrusted(cert);
        
        // Add the private key.
        final X500Principal subjectName = cert.getSubjectX500Principal();
        privateKeys.put(subjectName, privkey);
    }
    
    /**
     * <p>Return true if the provided certificate is valid and accepted by a
     * trusted certificate in this store.</p>
     * 
     * @param cert the certificate.
     * @return true if the certificate is accepted.
     * @throws CertificateExpiredException if the certificate is expired.
     * @throws CertificateNotYetValidException if the certificate is not yet
     *         valid.
     */
    public boolean isAccepted(final X509Certificate cert) throws CertificateExpiredException, CertificateNotYetValidException {
        cert.checkValidity();
        return isVerified(cert);
    }
    
    /**
     * <p>Return the private key associated with the provided certificate.</p>
     *  
     * @param cert the certificate.
     * @return the private key or null if not found.
     * @see #addTrusted(X509Certificate, PrivateKey)
     */
    public PrivateKey getPrivateKey(final X509Certificate cert) {
        final X500Principal subjectName = cert.getSubjectX500Principal();
        return privateKeys.get(subjectName);
    }

    /** Map of certificate subject names onto X.509 certificates. */
    private final Map</*SubjectName*/X500Principal, List<X509Certificate>> store = new HashMap<X500Principal, List<X509Certificate>>();
    /** Map of certificate subject names onto private keys. */
    private final Map</*SubjectName*/X500Principal, PrivateKey> privateKeys = new HashMap<X500Principal, PrivateKey>();
}
