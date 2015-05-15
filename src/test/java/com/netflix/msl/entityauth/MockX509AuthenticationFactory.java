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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

import org.json.JSONObject;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext;
import com.netflix.msl.crypto.RsaCryptoContext.Mode;
import com.netflix.msl.util.MslContext;

/**
 * Test X.509 asymmetric keys authentication factory.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockX509AuthenticationFactory extends EntityAuthenticationFactory {
    /** X.509 private key. */
    private static final String X509_PRIVATE_KEY = "entityauth/msl.key";
    /** X.509 self-signed resource certificate. */
    private static final String X509_SELF_SIGNED_CERT = "entityauth/msl.pem";
    /** X.509 certificate chain. */
    private static final String X509_CHAIN_JSON = "entityauth/chain.json";
    /** X.509 root certificate */
    private static final String X509_ROOT_FN = "entityauth/root.pem";
    
    /** X.509 ESN. */
    public static final String X509_ESN;
    /** X509Cert. */
    public static final X509Certificate X509_CERT;
    /** Private key. */
    public static final PrivateKey X509_PRIVKEY;
    /** X.509 certificate chain authentication data*/
    public static final JSONObject X509_CHAIN_JO;
    /** X.509 root certificate */
    public static final X509Certificate X509_ROOT;
    
    static {
        final ClassLoader loader = X509AuthenticationDataTest.class.getClassLoader();
        final CertificateFactory factory;
        try {
            final URL certUrl = loader.getResource(X509_SELF_SIGNED_CERT);
            final InputStream certInputStream = certUrl.openStream();
            factory = CertificateFactory.getInstance("X.509");
            X509_CERT = (X509Certificate)factory.generateCertificate(certInputStream);
            X509_ESN = X509_CERT.getSubjectX500Principal().getName();
        } catch (final Exception e) {
            throw new MslInternalException("Hard-coded X.509 self-signed certificate failure.", e);
        }
        
        try {
            final URL keyUrl = loader.getResource(X509_PRIVATE_KEY);
            final InputStream keyInputStream = keyUrl.openStream();
            final ByteArrayOutputStream key = new ByteArrayOutputStream();
            do {
                final byte[] data = new byte[4096];
                final int bytesRead = keyInputStream.read(data);
                if (bytesRead == -1) break;
                key.write(data, 0, bytesRead);
            } while (true);
            keyInputStream.close();
            
            final KeyFactory rsaFactory = KeyFactory.getInstance("RSA");
            final KeySpec keySpec = new PKCS8EncodedKeySpec(key.toByteArray());
            X509_PRIVKEY = rsaFactory.generatePrivate(keySpec);
        } catch (final Exception e) {
            throw new MslInternalException("Hard-coded X.509 private key failure.", e);
        }
        
        try {
        	X509_CHAIN_JO = new JSONObject(readFile(X509_CHAIN_JSON));
        } catch (final Exception e) {
            throw new MslInternalException("Hard-coded X.509 cert chain read failure.", e);
        }

        try {
            final URL certUrl = loader.getResource(X509_ROOT_FN);
            final InputStream certInputStream = certUrl.openStream();
            X509_ROOT = (X509Certificate)factory.generateCertificate(certInputStream);
        } catch (final Exception e) {
            throw new MslInternalException("Hard-coded X.509 root cert read failure.", e);
        }

    }
    
    /**
     * Create a new test X.509 authentication factory.
     */
    public MockX509AuthenticationFactory() {
        super(EntityAuthenticationScheme.X509);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, org.json.JSONObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final JSONObject entityAuthJO) throws MslCryptoException, MslEncodingException {
        return new X509AuthenticationData(entityAuthJO);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.X509AuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof X509AuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final X509AuthenticationData xad = (X509AuthenticationData)authdata;
        
        // Try to return the test crypto context.
        final String identity = xad.getIdentity();
        if (X509_CERT.getSubjectX500Principal().getName().equals(identity))
            return new RsaCryptoContext(ctx, identity, X509_PRIVKEY, X509_CERT.getPublicKey(), Mode.SIGN_VERIFY);

        // Certificate verification failed.
        throw new MslEntityAuthException(MslError.X509CERT_VERIFICATION_FAILED, xad.getX509Cert().toString()).setEntity(xad);
    }
    
    private static String readFile(String filename) throws IOException {
    	InputStream is = X509AuthenticationDataTest.class.getClassLoader().getResourceAsStream(filename);
        Scanner scanner = new Scanner(is);
        String fileContents = scanner.useDelimiter("\\A").next();
        scanner.close();
        return fileContents;
    }
    

}
