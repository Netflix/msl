/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Test pre-shared keys profile authentication factory.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockPresharedProfileAuthenticationFactory extends EntityAuthenticationFactory {
    /** PSK ESN. */
    public static final String PSK_ESN = "PSK-ESN";
    /** PSK Kpe. */
    private static final byte[] PSK_KPE = Base64.decode("kzWYEtKSsPI8dOW5YyoILQ==");
    /** PSK Kph. */
    private static final byte[] PSK_KPH = Base64.decode("VhxNUK7bYIcCV4wLE2YK90do1X3XqhPeMwwllmNh8Jw=");
    
    /** PSK ESN 2. */
    public static final String PSK_ESN2 = "PSK-ESN2";
    /** PSK Kpe 2. */
    private static final byte[] PSK_KPE2 = Base64.decode("lzWYEtKSsPI8dOW5YyoILQ==");
    /** PSK Kph 2. */
    private static final byte[] PSK_KPH2 = Base64.decode("WhxNUK7bYIcCV4wLE2YK90do1X3XqhPeMwwllmNh8Jw=");
    
    /** Profile. */
    public static final String PROFILE = "PROFILE";

    /** Kpe/Kph/Kpw #1. */
    public static final SecretKey KPE, KPH, KPW;
    /** Kpe/Kph/Kpw #2. */
    public static final SecretKey KPE2, KPH2, KPW2;

    static {
        KPE = new SecretKeySpec(PSK_KPE, JcaAlgorithm.AES);
        KPH = new SecretKeySpec(PSK_KPH, JcaAlgorithm.HMAC_SHA256);
        KPW = new SecretKeySpec(MslTestUtils.deriveWrappingKey(PSK_KPE, PSK_KPH), JcaAlgorithm.AESKW);

        KPE2 = new SecretKeySpec(PSK_KPE2, JcaAlgorithm.AES);
        KPH2 = new SecretKeySpec(PSK_KPH2, JcaAlgorithm.HMAC_SHA256);
        KPW2 = new SecretKeySpec(MslTestUtils.deriveWrappingKey(PSK_KPE2, PSK_KPH2), JcaAlgorithm.AESKW);
    }

    /**
     * Create a new test pre-shared keys profile authentication factory.
     */
    public MockPresharedProfileAuthenticationFactory() {
        super(EntityAuthenticationScheme.PSK_PROFILE);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException {
        return new PresharedProfileAuthenticationData(entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.PresharedAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof PresharedProfileAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final PresharedProfileAuthenticationData ppad = (PresharedProfileAuthenticationData)authdata;
        
        // Try to return the test crypto context.
        final String pskId = ppad.getPresharedKeysId();
        final String identity = ppad.getIdentity();
        if (PSK_ESN.equals(pskId))
            return new SymmetricCryptoContext(ctx, identity, KPE, KPH, KPW);
        if (PSK_ESN2.equals(pskId))
            return new SymmetricCryptoContext(ctx, identity, KPE2, KPH2, KPW2);
        
        // Entity not found.
        throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "psk profile " + pskId).setEntityAuthenticationData(ppad);
    }
}
