/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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

import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;

/**
 * <p>Master token protected entity authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "mastertoken", "authdata", "signature" ],
 *   "mastertoken" : mastertoken,
 *   "authdata" : "binary",
 *   "signature" : "binary",
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token used to protect the encapsulated authentication data</li>
 * <li>{@code authdata} is the ciphertext envelope containing the encapsulated authentication data</li>
 * <li>{@code signature} is the signature envelope verifying the encapsulated authentication data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MasterTokenProtectedAuthenticationData extends EntityAuthenticationData {
    /** Key master token. */
    protected static final String KEY_MASTER_TOKEN = "mastertoken";
    /** Key authentication data. */
    protected static final String KEY_AUTHENTICATION_DATA = "authdata";
    /** Key signature. */
    protected static final String KEY_SIGNATURE = "signature";
    
    /**
     * <p>Construct a new master token protected entity authentication data
     * instance using the provided master token and actual entity
     * authentication data.</p>
     * 
     * @param ctx MSL context.
     * @param masterToken the master token.
     * @param authdata encapsulated authentication data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the encapsulated authentication data.
     * @throws MslEntityAuthException if the master token crypto context cannot
     *         be found in the MSL store and cannot be created.
     */
    public MasterTokenProtectedAuthenticationData(final MslContext ctx, final MasterToken masterToken, final EntityAuthenticationData authdata) throws MslCryptoException, MslEntityAuthException {
        super(EntityAuthenticationScheme.MT_PROTECTED);
        this.ctx = ctx;
        this.masterToken = masterToken;
        this.authdata = authdata;
    }
    
    /**
     * <p>Construct a new master token protected entity authentication data
     * instance from the provided MSL object.</p>
     * 
     * @param ctx MSL context.
     * @param authdataMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the MSL
     *         representation.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the encapsulated authentication data.
     * @throws MslEntityAuthException if the encapsulated authentication data
     *         or signature are invalid, if the master token is invalid, or if
     *         the master token crypto context cannot be found in the MSL store
     *         and cannot be created.
     */
    MasterTokenProtectedAuthenticationData(final MslContext ctx, final MslObject authdataMo) throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        super(EntityAuthenticationScheme.MT_PROTECTED);
        this.ctx = ctx;
        
        // Extract authentication data fields.
        final byte[] ciphertext, signature;
        try {
            ciphertext = authdataMo.getBytes(KEY_AUTHENTICATION_DATA);
            signature = authdataMo.getBytes(KEY_SIGNATURE);
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            try {
                this.masterToken = new MasterToken(ctx, authdataMo.getMslObject(KEY_MASTER_TOKEN, encoder));
            } catch (final MslException e) {
                throw new MslEntityAuthException(MslError.ENTITYAUTH_MASTERTOKEN_INVALID, "master token protected authdata " + authdataMo, e);
            }
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "master token protected authdata " + authdataMo, e);
        }
        
        // Grab master token crypto context.
        final ICryptoContext cryptoContext;
        try {
            final ICryptoContext cachedCryptoContext = ctx.getMslStore().getCryptoContext(masterToken);
            if (cachedCryptoContext != null)
                cryptoContext = cachedCryptoContext;
            else
                cryptoContext = new SessionCryptoContext(ctx, masterToken);
        } catch (final MslMasterTokenException e) {
            throw new MslEntityAuthException(MslError.ENTITYAUTH_MASTERTOKEN_NOT_DECRYPTED, e);
        }
        
        // Verify and decrypt the authentication data.
        try {
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            if (!cryptoContext.verify(ciphertext, signature, encoder))
                throw new MslEntityAuthException(MslError.ENTITYAUTH_VERIFICATION_FAILED, "master token protected authdata " + authdataMo);
            final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
            final MslObject internalAuthdataMo = encoder.parseObject(plaintext);
            this.authdata = EntityAuthenticationData.create(ctx, internalAuthdataMo);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "master token protected authdata " + authdataMo, e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getIdentity()
     */
    @Override
    public String getIdentity() throws MslCryptoException {
        return authdata.getIdentity();
    }
    
    /**
     * Return the encapsulated entity authentication data.
     * 
     * @return the encapsulated entity authentication data.
     */
    public EntityAuthenticationData getEncapsulatedAuthdata() {
        return authdata;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        // Return any cached object.
        if (objects.containsKey(format))
            return objects.get(format);
        
        // Grab master token crypto context.
        final ICryptoContext cryptoContext;
        try {
            final ICryptoContext cachedCryptoContext = ctx.getMslStore().getCryptoContext(masterToken);
            if (cachedCryptoContext != null)
                cryptoContext = cachedCryptoContext;
            else
                cryptoContext = new SessionCryptoContext(ctx, masterToken);
        } catch (final MslMasterTokenException e) {
            throw new MslEncoderException("Master token is not trusted; cannot create session crypto context.", e);
        }
        
        // Encrypt and sign the authentication data.
        final byte[] plaintext = authdata.toMslEncoding(encoder, format);
        final byte[] ciphertext, signature;
        try {
            ciphertext = cryptoContext.encrypt(plaintext, encoder, format);
            signature = cryptoContext.sign(ciphertext, encoder, format);
        } catch (final MslCryptoException e) {
            throw new MslEncoderException("Error encrypting and signing the authentication data.", e);
        }
        
        // Return the authentication data.
        final MslObject mo = encoder.createObject();
        mo.put(KEY_MASTER_TOKEN, masterToken);
        mo.put(KEY_AUTHENTICATION_DATA, ciphertext);
        mo.put(KEY_SIGNATURE, signature);
        
        // Cache and return the object.
        final byte[] encoded = encoder.encodeObject(mo, format);
        final MslObject decoded = encoder.parseObject(encoded);
        objects.put(format, decoded);
        return decoded;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof MasterTokenProtectedAuthenticationData)) return false;
        final MasterTokenProtectedAuthenticationData that = (MasterTokenProtectedAuthenticationData)obj;
        return super.equals(obj) &&
            this.masterToken.equals(that.masterToken) &&
            this.authdata.equals(that.authdata);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode() ^
            masterToken.hashCode() ^
            authdata.hashCode();
    }
    
    /** MSL context. */
    private final MslContext ctx;

    /** Master token. */
    private final MasterToken masterToken;
    /** Entity authentication data. */
    private final EntityAuthenticationData authdata;
    
    /** Cached encoded objects. */
    private final Map<MslEncoderFormat,MslObject> objects = new HashMap<MslEncoderFormat,MslObject>();
}
