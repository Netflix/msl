/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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

import javax.xml.bind.DatatypeConverter;

import lombok.EqualsAndHashCode;
import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;

/**
 * <p>Master token protected entity authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "mastertoken", "authdata", "signature" ],
 *   "mastertoken" : mastertoken,
 *   "authdata" : "base64",
 *   "signature" : "base64",
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token used to protect the encapsulated authentication data</li>
 * <li>{@code authdata} is the Base64-encoded ciphertext envelope containing the encapsulated authentication data</li>
 * <li>{@code signature} is the Base64-encoded signature envelope verifying the encapsulated authentication data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@EqualsAndHashCode(of={"masterToken", "authdata"}, callSuper = true, doNotUseGetters = true)
public class MasterTokenProtectedAuthenticationData extends EntityAuthenticationData {
    /** JSON key master token. */
    protected static final String KEY_MASTER_TOKEN = "mastertoken";

    /** JSON key authentication data. */
    protected static final String KEY_AUTHENTICATION_DATA = "authdata";

    /** JSON key signature. */
    protected static final String KEY_SIGNATURE = "signature";

    /** Master token. */
    private final MasterToken masterToken;

    /** Entity authentication data. */
    private final EntityAuthenticationData authdata;

    /** Encrypted entity authentication data. */
    private final byte[] ciphertext;

    /** Ciphertext signature. */
    private final byte[] signature;

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
        
        this.masterToken = masterToken;
        this.authdata = authdata;
        
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
        
        // Encrypt and sign the authentication data.
        final byte[] plaintext = authdata.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET);
        this.ciphertext = cryptoContext.encrypt(plaintext);
        this.signature = cryptoContext.sign(this.ciphertext);
    }
    
    /**
     * <p>Construct a new master token protected entity authentication data
     * instance from the provided JSON object.</p>
     * 
     * @param ctx MSL context.
     * @param authdataJO the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         representation.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the encapsulated authentication data.
     * @throws MslEntityAuthException if the encapsulated authentication data
     *         or signature are invalid, if the master token is invalid, or if
     *         the master token crypto context cannot be found in the MSL store
     *         and cannot be created.
     */
    public MasterTokenProtectedAuthenticationData(final MslContext ctx, final JSONObject authdataJO) throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        super(EntityAuthenticationScheme.MT_PROTECTED);
        
        // Extract authentication data fields.
        try {
            try {
                this.masterToken = new MasterToken(ctx, authdataJO.getJSONObject(KEY_MASTER_TOKEN));
            } catch (final MslException e) {
                throw new MslEntityAuthException(MslError.ENTITYAUTH_MASTERTOKEN_INVALID, "master token protected authdata " + authdataJO.toString(), e);
            }
            try {
                this.ciphertext = DatatypeConverter.parseBase64Binary(authdataJO.getString(KEY_AUTHENTICATION_DATA));
            } catch (final IllegalArgumentException e) {
                throw new MslEntityAuthException(MslError.ENTITYAUTH_CIPHERTEXT_INVALID, "master token protected authdata " + authdataJO.toString(), e);
            }
            try {
                this.signature = DatatypeConverter.parseBase64Binary(authdataJO.getString(KEY_SIGNATURE));
            } catch (final IllegalArgumentException e) {
                throw new MslEntityAuthException(MslError.ENTITYAUTH_SIGNATURE_INVALID, "master token protected authdata " + authdataJO.toString(), e);
            }
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "master token protected authdata " + authdataJO.toString(), e);
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
            if (!cryptoContext.verify(this.ciphertext, this.signature))
                throw new MslEntityAuthException(MslError.ENTITYAUTH_VERIFICATION_FAILED, "master token protected authdata " + authdataJO.toString());
            final byte[] plaintext = cryptoContext.decrypt(this.ciphertext);
            final JSONObject internalAuthdataJO = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
            this.authdata = EntityAuthenticationData.create(ctx, internalAuthdataJO);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "master token protected authdata " + authdataJO.toString(), e);
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
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData()
     */
    @Override
    public JSONObject getAuthData() throws MslEncodingException {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_MASTER_TOKEN, masterToken);
            jsonObj.put(KEY_AUTHENTICATION_DATA, DatatypeConverter.printBase64Binary(ciphertext));
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return new JSONObject(jsonObj.toString());
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "master token protected authdata", e);
        }
    }

}
