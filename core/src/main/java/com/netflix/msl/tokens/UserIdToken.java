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
package com.netflix.msl.tokens;

import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.util.MslContext;

/**
 * <p>A user ID token provides proof of user identity. While there can be
 * multiple versions of a user ID token, this class should encapsulate support
 * for all of those versions.</p>
 * 
 * <p>User ID tokens are bound to a specific master token by the master token's
 * serial number.</p>
 * 
 * <p>The renewal window indicates the time after which the user ID token will
 * be renewed if requested by the entity. The expiration is the time after
 * which the user ID token will be renewed no matter what.</p>
 * 
 * <p>User ID tokens are represented as
 * {@code
 * useridtoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the Base64-encoded user ID token data (usertokendata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the user ID token data</li>
 * </ul>
 * 
 * <p>The token data is represented as
 * {@code
 * usertokendata = {
 *   "#mandatory" : [ "renewalwindow", "expiration", "mtserialnumber", "serialnumber", "userdata" ],
 *   "renewalwindow" : "int64(0,-)",
 *   "expiration" : "int64(0,-)",
 *   "mtserialnumber" : "int64(0,2^53^)",
 *   "serialnumber" : "int64(0,2^53^)",
 *   "userdata" : "base64"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code mtserialnumber} is the master token serial number</li>
 * <li>{@code serialnumber} is the user ID token serial number</li>
 * <li>{@code userdata} is the Base64-encoded encrypted user data (userdata)</li>
 * </ul></p>
 * 
 * <p>The decrypted user data is represented as
 * {@code
 * userdata = {
 *   "#mandatory" : [ "user" ],
 *   "issuerdata" : object,
 *   "identity" : "string"
 * }}
 * where:
 * <ul>
 * <li>{@code issuerdata} is the user ID token issuer data</li>
 * <li>{@code identity} is the encoded user identity data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@EqualsAndHashCode(of = {"serialNumber", "masterTokenSerialNumber"})
public class UserIdToken implements JSONString {
    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    /** JSON key token data. */
    private static final String KEY_TOKENDATA = "tokendata";
    /** JSON key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // tokendata
    /** JSON key renewal window timestamp. */
    private static final String KEY_RENEWAL_WINDOW = "renewalwindow";
    /** JSON key expiration timestamp. */
    private static final String KEY_EXPIRATION = "expiration";
    /** JSON key master token serial number. */
    private static final String KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** JSON key user ID token serial number. */
    private static final String KEY_SERIAL_NUMBER = "serialnumber";
    /** JSON key token user data. */
    private static final String KEY_USERDATA = "userdata";
    
    // userdata
    /** JSON key issuer data. */
    private static final String KEY_ISSUER_DATA = "issuerdata";
    /** JSON key identity. */
    private static final String KEY_IDENTITY = "identity";

    /** MSL context. */
    private final MslContext ctx;

    /** Token data. */
    private final byte[] tokendata;
    /** Encrypted token data signature. */

    private final byte[] signature;

    /** User ID token renewal window in seconds since the epoch. */
    private final long renewalWindow;

    /** User ID token expiration in seconds since the epoch. */
    private final long expiration;

    /**
     * Serial number of the master token this user ID token is bound to.
     */
    @Getter
    private final long masterTokenSerialNumber;

    /** User ID Serial number. */
    @Getter
    private final long serialNumber;

    /** User data. */
    private final byte[] userdata;

    /**
     * Issuer data or null if there is none or it is unknown (user data could not be decrypted).
     */
    @Getter
    private final JSONObject issuerData;

    /**
     * MSL user or null if unknown (user data could not be decrypted).
     */
    @Getter
    private final MslUser user;

    /** Token has been verified. */
    @Getter
    private final boolean verified;

    /**
     * Create a new user ID token with the specified user.
     * 
     * @param ctx MSL context.
     * @param renewalWindow the renewal window.
     * @param expiration the expiration.
     * @param masterToken the master token.
     * @param serialNumber the user ID token serial number.
     * @param issuerData the issuer data. May be null.
     * @param user the MSL user.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    public UserIdToken(final MslContext ctx, final Date renewalWindow, final Date expiration, final MasterToken masterToken, final long serialNumber, final JSONObject issuerData, final MslUser user) throws MslEncodingException, MslCryptoException {
        // The expiration must appear after the renewal window.
        if (expiration.before(renewalWindow))
            throw new MslInternalException("Cannot construct a user ID token that expires before its renewal window opens.");
        // A master token must be provided.
        if (masterToken == null)
            throw new MslInternalException("Cannot construct a user ID token without a master token.");
        // The serial number must be within range.
        if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Serial number " + serialNumber + " is outside the valid range.");
        
        this.ctx = ctx;
        this.renewalWindow = renewalWindow.getTime() / MILLISECONDS_PER_SECOND;
        this.expiration = expiration.getTime() / MILLISECONDS_PER_SECOND;
        this.masterTokenSerialNumber = masterToken.getSerialNumber();
        this.serialNumber = serialNumber;
        this.issuerData = issuerData;
        this.user = user;
        
        // Construct the user data.
        final JSONObject userData = new JSONObject();
        try {
            if (this.issuerData != null)
                userData.put(KEY_ISSUER_DATA, this.issuerData);
            userData.put(KEY_IDENTITY, user.getEncoded());
            this.userdata = userData.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "userdata", e);
        }
        
        try {
            // Encrypt the user data.
            final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
            final byte[] ciphertext = cryptoContext.encrypt(this.userdata);
        
            // Construct the token data.
            try {
                final JSONObject tokenDataJO = new JSONObject();
                tokenDataJO.put(KEY_RENEWAL_WINDOW, this.renewalWindow);
                tokenDataJO.put(KEY_EXPIRATION, this.expiration);
                tokenDataJO.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, this.masterTokenSerialNumber);
                tokenDataJO.put(KEY_SERIAL_NUMBER, this.serialNumber);
                tokenDataJO.put(KEY_USERDATA, DatatypeConverter.printBase64Binary(ciphertext));
                this.tokendata = tokenDataJO.toString().getBytes(MslConstants.DEFAULT_CHARSET);
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "usertokendata", e).setEntity(masterToken);
            }
        
            // Sign the token data.
            this.signature = cryptoContext.sign(this.tokendata);
            this.verified = true;
        } catch (final MslCryptoException e) {
            e.setEntity(masterToken);
            throw e;
        }
    }
    
    /**
     * Create a new user ID token from the provided JSON object. The associated
     * master token must be provided to verify the user ID token.
     * 
     * @param ctx MSL context.
     * @param userIdTokenJO user ID token JSON object.
     * @param masterToken the master token.
     * @throws MslEncodingException if there is an error parsing the JSON, the
     *         token data is missing or invalid, or the signature is invalid.
     * @throws MslCryptoException if there is an error verifying the token
     *         data.
     * @throws MslException if the user ID token master token serial number
     *         does not match the master token serial number, or the expiration
     *         timestamp occurs before the renewal window, or the user data is
     *         missing or invalid, or the user ID token master token serial
     *         number is out of range, or the user ID token serial number is
     *         out of range.
     */
    public UserIdToken(final MslContext ctx, final JSONObject userIdTokenJO, final MasterToken masterToken) throws MslEncodingException, MslCryptoException, MslException {
        this.ctx = ctx;
        
        // Grab the crypto context.
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Verify the JSON representation.
        try {
            try {
                tokendata = DatatypeConverter.parseBase64Binary(userIdTokenJO.getString(KEY_TOKENDATA));
            } catch (final IllegalArgumentException e) {
                throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_INVALID, "useridtoken " + userIdTokenJO.toString(), e).setEntity(masterToken);
            }
            if (tokendata == null || tokendata.length == 0)
                throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_MISSING, "useridtoken " + userIdTokenJO.toString()).setEntity(masterToken);
            try {
                signature = DatatypeConverter.parseBase64Binary(userIdTokenJO.getString(KEY_SIGNATURE));
            } catch (final IllegalArgumentException e) {
                throw new MslEncodingException(MslError.USERIDTOKEN_SIGNATURE_INVALID, "useridtoken " + userIdTokenJO.toString(), e).setEntity(masterToken);
            }
            verified = cryptoContext.verify(tokendata, signature);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "useridtoken " + userIdTokenJO.toString(), e).setEntity(masterToken);
        }
        
        // Pull the token data.
        final String tokenDataJson = new String(tokendata, MslConstants.DEFAULT_CHARSET);
        try {
            final JSONObject tokenDataJO = new JSONObject(tokenDataJson);
            renewalWindow = tokenDataJO.getLong(KEY_RENEWAL_WINDOW);
            expiration = tokenDataJO.getLong(KEY_EXPIRATION);
            if (expiration < renewalWindow)
                throw new MslException(MslError.USERIDTOKEN_EXPIRES_BEFORE_RENEWAL, "usertokendata " + tokenDataJson).setEntity(masterToken);
            masterTokenSerialNumber = tokenDataJO.getLong(KEY_MASTER_TOKEN_SERIAL_NUMBER);
            if (masterTokenSerialNumber < 0 || masterTokenSerialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokenDataJson).setEntity(masterToken);
            serialNumber = tokenDataJO.getLong(KEY_SERIAL_NUMBER);
            if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokenDataJson).setEntity(masterToken);
            final byte[] ciphertext;
            try {
                ciphertext = DatatypeConverter.parseBase64Binary(tokenDataJO.getString(KEY_USERDATA));
            } catch (final IllegalArgumentException e) {
                throw new MslException(MslError.USERIDTOKEN_USERDATA_INVALID, tokenDataJO.getString(KEY_USERDATA)).setEntity(masterToken);
            }
            if (ciphertext == null || ciphertext.length == 0)
                throw new MslException(MslError.USERIDTOKEN_USERDATA_MISSING, tokenDataJO.getString(KEY_USERDATA)).setEntity(masterToken);
            userdata = (verified) ? cryptoContext.decrypt(ciphertext) : null;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR, "usertokendata " + tokenDataJson, e).setEntity(masterToken);
        } catch (final MslCryptoException e) {
            e.setEntity(masterToken);
            throw e;
        }
        
        // Pull the user data.
        if (userdata != null) {
            final String userDataJson = new String(userdata, MslConstants.DEFAULT_CHARSET);
            try {
                final JSONObject userDataJO = new JSONObject(userDataJson);
                issuerData = (userDataJO.has(KEY_ISSUER_DATA)) ? userDataJO.getJSONObject(KEY_ISSUER_DATA) : null;
                final String identity = userDataJO.getString(KEY_IDENTITY);
                if (identity == null || identity.length() == 0)
                    throw new MslException(MslError.USERIDTOKEN_IDENTITY_INVALID, "userdata " + userDataJson).setEntity(masterToken);
                final TokenFactory factory = ctx.getTokenFactory();
                user = factory.createUser(ctx, identity);
                if (user == null)
                    throw new MslInternalException("TokenFactory.createUser() returned null in violation of the interface contract.");
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR, "userdata " + userDataJson, e).setEntity(masterToken);
            }
        } else {
            issuerData = null;
            user = null;
        }
        
        // Verify serial numbers.
        if (masterToken == null || this.masterTokenSerialNumber != masterToken.getSerialNumber())
            throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + this.masterTokenSerialNumber + "; mt " + masterToken).setEntity(masterToken);
    }
    
    /**
     * @return true if the decrypted content is available. (Implies verified.)
     */
    public boolean isDecrypted() {
        return user != null;
    }

    /**
     * @return the start of the renewal window.
     */
    public Date getRenewalWindow() {
        return new Date(renewalWindow * MILLISECONDS_PER_SECOND);
    }
    
    /**
     * <p>Returns true if the user ID token renewal window has been entered.</p>
     *
     * <ul>
     * <li>If a time is provided the renewal window value will be compared
     * against the provided time.</li>
     * <li>If the user ID token was issued by the local entity the renewal
     * window value will be compared against the local entity time. We assume
     * its clock at the time of issuance is in sync with the clock now.</li>
     * <li>Otherwise the user ID token is considered renewable under the
     * assumption that the local time is not synchronized with the master token
     * issuing entity time.</li>
     * </ul>
     *
     * @param now the time to compare against.
     * @return true if the renewal window has been entered.
     */
    public boolean isRenewable(final Date now) {
        if (now != null) {
            return renewalWindow * MILLISECONDS_PER_SECOND <= now.getTime();
        }
        if (isVerified()) {
            return renewalWindow * MILLISECONDS_PER_SECOND <= ctx.getTime();
        }
        return true;
    }
    
    /**
     * @return the expiration.
     */
    public Date getExpiration() {
        return new Date(expiration * MILLISECONDS_PER_SECOND);
    }
    
    /**
     * <p>Returns true if the user ID token is expired.</p>
     *
     * <ul>
     * <li>If a time is provided the expiration value will be compared against
     * the provided time.</li>
     * <li>If the user ID token was issued by the local entity the expiration
     * value will be compared against the local entity time. We assume
     * its clock at the time of issuance is in sync with the clock now.</li>
     * <li>Otherwise the user ID token is considered not expired under the
     * assumption that the local time is not synchronized with the token-
     * issuing entity time.</li>
     * </ul>
     *
     * @param now the time to compare against.
     * @return true if expired.
     */
    public boolean isExpired(final Date now) {
        if (now != null) {
            return expiration * MILLISECONDS_PER_SECOND <= now.getTime();
        }
        if (isVerified()) {
            return expiration * MILLISECONDS_PER_SECOND <= ctx.getTime();
        }
        return false;
    }

    /**
     * @param masterToken master token. May be null.
     * @return true if this token is bound to the provided master token.
     */
    public boolean isBoundTo(final MasterToken masterToken) {
        return masterToken != null && masterToken.getSerialNumber() == masterTokenSerialNumber;
    }
    
    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public final String toJSONString() {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendata));
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        try {
            final JSONObject userdataJO;
            if (isDecrypted()) {
                userdataJO = new JSONObject();
                if (issuerData != null)
                    userdataJO.put(KEY_ISSUER_DATA, issuerData);
                userdataJO.put(KEY_IDENTITY, user);
            } else {
                userdataJO = null;
            }
            
            final JSONObject tokendataJO = new JSONObject();
            tokendataJO.put(KEY_RENEWAL_WINDOW, renewalWindow);
            tokendataJO.put(KEY_EXPIRATION, expiration);
            tokendataJO.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, masterTokenSerialNumber);
            tokendataJO.put(KEY_SERIAL_NUMBER, serialNumber);
            tokendataJO.put(KEY_USERDATA, userdataJO);
            
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_TOKENDATA, tokendataJO);
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }
}
