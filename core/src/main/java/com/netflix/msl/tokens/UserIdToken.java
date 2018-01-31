/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;
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
 *   "tokendata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the user ID token data (usertokendata)</li>
 * <li>{@code signature} is the verification data of the user ID token data</li>
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
 *   "userdata" : "binary"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code mtserialnumber} is the master token serial number</li>
 * <li>{@code serialnumber} is the user ID token serial number</li>
 * <li>{@code userdata} is the encrypted user data (userdata)</li>
 * </ul></p>
 * 
 * <p>The decrypted user data is represented as
 * {@code
 * userdata = {
 *   "#mandatory" : [ "identity" ],
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
public class UserIdToken implements MslEncodable {
    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    /** Key token data. */
    private static final String KEY_TOKENDATA = "tokendata";
    /** Key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // tokendata
    /** Key renewal window timestamp. */
    private static final String KEY_RENEWAL_WINDOW = "renewalwindow";
    /** Key expiration timestamp. */
    private static final String KEY_EXPIRATION = "expiration";
    /** Key master token serial number. */
    private static final String KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** Key user ID token serial number. */
    private static final String KEY_SERIAL_NUMBER = "serialnumber";
    /** Key token user data. */
    private static final String KEY_USERDATA = "userdata";
    
    // userdata
    /** Key issuer data. */
    private static final String KEY_ISSUER_DATA = "issuerdata";
    /** Key identity. */
    private static final String KEY_IDENTITY = "identity";

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
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    public UserIdToken(final MslContext ctx, final Date renewalWindow, final Date expiration, final MasterToken masterToken, final long serialNumber, final MslObject issuerData, final MslUser user) throws MslEncodingException, MslCryptoException {
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
        this.mtSerialNumber = masterToken.getSerialNumber();
        this.serialNumber = serialNumber;
        this.issuerdata = issuerData;
        this.user = user;
        
        // Construct the user data.
        final MslEncoderFactory encoder = this.ctx.getMslEncoderFactory();
        this.userdata = encoder.createObject();
        if (this.issuerdata != null)
            this.userdata.put(KEY_ISSUER_DATA, this.issuerdata);
        this.userdata.put(KEY_IDENTITY, user.getEncoded());

        this.tokendataBytes = null;
        this.signatureBytes = null;
        this.verified = true;
    }
    
    /**
     * Create a new user ID token from the provided MSL object. The associated
     * master token must be provided to verify the user ID token.
     * 
     * @param ctx MSL context.
     * @param userIdTokenMo user ID token MSL object.
     * @param masterToken the master token.
     * @throws MslEncodingException if there is an error parsing the data, the
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
    public UserIdToken(final MslContext ctx, final MslObject userIdTokenMo, final MasterToken masterToken) throws MslEncodingException, MslCryptoException, MslException {
        this.ctx = ctx;
        
        // Grab the crypto context and encoder.
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        
        // Verify the encoding.
        try {
            tokendataBytes = userIdTokenMo.getBytes(KEY_TOKENDATA);
            if (tokendataBytes.length == 0)
                throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_MISSING, "useridtoken " + userIdTokenMo).setMasterToken(masterToken);
            signatureBytes = userIdTokenMo.getBytes(KEY_SIGNATURE);
            verified = cryptoContext.verify(tokendataBytes, signatureBytes, encoder);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "useridtoken " + userIdTokenMo, e).setMasterToken(masterToken);
        }
        
        // Pull the token data.
        final byte[] plaintext;
        try {
            final MslObject tokendata = encoder.parseObject(tokendataBytes);
            renewalWindow = tokendata.getLong(KEY_RENEWAL_WINDOW);
            expiration = tokendata.getLong(KEY_EXPIRATION);
            if (expiration < renewalWindow)
                throw new MslException(MslError.USERIDTOKEN_EXPIRES_BEFORE_RENEWAL, "usertokendata " + tokendata).setMasterToken(masterToken);
            mtSerialNumber = tokendata.getLong(KEY_MASTER_TOKEN_SERIAL_NUMBER);
            if (mtSerialNumber < 0 || mtSerialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokendata).setMasterToken(masterToken);
            serialNumber = tokendata.getLong(KEY_SERIAL_NUMBER);
            if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokendata).setMasterToken(masterToken);
            final byte[] ciphertext = tokendata.getBytes(KEY_USERDATA);
            if (ciphertext.length == 0)
                throw new MslException(MslError.USERIDTOKEN_USERDATA_MISSING).setMasterToken(masterToken);
            plaintext = (verified) ? cryptoContext.decrypt(ciphertext, encoder) : null;
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR, "usertokendata " + Base64.encode(tokendataBytes), e).setMasterToken(masterToken);
        } catch (final MslCryptoException e) {
            e.setMasterToken(masterToken);
            throw e;
        }
        
        // Pull the user data.
        if (plaintext != null) {
            try {
                userdata = encoder.parseObject(plaintext);
                issuerdata = (userdata.has(KEY_ISSUER_DATA)) ? userdata.getMslObject(KEY_ISSUER_DATA, encoder) : null;
                final String identity = userdata.getString(KEY_IDENTITY);
                if (identity == null || identity.length() == 0)
                    throw new MslException(MslError.USERIDTOKEN_IDENTITY_INVALID, "userdata " + userdata).setMasterToken(masterToken);
                final TokenFactory factory = ctx.getTokenFactory();
                user = factory.createUser(ctx, identity);
                if (user == null)
                    throw new MslInternalException("TokenFactory.createUser() returned null in violation of the interface contract.");
            } catch (final MslEncoderException e) {
                throw new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR, "userdata " + Base64.encode(plaintext), e).setMasterToken(masterToken);
            }
        } else {
            userdata = null;
            issuerdata = null;
            user = null;
        }
        
        // Verify serial numbers.
        if (masterToken == null || this.mtSerialNumber != masterToken.getSerialNumber())
            throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + this.mtSerialNumber + "; mt " + masterToken).setMasterToken(masterToken);
    }
    
    /**
     * @return true if the decrypted content is available. (Implies verified.)
     */
    public boolean isDecrypted() {
        return user != null;
    }
    
    /**
     * @return true if the token has been verified.
     */
    public boolean isVerified() {
        return verified;
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
     * @param now the time to compare against. May be {@code null}.
     * @return true if the renewal window has been entered.
     */
    public boolean isRenewable(final Date now) {
        if (now != null)
            return renewalWindow * MILLISECONDS_PER_SECOND <= now.getTime();
        if (isVerified())
            return renewalWindow * MILLISECONDS_PER_SECOND <= ctx.getTime();
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
        if (now != null)
            return expiration * MILLISECONDS_PER_SECOND <= now.getTime();
        if (isVerified())
            return expiration * MILLISECONDS_PER_SECOND <= ctx.getTime();
        return false;
    }
    
    /**
     * @return the user ID token issuer data or null if there is none or it is
     *         unknown (user data could not be decrypted).
     */
    public MslObject getIssuerData() {
        return issuerdata;
    }

    /**
     * @return the MSL user, or null if unknown (user data could not be
     *         decrypted).
     */
    public MslUser getUser() {
        return user;
    }
    
    /**
     * @return the user ID token serial number.
     */
    public long getSerialNumber() {
        return serialNumber;
    }
    
    /**
     * Return the serial number of the master token this user ID token is bound
     * to.
     * 
     * @return the master token serial number.
     */
    public long getMasterTokenSerialNumber() {
        return mtSerialNumber;
    }
    
    /**
     * @param masterToken master token. May be null.
     * @return true if this token is bound to the provided master token.
     */
    public boolean isBoundTo(final MasterToken masterToken) {
        return masterToken != null && masterToken.getSerialNumber() == mtSerialNumber;
    }
    
    /** MSL context. */
    private final MslContext ctx;

    /** User ID token renewal window in seconds since the epoch. */
    private final long renewalWindow;
    /** User ID token expiration in seconds since the epoch. */
    private final long expiration;
    /** Master token serial number. */
    private final long mtSerialNumber;
    /** Serial number. */
    private final long serialNumber;
    /** User data. */
    private final MslObject userdata;

    /** Issuer data. */
    private final MslObject issuerdata;
    /** MSL user. */
    private final MslUser user;
    
    /** Token data bytes. */
    private final byte[] tokendataBytes;
    /** Signature bytes. */
    private final byte[] signatureBytes;
    
    /** Token is verified. */
    private final boolean verified;
    
    /** Cached encodings. */
    private final Map<MslEncoderFormat,byte[]> encodings = new HashMap<MslEncoderFormat,byte[]>();
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        // Return any cached encoding.
        if (encodings.containsKey(format))
            return encodings.get(format);

        // If we parsed this token (i.e. did not create it from scratch) then
        // we should not re-encrypt or re-sign as there is no guarantee out MSL
        // crypto context is capable of encrypting and signing with the same
        // keys, even if it is capable of decrypting and verifying.
        final byte[] data, signature;
        if (tokendataBytes != null || signatureBytes != null) {
            data = tokendataBytes;
            signature = signatureBytes;
        }
        //
        // Otherwise create the token data and signature.
        else {
            // Grab the MSL token crypto context.
            final ICryptoContext cryptoContext;
            try {
                cryptoContext = ctx.getMslCryptoContext();
            } catch (final MslCryptoException e) {
                throw new MslEncoderException("Error creating the MSL crypto context.", e);
            }
        
            // Encrypt the user data.
            final byte[] plaintext = encoder.encodeObject(userdata, format);
            final byte[] ciphertext;
            try {
                ciphertext = cryptoContext.encrypt(plaintext, encoder, format);
            } catch (final MslCryptoException e) {
                throw new MslEncoderException("Error encrypting the user data.", e);
            }
    
            // Construct the token data.
            final MslObject tokendata = encoder.createObject();
            tokendata.put(KEY_RENEWAL_WINDOW, this.renewalWindow);
            tokendata.put(KEY_EXPIRATION, this.expiration);
            tokendata.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, this.mtSerialNumber);
            tokendata.put(KEY_SERIAL_NUMBER, this.serialNumber);
            tokendata.put(KEY_USERDATA, ciphertext);
    
            // Sign the token data.
            data = encoder.encodeObject(tokendata, format);
            try {
                signature = cryptoContext.sign(data, encoder, format);
            } catch (final MslCryptoException e) {
                throw new MslEncoderException("Error signing the token data.", e);
            }
        }
        
        // Encode the token.
        final MslObject token = encoder.createObject();
        token.put(KEY_TOKENDATA, data);
        token.put(KEY_SIGNATURE, signature);
        final byte[] encoding = encoder.encodeObject(token, format);

        // Cache and return the encoding.
        encodings.put(format, encoding);
        return encoding;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();

        final MslObject tokendataMo = encoder.createObject();
        tokendataMo.put(KEY_RENEWAL_WINDOW, renewalWindow);
        tokendataMo.put(KEY_EXPIRATION, expiration);
        tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, mtSerialNumber);
        tokendataMo.put(KEY_SERIAL_NUMBER, serialNumber);
        tokendataMo.put(KEY_USERDATA, "(redacted)");

        final MslObject mslObj = encoder.createObject();
        mslObj.put(KEY_TOKENDATA, tokendataMo);
        mslObj.put(KEY_SIGNATURE, (signatureBytes != null) ? signatureBytes : "(null)");
        return mslObj.toString();
    }

    /**
     * <p>Returns true if the other object is a user ID token with the same
     * serial number bound to the same master token.</p>
     * 
     * <p>This function is designed for use with sets and maps to guarantee
     * uniqueness of individual user ID tokens.</p>
     * 
     * @param obj the reference object with which to compare.
     * @return true if the other object is a user ID token with the same serial
     *         number bound to the same master token.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (obj instanceof UserIdToken) {
            final UserIdToken that = (UserIdToken)obj;
            return this.serialNumber == that.serialNumber &&
                this.mtSerialNumber == that.mtSerialNumber;
        }
        return false;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return (String.valueOf(serialNumber) + ":" + String.valueOf(mtSerialNumber)).hashCode();
    }
}
