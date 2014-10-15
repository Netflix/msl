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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

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
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.util.MslContext;

/**
 * <p>The master token provides proof of remote entity identity. A MSL-specific
 * crypto context is used to encrypt the master token data and generate the
 * master token verification data. The remote entity cannot decrypt the master
 * token data or generate the master token verification data.</p> 
 * 
 * <p>The master token session keys will be used for MSL message encryption and
 * integrity protection. The use of these session keys implies the MSL message
 * identity as specified in the master token.</p>
 * 
 * <p>Master tokens also contain a sequence number identifying the issue number
 * of the token. This is a monotonically increasing number that is incremented
 * by one each time a master token is renewed.</p>
 * 
 * <p>When in possession of multiple master tokens, the token with the highest
 * sequence number should be considered the newest token. Since the sequence
 * number space is signed 53-bit numbers, if a sequence number is smaller by
 * more than 45-bits (e.g. the new sequence number is <= 128 and the old
 * sequence number is 2^53), it is considered the newest token.</p>
 * 
 * <p>The renewal window indicates the time after which the master token will
 * be renewed if requested by the entity. The expiration is the time after
 * which the master token will be renewed no matter what.</p>
 * 
 * <p>Master tokens also contain a serial number against which all other tokens
 * are bound. Changing the serial number when the master token is renewed
 * invalidates all of those tokens.</p>
 * 
 * <p>The issuer identity identifies the issuer of this master token, which may
 * be useful to services that accept the master token.</p>
 * 
 * <p>While there can be multiple versions of a master token, this class should
 * encapsulate support for all of those versions.</p>
 * 
 * <p>Master tokens are represented as
 * {@code
 * mastertoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the Base64-encoded master token data (mastertokendata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the master token data</li>
 * </ul></p>
 * 
 * <p>The token data is represented as
 * {@code
 * mastertokendata = {
 *   "#mandatory" : [ "renewalwindow", "expiration", "sequencenumber", "serialnumber", "sessiondata" ],
 *   "renewalwindow" : "int64(0,-)",
 *   "expiration" : "int64(0,-)",
 *   "sequencenumber" : "int64(0,2^53^)",
 *   "serialnumber" : "int64(0,2^53^)",
 *   "sessiondata" : "base64"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code sequencenumber} is the master token sequence number</li>
 * <li>{@code serialnumber} is the master token serial number</li>
 * <li>{@code sessiondata} is the Base64-encoded encrypted session data (sessiondata)</li>
 * </ul></p>
 * 
 * <p>The decrypted session data is represented as
 * {@code
 * sessiondata = {
 *   "#mandatory" : [ "identity", "encryptionkey", "hmackey" ],
 *   "issuerdata" : object,
 *   "identity" : "string",
 *   "encryptionkey" : "base64",
 *   "hmackey" : "base64"
 * }}
 * where:
 * <ul>
 * <li>{@code issuerdata} is the master token issuer data</li>
 * <li>{@code identity} is the identifier of the remote entity</li>
 * <li>{@code encryptionkey} is the Base64-encoded AES-128 encryption session key</li>
 * <li>{@code hmackey} is the Base64-encoded SHA-256 HMAC session key</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MasterToken implements JSONString {
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
    /** JSON key sequence number. */
    private static final String KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** JSON key serial number. */
    private static final String KEY_SERIAL_NUMBER = "serialnumber";
    /** JSON key session data. */
    private static final String KEY_SESSIONDATA = "sessiondata";
    
    // sessiondata
    /** JSON key issuer data. */
    private static final String KEY_ISSUER_DATA = "issuerdata";
    /** JSON key identity. */
    private static final String KEY_IDENTITY = "identity";
    /** JSON key symmetric encryption key. */
    private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
    /** JSON key symmetric HMAC key. */
    private static final String KEY_HMAC_KEY = "hmackey";
        
    /**
     * Create a new master token with the specified expiration, identity,
     * serial number, and encryption and HMAC keys.
     * 
     * @param ctx MSL context.
     * @param renewalWindow the renewal window.
     * @param expiration the expiration.
     * @param sequenceNumber the master token sequence number.
     * @param serialNumber the master token serial number.
     * @param issuerData the issuer data. May be null.
     * @param identity the singular identity this master token represents.
     * @param encryptionKey the session encryption key.
     * @param hmacKey the session HMAC key.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    public MasterToken(final MslContext ctx, final Date renewalWindow, final Date expiration, final long sequenceNumber, final long serialNumber, final JSONObject issuerData, final String identity, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslEncodingException, MslCryptoException {
        // The expiration must appear after the renewal window.
        if (expiration.before(renewalWindow))
            throw new MslInternalException("Cannot construct a master token that expires before its renewal window opens.");
        // The sequence number and serial number must be within range.
        if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Sequence number " + sequenceNumber + " is outside the valid range.");
        if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Serial number " + serialNumber + " is outside the valid range.");
        
        this.ctx = ctx;
        this.renewalWindow = renewalWindow.getTime() / MILLISECONDS_PER_SECOND;
        this.expiration = expiration.getTime() / MILLISECONDS_PER_SECOND;
        this.sequenceNumber = sequenceNumber;
        this.serialNumber = serialNumber;
        this.issuerData = issuerData;
        this.identity = identity;
        this.encryptionKey = encryptionKey;
        this.hmacKey = hmacKey;
        
        // Construct the session data.
        final JSONObject sessionData = new JSONObject();
        try {
            if (this.issuerData != null)
                sessionData.put(KEY_ISSUER_DATA, this.issuerData);
            sessionData.put(KEY_IDENTITY, this.identity);
            sessionData.put(KEY_ENCRYPTION_KEY, DatatypeConverter.printBase64Binary(this.encryptionKey.getEncoded()));
            sessionData.put(KEY_HMAC_KEY, DatatypeConverter.printBase64Binary(this.hmacKey.getEncoded()));
            this.sessiondata = sessionData.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "sessiondata", e);
        }
        
        // Encrypt the session data.
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] ciphertext = cryptoContext.encrypt(this.sessiondata);
        
        // Construct the token data.
        try {
            final JSONObject tokenDataJO = new JSONObject();
            tokenDataJO.put(KEY_RENEWAL_WINDOW, this.renewalWindow);
            tokenDataJO.put(KEY_EXPIRATION, this.expiration);
            tokenDataJO.put(KEY_SEQUENCE_NUMBER, this.sequenceNumber);
            tokenDataJO.put(KEY_SERIAL_NUMBER, this.serialNumber);
            tokenDataJO.put(KEY_SESSIONDATA, DatatypeConverter.printBase64Binary(ciphertext));
            this.tokendata = tokenDataJO.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "mastertokendata", e);
        }
        
        // Sign the token data.
        this.signature = cryptoContext.sign(this.tokendata);
        this.verified = true;
    }
    
    /**
     * Create a new master token from the provided JSON.
     * 
     * @param ctx MSL context.
     * @param masterTokenJO master token JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON,
     *         the token data is missing or invalid, the signature is missing
     *         or invalid, or the session data is missing or invalid.
     * @throws MslCryptoException if there is an error verifying the token data
     *         or extracting the session keys.
     * @throws MslException if the expiration timestamp occurs before the
     *         renewal window, or the sequence number is out of range, or the
     *         serial number is out of range.
     */
    public MasterToken(final MslContext ctx, final JSONObject masterTokenJO) throws MslEncodingException, MslCryptoException, MslException {
        this.ctx = ctx;
        
        // Grab the crypto context.
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Verify the JSON representation.
        try {
            try {
                tokendata = DatatypeConverter.parseBase64Binary(masterTokenJO.getString(KEY_TOKENDATA));
            } catch (final IllegalArgumentException e) {
                throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_INVALID, "mastertoken " + masterTokenJO.toString(), e);
            }
            if (tokendata == null || tokendata.length == 0)
                throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_MISSING, "mastertoken " + masterTokenJO.toString());
            try {
                signature = DatatypeConverter.parseBase64Binary(masterTokenJO.getString(KEY_SIGNATURE));
            } catch (final IllegalArgumentException e) {
                throw new MslEncodingException(MslError.MASTERTOKEN_SIGNATURE_INVALID, "mastertoken " + masterTokenJO.toString(), e);
            }
            verified = cryptoContext.verify(tokendata, signature);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "mastertoken " + masterTokenJO.toString(), e);
        }
        
        // Pull the token data.
        final String tokenDataJson = new String(tokendata, MslConstants.DEFAULT_CHARSET);
        try {
            final JSONObject tokenDataJO = new JSONObject(tokenDataJson);
            renewalWindow = tokenDataJO.getLong(KEY_RENEWAL_WINDOW);
            expiration = tokenDataJO.getLong(KEY_EXPIRATION);
            if (expiration < renewalWindow)
                throw new MslException(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL, "mastertokendata " + tokenDataJson);
            sequenceNumber = tokenDataJO.getLong(KEY_SEQUENCE_NUMBER);
            if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokenDataJson);
            serialNumber = tokenDataJO.getLong(KEY_SERIAL_NUMBER);
            if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokenDataJson);
            final byte[] ciphertext;
            try {
                ciphertext = DatatypeConverter.parseBase64Binary(tokenDataJO.getString(KEY_SESSIONDATA));
            } catch (final IllegalArgumentException e) {
                throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_INVALID, tokenDataJO.getString(KEY_SESSIONDATA));
            }
            if (ciphertext == null || ciphertext.length == 0)
                throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_MISSING, tokenDataJO.getString(KEY_SESSIONDATA));
            sessiondata = (this.verified) ? cryptoContext.decrypt(ciphertext) : null;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR, "mastertokendata " + tokenDataJson, e);
        }
        
        // Pull the session data.
        if (sessiondata != null) {
            // Parse JSON.
            final String sessionDataJson = new String(sessiondata, MslConstants.DEFAULT_CHARSET);
            final String encryptionB64, hmacB64;
            try {
                final JSONObject sessionDataJO = new JSONObject(sessionDataJson);
                issuerData = (sessionDataJO.has(KEY_ISSUER_DATA)) ? sessionDataJO.getJSONObject(KEY_ISSUER_DATA) : null;
                identity = sessionDataJO.getString(KEY_IDENTITY);
                // TODO: optionally include the algorithm names in the master token.
                encryptionB64 = sessionDataJO.getString(KEY_ENCRYPTION_KEY);
                hmacB64 = sessionDataJO.getString(KEY_HMAC_KEY);
            } catch (final JSONException e) {
                throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR, "sessiondata " + sessionDataJson, e);
            }
            
            // Reconstruct keys.
            try {
                encryptionKey = new SecretKeySpec(DatatypeConverter.parseBase64Binary(encryptionB64), JcaAlgorithm.AES);
                hmacKey = new SecretKeySpec(DatatypeConverter.parseBase64Binary(hmacB64), JcaAlgorithm.HMAC_SHA256);
            } catch (final IllegalArgumentException e) {
                throw new MslCryptoException(MslError.MASTERTOKEN_KEY_CREATION_ERROR, e);
            }
        } else {
            issuerData = null;
            identity = null;
            encryptionKey = null;
            hmacKey = null;
        }
    }
    
    /**
     * @return true if the decrypted content is available. (Implies verified.)
     */
    public boolean isDecrypted() {
        return sessiondata != null;
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
     * <p>Returns true if the master token renewal window has been entered.</p>
     *
     * <ul>
     * <li>If a time is provided the renewal window value will be compared
     * against the provided time.</li>
     * <li>If the master token was issued by the local entity the renewal
     * window value will be compared against the local entity time. We assume
     * its clock at the time of issuance is in sync with the clock now.</li>
     * <li>Otherwise the master token is considered renewable under the
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
     * <p>Returns true if the master token is expired.</p>
     *
     * <ul>
     * <li>If a time is provided the expiration value will be compared against
     * the provided time.</li>
     * <li>If the master token was issued by the local entity the expiration
     * value will be compared against the local entity time. We assume
     * its clock at the time of issuance is in sync with the clock now.</li>
     * <li>Otherwise the master token is considered not expired under the
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
     * @return the sequence number.
     */
    public long getSequenceNumber() {
        return sequenceNumber;
    }

    /**
     * @return the serial number.
     */
    public long getSerialNumber() {
        return serialNumber;
    }
    
    /**
     * <p>A master token is considered newer if its sequence number is greater
     * than another master token. If both the sequence numbers are equal, then
     * the master token with the later expiration date is considered newer.</p>
     * 
     * <p>Serial numbers are not taken into consideration when comparing which
     * master token is newer because serial numbers will change when new master
     * tokens are created as opposed to renewed. The caller of this function
     * should already be comparing master tokens that can be used
     * interchangeably (i.e. for the same MSL network).</p>
     * 
     * @param that the master token to compare with.
     * @return true if this master token is newer than the provided one.
     */
    public boolean isNewerThan(final MasterToken that) {
        // If the sequence numbers are equal then compare the expiration dates.
        if (this.sequenceNumber == that.sequenceNumber)
            return this.expiration > that.expiration;
        
        // If this sequence number is bigger than that sequence number, make
        // sure that sequence number is not less than the cutoff.
        if (this.sequenceNumber > that.sequenceNumber) {
            final long cutoff = this.sequenceNumber - MslConstants.MAX_LONG_VALUE + 127;
            return that.sequenceNumber >= cutoff;
        }
        
        // If this sequence number is smaller than that sequence number, make
        // sure this sequence number is less than the cutoff.
        final long cutoff = that.sequenceNumber - MslConstants.MAX_LONG_VALUE + 127;
        return this.sequenceNumber < cutoff;
    }
    
    /**
     * Returns the issuer data.
     * 
     * @return the master token issuer data or null if there is none or it is
     *         unknown (session data could not be decrypted).
     */
    public JSONObject getIssuerData() {
        return issuerData;
    }

    /**
     * Returns the identifier of the authenticated peer.
     * 
     * @return the Netflix peer identity or null if unknown (session data could
     *         not be decrypted).
     */
    public String getIdentity() {
        return identity;
    }
    
    /**
     * @return the symmetric encryption key or null if unknown (session data
     *         could not be decrypted).
     */
    public SecretKey getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * @return the symmetric HMAC key or null if unknown (session data could
     *         not be decrypted).
     */
    public SecretKey getHmacKey() {
        return hmacKey;
    }
    
    /** MSL context. */
    private final MslContext ctx;

    /** Token data. */
    private final byte[] tokendata;
    /** Master token signature. */
    private final byte[] signature;
    
    /** Master token renewal window in seconds since the epoch. */
    private final long renewalWindow;
    /** Master token expiration in seconds since the epoch. */
    private final long expiration;
    /** Sequence number. */
    private final long sequenceNumber;
    /** Serial number. */
    private final long serialNumber;
    /** Session data. */
    private final byte[] sessiondata;
    
    /** Issuer data. */
    private final JSONObject issuerData;
    /** Entity identity. */
    private final String identity;
    /** Encryption key. */
    private final SecretKey encryptionKey;
    /** HMAC key. */
    private final SecretKey hmacKey;
    
    /** Token is verified. */
    private final boolean verified;

    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
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
            final JSONObject sessiondataJO;
            if (isDecrypted()) {
                sessiondataJO = new JSONObject();
                if (issuerData != null)
                    sessiondataJO.put(KEY_ISSUER_DATA, issuerData);
                sessiondataJO.put(KEY_IDENTITY, identity);
                sessiondataJO.put(KEY_ENCRYPTION_KEY, encryptionKey);
                sessiondataJO.put(KEY_HMAC_KEY, hmacKey);
            } else {
                sessiondataJO = null;
            }
            
            final JSONObject tokendataJO = new JSONObject();
            tokendataJO.put(KEY_RENEWAL_WINDOW, renewalWindow);
            tokendataJO.put(KEY_EXPIRATION, expiration);
            tokendataJO.put(KEY_SEQUENCE_NUMBER, sequenceNumber);
            tokendataJO.put(KEY_SERIAL_NUMBER, serialNumber);
            tokendataJO.put(KEY_SESSIONDATA, sessiondataJO);
            
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_TOKENDATA, tokendataJO);
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }

    /**
     * @param obj the reference object with which to compare.
     * @return true if the other object is a master token with the same
     *         serial number and sequence number.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (obj instanceof MasterToken) {
            final MasterToken that = (MasterToken)obj;
            return this.serialNumber == that.serialNumber &&
                this.sequenceNumber == that.sequenceNumber &&
                this.expiration == that.expiration;
        }
        return false;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return (String.valueOf(serialNumber) + ":" + String.valueOf(sequenceNumber) + ":" + String.valueOf(expiration)).hashCode();
    }
}
