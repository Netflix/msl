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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.EncryptionAlgo;
import com.netflix.msl.MslConstants.SignatureAlgo;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;
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
 *   "tokendata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the master token data (mastertokendata)</li>
 * <li>{@code signature} is the verification data of the master token data</li>
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
 *   "sessiondata" : "binary"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code sequencenumber} is the master token sequence number</li>
 * <li>{@code serialnumber} is the master token serial number</li>
 * <li>{@code sessiondata} is the encrypted session data (sessiondata)</li>
 * </ul></p>
 * 
 * <p>The decrypted session data is represented as
 * {@code
 * sessiondata = {
 *   "#mandatory" : [ "identity", "encryptionkey" ],
 *   "#conditions" : [ "hmackey" or "signaturekey" ],
 *   "issuerdata" : object,
 *   "identity" : "string",
 *   "encryptionkey" : "binary",
 *   "encryptionkeyalgorithm" : "string",
 *   "hmackey" : "binary",
 *   "signaturekey" : "binary",
 *   "signaturekeyalgorithm" : "string",
 * }}
 * where:
 * <ul>
 * <li>{@code issuerdata} is the master token issuer data</li>
 * <li>{@code identity} is the identifier of the remote entity</li>
 * <li>{@code encryptionkey} is the encryption session key</li>
 * <li>{@code encryptionkeyalgorithm} is the JCA encryption algorithm name (default: AES/CBC/PKCS5Padding)</li>
 * <li>{@code hmackey} is the HMAC session key</li>
 * <li>{@code signaturekey} is the signature session key</li>
 * <li>{@code signaturekeyalgorithm} is the JCA signature algorithm name (default: HmacSHA256)</li> 
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MasterToken implements MslEncodable {
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
    /** Key sequence number. */
    private static final String KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** Key serial number. */
    private static final String KEY_SERIAL_NUMBER = "serialnumber";
    /** Key session data. */
    private static final String KEY_SESSIONDATA = "sessiondata";
    
    // sessiondata
    /** Key issuer data. */
    private static final String KEY_ISSUER_DATA = "issuerdata";
    /** Key identity. */
    private static final String KEY_IDENTITY = "identity";
    /** Key symmetric encryption key. */
    private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
    /** Key encryption algorithm. */
    private static final String KEY_ENCRYPTION_ALGORITHM = "encryptionalgorithm";
    /** Key symmetric HMAC key. */
    private static final String KEY_HMAC_KEY = "hmackey";
    /** Key signature key. */
    private static final String KEY_SIGNATURE_KEY = "signaturekey";
    /** Key signature algorithm. */
    private static final String KEY_SIGNATURE_ALGORITHM = "signaturealgorithm";
        
    /**
     * Create a new master token with the specified expiration, identity,
     * serial number, and encryption and signature keys.
     * 
     * @param ctx MSL context.
     * @param renewalWindow the renewal window.
     * @param expiration the expiration.
     * @param sequenceNumber the master token sequence number.
     * @param serialNumber the master token serial number.
     * @param issuerData the issuer data. May be null.
     * @param identity the singular identity this master token represents.
     * @param encryptionKey the session encryption key.
     * @param signatureKey the session signature key.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data or the crypto algorithms are not recognized.
     */
    public MasterToken(final MslContext ctx, final Date renewalWindow, final Date expiration, final long sequenceNumber, final long serialNumber, final MslObject issuerData, final String identity, final SecretKey encryptionKey, final SecretKey signatureKey) throws MslEncodingException, MslCryptoException {
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
        this.issuerdata = issuerData;
        this.identity = identity;
        this.encryptionKey = encryptionKey;
        this.signatureKey = signatureKey;
        
        // Encode session keys and algorithm names.
        final byte[] encryptionKeyBytes = this.encryptionKey.getEncoded();
        final byte[] signatureKeyBytes = this.signatureKey.getEncoded();
        final EncryptionAlgo encryptionAlgo;
        final SignatureAlgo signatureAlgo;
        try {
            encryptionAlgo = EncryptionAlgo.fromString(this.encryptionKey.getAlgorithm());
            signatureAlgo = SignatureAlgo.fromString(this.signatureKey.getAlgorithm());
        } catch (final IllegalArgumentException e) {
            throw new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM, "encryption algorithm: " + this.encryptionKey.getAlgorithm() + "; signature algorithm: " + this.signatureKey.getAlgorithm(), e);
        }
        
        // Create session data.
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        this.sessiondata = encoder.createObject();
        if (this.issuerdata != null)
            this.sessiondata.put(KEY_ISSUER_DATA, this.issuerdata);
        this.sessiondata.put(KEY_IDENTITY, this.identity);
        this.sessiondata.put(KEY_ENCRYPTION_KEY, encryptionKeyBytes);
        this.sessiondata.put(KEY_ENCRYPTION_ALGORITHM, encryptionAlgo);
        this.sessiondata.put(KEY_HMAC_KEY, signatureKeyBytes);
        this.sessiondata.put(KEY_SIGNATURE_KEY, signatureKeyBytes);
        this.sessiondata.put(KEY_SIGNATURE_ALGORITHM, signatureAlgo);

        this.tokendataBytes = null;
        this.signatureBytes = null;
        this.verified = true;
    }
    
    /**
     * Create a new master token from the provided MSL object.
     * 
     * @param ctx MSL context.
     * @param masterTokenMo master token MSL object.
     * @throws MslEncodingException if there is an error parsing the object,
     *         the token data is missing or invalid, the signature is missing
     *         or invalid, or the session data is missing or invalid.
     * @throws MslCryptoException if there is an error verifying the token data
     *         or extracting the session keys.
     * @throws MslException if the expiration timestamp occurs before the
     *         renewal window, or the sequence number is out of range, or the
     *         serial number is out of range.
     */
    public MasterToken(final MslContext ctx, final MslObject masterTokenMo) throws MslEncodingException, MslCryptoException, MslException {
        this.ctx = ctx;
        
        // Grab the crypto context.
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Verify the encoding.
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        try {
            tokendataBytes = masterTokenMo.getBytes(KEY_TOKENDATA);
            if (tokendataBytes.length == 0)
                throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_MISSING, "mastertoken " + masterTokenMo);
            signatureBytes = masterTokenMo.getBytes(KEY_SIGNATURE);
            verified = cryptoContext.verify(tokendataBytes, signatureBytes, encoder);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "mastertoken " + masterTokenMo, e);
        }
        
        // Pull the token data.
        final byte[] plaintext;
        try {
            final MslObject tokendata = encoder.parseObject(tokendataBytes);
            renewalWindow = tokendata.getLong(KEY_RENEWAL_WINDOW);
            expiration = tokendata.getLong(KEY_EXPIRATION);
            if (expiration < renewalWindow)
                throw new MslException(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL, "mastertokendata " + tokendata);
            sequenceNumber = tokendata.getLong(KEY_SEQUENCE_NUMBER);
            if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokendata);
            serialNumber = tokendata.getLong(KEY_SERIAL_NUMBER);
            if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokendata);
            final byte[] ciphertext = tokendata.getBytes(KEY_SESSIONDATA);
            if (ciphertext.length == 0)
                throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_MISSING, "mastertokendata " + tokendata);
            plaintext = (this.verified) ? cryptoContext.decrypt(ciphertext, encoder) : null;
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR, "mastertokendata " + Base64.encode(tokendataBytes), e);
        }
        
        // Pull the session data.
        if (plaintext != null) {
            final byte[] rawEncryptionKey, rawSignatureKey;
            final String encryptionAlgo, signatureAlgo;
            try {
                sessiondata = encoder.parseObject(plaintext);
                issuerdata = (sessiondata.has(KEY_ISSUER_DATA)) ? sessiondata.getMslObject(KEY_ISSUER_DATA, encoder) : null;
                identity = sessiondata.getString(KEY_IDENTITY);
                rawEncryptionKey = sessiondata.getBytes(KEY_ENCRYPTION_KEY);
                encryptionAlgo = sessiondata.optString(KEY_ENCRYPTION_ALGORITHM, JcaAlgorithm.AES);
                rawSignatureKey = (sessiondata.has(KEY_SIGNATURE_KEY))
                    ? sessiondata.getBytes(KEY_SIGNATURE_KEY)
                    : sessiondata.getBytes(KEY_HMAC_KEY);
                signatureAlgo = sessiondata.optString(KEY_SIGNATURE_ALGORITHM, JcaAlgorithm.HMAC_SHA256);
            } catch (final MslEncoderException e) {
                throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR, "sessiondata " + Base64.encode(plaintext), e);
            }
            
            // Decode algorithm names.
            final String jcaEncryptionAlgo, jcaSignatureAlgo;
            try {
                jcaEncryptionAlgo = EncryptionAlgo.fromString(encryptionAlgo).toString();
                jcaSignatureAlgo = SignatureAlgo.fromString(signatureAlgo).toString();
            } catch (final IllegalArgumentException e) {
                throw new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM, "encryption algorithm: " + encryptionAlgo + "; signature algorithm" + signatureAlgo, e);
            }
            
            // Reconstruct keys.
            try {
                encryptionKey = new SecretKeySpec(rawEncryptionKey, jcaEncryptionAlgo);
                signatureKey = new SecretKeySpec(rawSignatureKey, jcaSignatureAlgo);
            } catch (final IllegalArgumentException e) {
                throw new MslCryptoException(MslError.MASTERTOKEN_KEY_CREATION_ERROR, e);
            }
        } else {
            sessiondata = null;
            issuerdata = null;
            identity = null;
            encryptionKey = null;
            signatureKey = null;
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
    public MslObject getIssuerData() {
        return issuerdata;
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
     * @return the encryption key or null if unknown (session data could not be
     *         decrypted).
     */
    public SecretKey getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * @return the signature key or null if unknown (session data could not be
     *         decrypted).
     */
    public SecretKey getSignatureKey() {
        return signatureKey;
    }
    
    /** MSL context. */
    private final MslContext ctx;
    
    /** Master token renewal window in seconds since the epoch. */
    private final long renewalWindow;
    /** Master token expiration in seconds since the epoch. */
    private final long expiration;
    /** Sequence number. */
    private final long sequenceNumber;
    /** Serial number. */
    private final long serialNumber;
    /** Session data. */
    private final MslObject sessiondata;
    
    /** Issuer data. */
    private final MslObject issuerdata;
    /** Entity identity. */
    private final String identity;
    /** Encryption key. */
    private final SecretKey encryptionKey;
    /** Signature key. */
    private final SecretKey signatureKey;

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

            // Encrypt the session data.
            final byte[] plaintext = encoder.encodeObject(sessiondata, format);
            final byte[] ciphertext;
            try {
                ciphertext = cryptoContext.encrypt(plaintext, encoder, format);
            } catch (final MslCryptoException e) {
                throw new MslEncoderException("Error encrypting the session data.", e);
            }

            // Construct the token data.
            final MslObject tokendata = encoder.createObject();
            tokendata.put(KEY_RENEWAL_WINDOW, renewalWindow);
            tokendata.put(KEY_EXPIRATION, expiration);
            tokendata.put(KEY_SEQUENCE_NUMBER, sequenceNumber);
            tokendata.put(KEY_SERIAL_NUMBER, serialNumber);
            tokendata.put(KEY_SESSIONDATA, ciphertext);
            
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

        final MslObject tokendata = encoder.createObject();
        tokendata.put(KEY_RENEWAL_WINDOW, renewalWindow);
        tokendata.put(KEY_EXPIRATION, expiration);
        tokendata.put(KEY_SEQUENCE_NUMBER, sequenceNumber);
        tokendata.put(KEY_SERIAL_NUMBER, serialNumber);
        tokendata.put(KEY_SESSIONDATA, "(redacted)");

        final MslObject token = encoder.createObject();
        token.put(KEY_TOKENDATA, tokendata);
        token.put(KEY_SIGNATURE, (signatureBytes != null) ? signatureBytes : "(null)");
        return token.toString();
    }

    /**
     * <p>Returns true if the other object is a master token with the same
     * serial number, sequence number, and expiration. The expiration is
     * considered in the event the issuer renews a master token but is unable
     * or unwilling to increment the sequence number.</p>
     * 
     * @param obj the reference object with which to compare.
     * @return true if the other object is a master token with the same
     *         serial number, sequence number, and expiration.
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
