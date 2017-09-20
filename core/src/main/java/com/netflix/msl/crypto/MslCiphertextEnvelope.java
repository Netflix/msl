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
package com.netflix.msl.crypto;

import com.netflix.msl.MslConstants.CipherSpec;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;

/**
 * MSL ciphertext envelopes contain all of the information necessary for
 * decrypting ciphertext using a known key.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslCiphertextEnvelope implements MslEncodable {
    /** Key version. */
    private final static String KEY_VERSION = "version";
    /** Key key ID. */
    private final static String KEY_KEY_ID = "keyid";
    /** Key cipherspec. */
    private final static String KEY_CIPHERSPEC = "cipherspec";
    /** Key initialization vector. */
    private final static String KEY_IV = "iv";
    /** Key ciphertext. */
    private final static String KEY_CIPHERTEXT = "ciphertext";
    /** Key SHA-256. */
    private final static String KEY_SHA256 = "sha256";
    
    /** Versions. */
    public static enum Version {
        /**
         * <p>Version 1.</p>
         * 
         * {@code {
         *   "#mandatory" : [ "keyid", "iv", "ciphertext", "sha256" ],
         *   "keyid" : "string",
         *   "iv" : "binary",
         *   "ciphertext" : "binary",
         *   "sha256" : "binary",
         * }} where:
         * <ul>
         * <li>{@code keyid} is the encryption key ID</li>
         * <li>{@code iv} is the initialization vector</li>
         * <li>{@code ciphertext} is the ciphertext</li>
         * <li>{@code sha256} is the SHA-256 of the encryption envelope</li>
         * </ul>
         * 
         * <p>The SHA-256 is computed over the concatenation of {@code key ID ||
         * IV || ciphertext}.</p>
         */
        V1,
        /**
         * <p>Version 2.</p>
         * 
         * {@code {
         *   "#mandatory" : [ "version", "cipherspec", "ciphertext" ],
         *   "version" : "number",
         *   "cipherspec" : "string",
         *   "iv" : "binary",
         *   "ciphertext" : "binary",
         * }} where:
         * <ul>
         * <li>{@code version} is the number '2'</li>
         * <li>{@code cipherspec} is one of the recognized cipher specifications</li>
         * <li>{@code iv} is the optional initialization vector</li>
         * <li>{@code ciphertext} is the ciphertext</li>
         * </ul>
         * 
         * <p>Supported cipher specifications:
         * <table>
         * <tr><th>Cipher Spec</th><th>Description</th></tr>
         * <tr><td>AES/CBC/PKCS5Padding</td><td>AES CBC w/PKCS#5 Padding</td></tr>
         * </table></p>
         */
        V2;
        
        /**
         * @param version the integer value of this version.
         * @return the version identified by the integer value.
         * @throws IllegalArgumentException if the version is unknown.
         */
        public static Version valueOf(final int version) {
            switch (version) {
                case 1: return V1;
                case 2: return V2;
                default: throw new IllegalArgumentException("Unknown ciphertext envelope version " + version + ".");
            }
        }
        
        /**
         * @return the integer value of this version.
         */
        public int intValue() {
            switch (this) {
                case V1: return 1;
                case V2: return 2;
                default: throw new MslInternalException("No integer value defined for version " + this + ".");
            }
        }
    }
    
    /**
     * Determines the envelope version of the given MSL object.
     * 
     * @param mo the MSL object.
     * @return the envelope version.
     * @throws MslCryptoException if the envelope version is not recognized.
     */
    private static Version getVersion(final MslObject mo) throws MslCryptoException {
        try {
            final int v = mo.getInt(KEY_VERSION);
            return Version.valueOf(v);
        } catch (final MslEncoderException e) {
            // If anything fails to parse, treat this as a version 1 envelope.
            return Version.V1;
        } catch (final IllegalArgumentException e) {
            throw new MslCryptoException(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE, "ciphertext envelope " + mo, e);
        }
    }
    
    /**
     * Create a new version 1 ciphertext envelope with the provided data.
     * 
     * @param keyId the key identifier.
     * @param iv the initialization vector. May be null.
     * @param ciphertext the ciphertext.
     */
    public MslCiphertextEnvelope(final String keyId, final byte[] iv, final byte[] ciphertext) {
        this.version = Version.V1;
        this.keyId = keyId;
        this.cipherSpec = null;
        this.iv = iv;
        this.ciphertext = ciphertext;
    }
    
    /**
     * Create a new version 2 ciphertext envelope with the provided data.
     * 
     * @param cipherSpec the cipher specification.
     * @param iv the initialization vector. May be null.
     * @param ciphertext the ciphertext.
     */
    public MslCiphertextEnvelope(final CipherSpec cipherSpec, final byte[] iv, final byte[] ciphertext) {
        this.version = Version.V2;
        this.keyId = null;
        this.cipherSpec = cipherSpec;
        this.iv = iv;
        this.ciphertext = ciphertext;
    }
    
    /**
     * Create a new encryption envelope from the provided MSL object.
     * 
     * @param mo the MSL object.
     * @throws MslCryptoException if there is an error processing the
     *         encryption envelope.
     * @throws MslEncodingException if there is an error parsing the data.
     */
    public MslCiphertextEnvelope(final MslObject mo) throws MslCryptoException, MslEncodingException {
        this(mo, getVersion(mo));
    }

    /**
     * Create a new encryption envelope of the specified version from the
     * provided MSL object.
     * 
     * @param mo the MSL object.
     * @param version the envelope version.
     * @throws MslCryptoException if there is an error processing the
     *         encryption envelope.
     * @throws MslEncodingException if there is an error parsing the data.
     */
    public MslCiphertextEnvelope(final MslObject mo, final Version version) throws MslCryptoException, MslEncodingException {
        // Parse envelope.
        switch (version) {
            case V1:
                try {
                    this.version = Version.V1;
                    this.keyId = mo.getString(KEY_KEY_ID);
                    this.cipherSpec = null;
                    this.iv = (mo.has(KEY_IV)) ? mo.getBytes(KEY_IV) : null;
                    this.ciphertext = mo.getBytes(KEY_CIPHERTEXT);
                    mo.getBytes(KEY_SHA256);
                } catch (final MslEncoderException e) {
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "ciphertext envelope " + mo, e);
                }
                break;
            case V2:
                try {
                    final int v = mo.getInt(KEY_VERSION);
                    this.version = Version.valueOf(v);
                    if (!Version.V2.equals(this.version))
                        throw new MslCryptoException(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE, "ciphertext envelope " + mo.toString());
                    this.keyId = null;
                    try {
                        this.cipherSpec = CipherSpec.fromString(mo.getString(KEY_CIPHERSPEC));
                    } catch (final IllegalArgumentException e) {
                        throw new MslCryptoException(MslError.UNIDENTIFIED_CIPHERSPEC, "ciphertext envelope " + mo, e);
                    }
                    this.iv = (mo.has(KEY_IV)) ? mo.getBytes(KEY_IV) : null;
                    this.ciphertext = mo.getBytes(KEY_CIPHERTEXT);
                } catch (final MslEncoderException e) {
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "ciphertext envelope " + mo, e);
                }
                break;
            default:
                throw new MslCryptoException(MslError.UNSUPPORTED_CIPHERTEXT_ENVELOPE, "ciphertext envelope version " + version);
        }
    }
    
    /**
     * @return the encryption key ID. May be null.
     */
    public String getKeyId() {
        return keyId;
    }
    
    /**
     * @return the ciphser specification. May be null.
     */
    public CipherSpec getCipherSpec() {
        return cipherSpec;
    }

    /**
     * @return the initialization vector. May be null.
     */
    public byte[] getIv() {
        return iv;
    }

    /**
     * @return the ciphertext.
     */
    public byte[] getCiphertext() {
        return ciphertext;
    }

    /** Envelope version. */
    private final Version version;
    /** Key identifier. */
    private final String keyId;
    /** Cipher specification. */
    private CipherSpec cipherSpec;
    /** Optional initialization vector. */
    private final byte[] iv;
    /** Ciphertext. */
    private final byte[] ciphertext;
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        final MslObject mo = encoder.createObject();
        switch (version) {
            case V1:
                mo.put(KEY_KEY_ID, keyId);
                if (iv != null) mo.put(KEY_IV, iv);
                mo.put(KEY_CIPHERTEXT, ciphertext);
                mo.put(KEY_SHA256, Base64.decode("AA=="));
                break;
            case V2:
                mo.put(KEY_VERSION, version.intValue());
                mo.put(KEY_CIPHERSPEC, cipherSpec.toString());
                if (iv != null) mo.put(KEY_IV, iv);
                mo.put(KEY_CIPHERTEXT, ciphertext);
                break;
            default:
                throw new MslEncoderException("Ciphertext envelope version " + version + " encoding unsupported.");
        }
        return encoder.encodeObject(mo, format);
    }
}
