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
package com.netflix.msl.crypto;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslConstants.CipherSpec;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;

/**
 * MSL ciphertext envelopes contain all of the information necessary for
 * decrypting ciphertext using a known key.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslCiphertextEnvelope implements JSONString {
    /** JSON key version. */
    private final static String KEY_VERSION = "version";
    /** JSON key key ID. */
    private final static String KEY_KEY_ID = "keyid";
    /** JSON key cipherspec. */
    private final static String KEY_CIPHERSPEC = "cipherspec";
    /** JSON key initialization vector. */
    private final static String KEY_IV = "iv";
    /** JSON key ciphertext. */
    private final static String KEY_CIPHERTEXT = "ciphertext";
    /** JSON key SHA-256. */
    private final static String KEY_SHA256 = "sha256";
    
    /** Versions. */
    public enum Version {
        /**
         * <p>Version 1.</p>
         * 
         * {@code {
         *   "#mandatory" : [ "keyid", "iv", "ciphertext", "sha256" ],
         *   "keyid" : "string",
         *   "iv" : "base64",
         *   "ciphertext" : "base64",
         *   "sha256" : "base64",
         * }} where:
         * <ul>
         * <li>{@code keyid} is the encryption key ID</li>
         * <li>{@code iv} is the Base64-encoded initialization vector</li>
         * <li>{@code ciphertext} is the Base64-encoded ciphertext</li>
         * <li>{@code sha256} is the Base64-encoded SHA-256 of the encryption envelope</li>
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
         *   "iv" : "base64",
         *   "ciphertext" : "base64",
         * }} where:
         * <ul>
         * <li>{@code version} is the number '2'</li>
         * <li>{@code cipherspec} is one of the recognized cipher specifications</li>
         * <li>{@code iv} is the optional Base64-encoded initialization vector</li>
         * <li>{@code ciphertext} is the Base64-encoded ciphertext</li>
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
     * Determines the envelope version of the given JSON object.
     * 
     * @param jo the JSON object.
     * @return the envelope version.
     * @throws MslCryptoException if the envelope version is not recognized.
     */
    private static Version getVersion(final JSONObject jo) throws MslCryptoException {
        try {
            final int v = jo.getInt(KEY_VERSION);
            return Version.valueOf(v);
        } catch (final JSONException e) {
            // If anything fails to parse, treat this as a version 1 envelope.
            return Version.V1;
        } catch (final IllegalArgumentException e) {
            throw new MslCryptoException(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE, "ciphertext envelope " + jo.toString(), e);
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
     * Create a new encryption envelope from the provided JSON object.
     * 
     * @param jsonObj the JSON object.
     * @throws MslCryptoException if there is an error processing the
     *         encryption envelope.
     * @throws MslEncodingException if there is an error parsing the JSON.
     */
    public MslCiphertextEnvelope(final JSONObject jsonObj) throws MslCryptoException, MslEncodingException {
        this(jsonObj, getVersion(jsonObj));
    }

    /**
     * Create a new encryption envelope of the specified version from the
     * provided JSON object.
     * 
     * @param jsonObj the JSON object.
     * @param version the envelope version.
     * @throws MslCryptoException if there is an error processing the
     *         encryption envelope.
     * @throws MslEncodingException if there is an error parsing the JSON.
     */
    public MslCiphertextEnvelope(final JSONObject jsonObj, final Version version) throws MslCryptoException, MslEncodingException {
        // Parse envelope.
        switch (version) {
            case V1:
                try {
                    this.version = Version.V1;
                    this.keyId = jsonObj.getString(KEY_KEY_ID);
                    this.cipherSpec = null;
                    try {
                        this.iv = (jsonObj.has(KEY_IV)) ? DatatypeConverter.parseBase64Binary(jsonObj.getString(KEY_IV)) : null;
                    } catch (final IllegalArgumentException e) {
                        throw new MslCryptoException(MslError.INVALID_IV, "ciphertext envelope " + jsonObj.toString(), e);
                    }
                    try {
                        this.ciphertext = DatatypeConverter.parseBase64Binary(jsonObj.getString(KEY_CIPHERTEXT));
                    } catch (final IllegalArgumentException e) {
                        throw new MslCryptoException(MslError.INVALID_CIPHERTEXT, "ciphertext envelope " + jsonObj.toString(), e);
                    }
                    jsonObj.getString(KEY_SHA256);
                } catch (final JSONException e) {
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "ciphertext envelope " + jsonObj.toString(), e);
                }
                break;
            case V2:
                try {
                    final int v = jsonObj.getInt(KEY_VERSION);
                    this.version = Version.valueOf(v);
                    if (!Version.V2.equals(this.version))
                        throw new MslCryptoException(MslError.UNIDENTIFIED_CIPHERTEXT_ENVELOPE, "ciphertext envelope " + jsonObj.toString());
                    this.keyId = null;
                    this.cipherSpec = CipherSpec.fromString(jsonObj.getString(KEY_CIPHERSPEC));
                    try {
                        this.iv = (jsonObj.has(KEY_IV)) ? DatatypeConverter.parseBase64Binary(jsonObj.getString(KEY_IV)) : null;
                    } catch (final IllegalArgumentException e) {
                        throw new MslCryptoException(MslError.INVALID_IV, "ciphertext envelope " + jsonObj.toString(), e);
                    }
                    try {
                        this.ciphertext = DatatypeConverter.parseBase64Binary(jsonObj.getString(KEY_CIPHERTEXT));
                    } catch (final IllegalArgumentException e) {
                        throw new MslCryptoException(MslError.INVALID_CIPHERTEXT, "ciphertext envelope " + jsonObj.toString(), e);
                    }
                } catch (final IllegalArgumentException e) {
                    throw new MslCryptoException(MslError.UNIDENTIFIED_CIPHERSPEC, "ciphertext envelope " + jsonObj.toString(), e);
                } catch (final JSONException e) {
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "ciphertext envelope " + jsonObj.toString(), e);
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
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        try {
            final JSONObject jsonObj = new JSONObject();
            switch (version) {
                case V1:
                    jsonObj.put(KEY_KEY_ID, keyId);
                    if (iv != null) jsonObj.put(KEY_IV, DatatypeConverter.printBase64Binary(iv));
                    jsonObj.put(KEY_CIPHERTEXT, DatatypeConverter.printBase64Binary(ciphertext));
                    jsonObj.put(KEY_SHA256, "AA==");
                    break;
                case V2:
                    jsonObj.put(KEY_VERSION, version.intValue());
                    jsonObj.put(KEY_CIPHERSPEC, cipherSpec.toString());
                    if (iv != null) jsonObj.put(KEY_IV, DatatypeConverter.printBase64Binary(iv));
                    jsonObj.put(KEY_CIPHERTEXT, DatatypeConverter.printBase64Binary(ciphertext));
                    break;
                default:
                    throw new MslInternalException("Ciphertext envelope version " + version + " encoding unsupported.");
            }
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }
}
