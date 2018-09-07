/**
 * Copyright (c) 2013-2018 Netflix, Inc.  All rights reserved.
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

import com.netflix.msl.MslConstants.SignatureAlgo;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

/**
 * <p>MSL signature envelopes contain all of the information necessary for
 * verifying data using a known key.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslSignatureEnvelope {
    /** Key version. */
    private final static String KEY_VERSION = "version";
    /** Key algorithm. */
    private final static String KEY_ALGORITHM = "algorithm";
    /** Key signature. */
    private final static String KEY_SIGNATURE = "signature";
    
    /** Versions. */
    public static enum Version {
        /**
         * <p>Version 1.</p>
         * 
         * {@code signature}
         * 
         * <p>The signature is represented as raw bytes.</p>
         */
        V1,
        /**
         * <p>Version 2.</p>
         * 
         * {@code {
         *   "#mandatory" : [ "version", "algorithm", "signature" ],
         *   "version" : "number",
         *   "algorithm" : "string",
         *   "signature" : "binary"
         * }} where:
         * <ul>
         * <li>{@code version} is the number '2'</li>
         * <li>{@code algorithm} is one of the recognized signature algorithms</li>
         * <li>{@code signature} is the signature</li>
         * </ul>
         * 
         * <p>Supported algorithms:
         * <table>
         * <tr><th>Algorithm</th><th>Description</th>
         * <tr><td>HmacSHA256</td><td>HMAC w/SHA-256</td></tr>
         * <tr><td>SHA256withRSA</td><td>RSA signature w/SHA-256</td></tr>
         * <tr><td>AESCmac</td><td>AES CMAC</td></tr>
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
                default: throw new IllegalArgumentException("Unknown signature envelope version.");
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
     * Create a new version 1 signature envelope with the provided signature.
     * 
     * @param signature the signature.
     */
    public MslSignatureEnvelope(final byte[] signature) {
        this.version = Version.V1;
        this.algorithm = null;
        this.signature = signature;
    }
    
    /**
     * Create a new version 2 signature envelope with the provided data.
     * 
     * @param algorithm the signature algorithm.
     * @param signature the signature.
     */
    public MslSignatureEnvelope(final SignatureAlgo algorithm, final byte[] signature) {
        this.version = Version.V2;
        this.algorithm = algorithm;
        this.signature = signature;
    }
    
    /**
     * Create a new signature envelope for the specified version from the
     * provided envelope bytes.
     * 
     * @param ctx MSL context.
     * @param envelope the raw envelope bytes.
     * @param version the envelope version.
     * @return the envelope.
     * @throws MslCryptoException if there is an error processing the signature
     *         envelope.
     * @throws MslEncodingException if there is an error parsing the envelope.
     * @see #getBytes(MslEncoderFactory, MslEncoderFormat)
     */
    public static MslSignatureEnvelope parse(final MslContext ctx, final byte[] envelope, final Version version) throws MslCryptoException, MslEncodingException {
        // Parse envelope.
        switch (version) {
            case V1:
                return new MslSignatureEnvelope(envelope);
            case V2:
                try {
                    // We expect the byte representation to be a MSL object.
                    final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
                    final MslObject envelopeMo = encoder.parseObject(envelope);
                    
                    // Verify version.
                    try {
                        final Version v = Version.valueOf(envelopeMo.getInt(KEY_VERSION));
                        if (!Version.V2.equals(v))
                            throw new MslCryptoException(MslError.UNSUPPORTED_SIGNATURE_ENVELOPE, "signature envelope " + envelopeMo);
                    } catch (final IllegalArgumentException e) {
                        throw new MslCryptoException(MslError.UNIDENTIFIED_SIGNATURE_ENVELOPE, "signature envelope " + envelopeMo, e);
                    }
                    
                    // Grab algorithm.
                    final SignatureAlgo algorithm;
                    try {
                        algorithm = SignatureAlgo.fromString(envelopeMo.getString(KEY_ALGORITHM));
                    } catch (final IllegalArgumentException e) {
                        throw new MslCryptoException(MslError.UNIDENTIFIED_ALGORITHM, "signature envelope " + envelopeMo, e);
                    }
                    
                    // Grab signature.
                    final byte[] signature = envelopeMo.getBytes(KEY_SIGNATURE);
                    
                    // Return the envelope.
                    return new MslSignatureEnvelope(algorithm, signature);
                } catch (final MslEncoderException e) {
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "signature envelope " + Base64.encode(envelope), e);
                }
            default:
                throw new MslCryptoException(MslError.UNSUPPORTED_SIGNATURE_ENVELOPE, "signature envelope " + Base64.encode(envelope));
        }
    }
    
    /**
     * Create a new signature envelope from the provided envelope bytes.
     * 
     * @param envelope the raw envelope bytes.
     * @param encoder MSL encoder factory.
     * @return the envelope.
     * @throws MslCryptoException if there is an error processing the signature
     *         envelope.
     * @throws MslEncodingException if there is an error parsing the envelope.
     * @see #getBytes(MslEncoderFactory, MslEncoderFormat)
     */
    public static MslSignatureEnvelope parse(final byte[] envelope, final MslEncoderFactory encoder) throws MslCryptoException, MslEncodingException {
        // Attempt to convert this to a MSL object.
        MslObject envelopeMo;
        try {
            // If this is a MSL object, we expect the byte representation to be
            // decodable.
            envelopeMo = encoder.parseObject(envelope);
        } catch (final MslEncoderException e) {
            envelopeMo = null;
        }

        // Determine the envelope version.
        //
        // If there is no MSL object, or there is no version field (as the
        // binary signature may coincidentally parse into a MSL object), then
        // this is a version 1 envelope.
        Version version;
        if (envelopeMo == null || !envelopeMo.has(KEY_VERSION)) {
            version = Version.V1;
        } else {
            try {
                version = Version.valueOf(envelopeMo.getInt(KEY_VERSION));
            } catch (final MslEncoderException e) {
                // There is a possibility that this is a version 1 envelope.
                version = Version.V1;
            } catch (final IllegalArgumentException e) {
                // There is a possibility that this is a version 1 envelope.
                version = Version.V1;
            }
        }
        
        // Parse envelope.
        switch (version) {
            case V1:
                return new MslSignatureEnvelope(envelope);
            case V2:
                try {
                    final SignatureAlgo algorithm = SignatureAlgo.fromString(envelopeMo.getString(KEY_ALGORITHM));
                    final byte[] signature = envelopeMo.getBytes(KEY_SIGNATURE);
                    return new MslSignatureEnvelope(algorithm, signature);
                } catch (final MslEncoderException e) {
                    // It is extremely unlikely but possible that this is a
                    // version 1 envelope.
                    return new MslSignatureEnvelope(envelope);
                } catch (final IllegalArgumentException e) {
                    // It is extremely unlikely but possible that this is a
                    // version 1 envelope.
                    return new MslSignatureEnvelope(envelope);
                }
            default:
                throw new MslCryptoException(MslError.UNSUPPORTED_SIGNATURE_ENVELOPE, "signature envelope " + Base64.encode(envelope));
        }
    }
    
    /**
     * @return the signature algorithm. May be null.
     */
    public SignatureAlgo getAlgorithm() {
        return algorithm;
    }
    
    /**
     * @return the signature.
     */
    public byte[] getSignature() {
        return signature;
    }
    
    /** Envelope version. */
    private final Version version;
    /** Algorithm. */
    private final SignatureAlgo algorithm;
    /** Signature. */
    private final byte[] signature;
    
    /**
     * Returns the signature envelope in byte form.
     * 
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the byte representation of the signature envelope.
     * @throws MslEncoderException if there is an error encoding the envelope.
     * @throws MslInternalException if the envelope version is not supported.
     */
    public byte[] getBytes(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        switch (version) {
            case V1:
                return signature;
            case V2:
                final MslObject mo = encoder.createObject();
                mo.put(KEY_VERSION, version.intValue());
                mo.put(KEY_ALGORITHM, algorithm.name());
                mo.put(KEY_SIGNATURE, signature);
                return encoder.encodeObject(mo, format);
            default:
                throw new MslInternalException("Signature envelope version " + version + " encoding unsupported.");
        }
    }
}
