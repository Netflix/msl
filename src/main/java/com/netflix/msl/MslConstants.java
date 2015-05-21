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
package com.netflix.msl;

import java.nio.charset.Charset;
import java.util.Set;

/**
 * Message security layer constants.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class MslConstants {
    /** RFC-4627 defines UTF-8 as the default encoding. */
    public static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");
    
    /** Maximum long integer value (2^53 limited by JavaScript). */
    public static final long MAX_LONG_VALUE = 9007199254740992L;
    
    /**
     * The maximum number of MSL messages (requests sent or responses received)
     * to allow before giving up. Six exchanges, or twelve total messages,
     * should be sufficient to capture all possible error recovery and
     * handshake requirements in both trusted network and peer-to-peer modes.
     */
    public static final int MAX_MESSAGES = 12;
    
    /** Compression algorithm. */
    public static enum CompressionAlgorithm {
        // In order of most preferred to least preferred.
        /** GZIP */
        GZIP,
        /** LZW */
        LZW;
        
        /**
         * Returns the most preferred compression algorithm from the provided
         * set of algorithms.
         * 
         * @param algos the set of algorithms to choose from.
         * @return the most preferred compression algorithm or {@code null} if
         *         the algorithm set is empty.
         */
        public static CompressionAlgorithm getPreferredAlgorithm(final Set<CompressionAlgorithm> algos) {
            // Enum.values() returns the values in declaration order which will
            // be the preferred order as promised above.
            final CompressionAlgorithm preferredAlgos[] = CompressionAlgorithm.values();
            for (int i = 0; i < preferredAlgos.length && algos.size() > 0; ++i) {
                final CompressionAlgorithm preferredAlgo = preferredAlgos[i];
                if (algos.contains(preferredAlgo))
                    return preferredAlgo;
            }
            return null;
        }
    }
    
    /** Encryption algorithms. */
    public static enum EncryptionAlgo {
        /** AES */
        AES,
        ;
        
        /**
         * @param value the string value of the encryption algorithm.
         * @return the encryption algorithm associated with the string value.
         * @throws IllegalArgumentException if the value is unknown.
         */
        public static EncryptionAlgo fromString(final String value) {
            return EncryptionAlgo.valueOf(EncryptionAlgo.class, value);
        }
        
        /**
         * Returns the string value of this encryption algorithm. This will be
         * equal to the Java standard algorithm name and is suitable for use
         * with the JCE interfaces.
         * 
         * @return the Java standard algorithm name for this encryption
         *         algorithm.
         */
        @Override
        public String toString() {
            return name();
        }
    }
    
    /** Cipher specifications. */
    public static enum CipherSpec {
        /** AES/CBC/PKCS5Padding */
        AES_CBC_PKCS5Padding,
        /** AESWrap */
        AESWrap,
        /** RSA/ECB/PKCS1Padding */
        RSA_ECB_PKCS1Padding,
        ;
        
        /** AES/CBC/PKCS5Padding string value. */
        private static final String AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";
        /** RSA/ECB/PCKS1Padding string value. */
        private static final String RSA_ECB_PKCS1PADDING = "RSA/ECB/PKCS1Padding";
        
        /**
         * @param value the string value of the cipher specification.
         * @return the cipher specification associated with the string value.
         * @throws IllegalArgumentException if the value is unknown.
         */
        public static CipherSpec fromString(final String value) {
            if (AES_CBC_PKCS5PADDING.equals(value))
                return AES_CBC_PKCS5Padding;
            if (RSA_ECB_PKCS1PADDING.equals(value))
                return RSA_ECB_PKCS1Padding;
            return CipherSpec.valueOf(CipherSpec.class, value);
        }
        
        /**
         * Returns the string value of this cipher specification. This will be
         * equal to the Java standard algorithm name and is suitable for use
         * with the JCE interfaces.
         * 
         * @return the Java standard algortihm name for this cipher
         *         specification.
         */
        @Override
        public String toString() {
            switch (this) {
                case AES_CBC_PKCS5Padding:
                    return AES_CBC_PKCS5PADDING;
                case RSA_ECB_PKCS1Padding:
                    return RSA_ECB_PKCS1PADDING;
                default:
                    return name();
            }
        }
    }
    
    /** Signature algorithms. */
    public static enum SignatureAlgo {
        /** HmacSHA256 */
        HmacSHA256,
        /** SHA256withRSA */
        SHA256withRSA,
        /** AESCmac. */
        AESCmac,
        ;
        
        /**
         * @param value the string value of the signature algorithm.
         * @return the signature algorithm associated with the string value.
         * @throws IllegalArgumentException if the value is unknown.
         */
        public static SignatureAlgo fromString(final String value) {
            return SignatureAlgo.valueOf(SignatureAlgo.class, value);
        }
        
        /**
         * Returns the string value of this signature algorithm. This will be
         * equal to the Java standard algorithm name and is suitable for use
         * with the JCE interfaces.
         * 
         * @return the Java standard algortihm name for this signature
         *         algorithm.
         */
        @Override
        public String toString() {
            return name();
        }
    }
    
    /** Error response codes. */
    public static enum ResponseCode {
        /** The message is erroneous and will continue to fail if retried. */
        FAIL(1),
        /** The message is expected to succeed if retried after a delay. */
        TRANSIENT_FAILURE(2),
        /** The message is expected to succeed post entity re-authentication. */
        ENTITY_REAUTH(3),
        /** The message is expected to succeed post user re-authentication. */
        USER_REAUTH(4),
        /** The message is expected to succeed post key exchange. */
        KEYX_REQUIRED(5),
        /** The message is expected to succeed with new entity authentication data. */
        ENTITYDATA_REAUTH(6),
        /** The message is expected to succeed with new user authentication data. */
        USERDATA_REAUTH(7),
        /** The message is expected to succeed if retried with a renewed master token or renewable message. */
        EXPIRED(8),
        /** The non-replayable message is expected to succeed if retried with the newest master token. */
        REPLAYED(9),
        /** The message is expected to succeed with new user authentication data containing a valid single-sign-on token. */
        SSOTOKEN_REJECTED(10),
        ;
        
        /**
         * @return the response code corresponding to the integer value.
         * @throws IllegalArgumentException if the integer value does not map
         *         onto a response code.
         */
        public static ResponseCode valueOf(final int code) {
            for (final ResponseCode value : ResponseCode.values()) {
                if (value.intValue() == code)
                    return value;
            }
            throw new IllegalArgumentException("Unknown response code value " + code + ".");
        }
        
        /**
         * Create a new response code with the specified integer value.
         * 
         * @param code the integer value for the response code.
         */
        private ResponseCode(final int code) {
            this.code = code;
        }
        
        /**
         * @return the integer value of the response code.
         */
        public int intValue() {
            return code;
        }
        
        /** The response code value. */
        private final int code;
    }
}
