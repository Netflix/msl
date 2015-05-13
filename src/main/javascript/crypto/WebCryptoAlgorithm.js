/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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

/**
 * MSL algorithms mapped onto Web Crypto algorithms.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var WebCryptoAlgorithm = {
    /** generate/wrap/unwrap */
    A128KW: { 'name': 'AES-KW' },
    /** generate/encrypt/decrypt */
    AES_CBC: { 'name': 'AES-CBC' },
    /** generate */
    DIFFIE_HELLMAN: { 'name': 'DH' },
    /** generate/sign/verify */
    HMAC_SHA256: { 'name': 'HMAC', 'hash': { 'name': 'SHA-256' } },
    /** generate/encrypt/decrypt/wrap/unwrap */
    RSA_OAEP: { 'name': 'RSA-OAEP', 'hash': { 'name': 'SHA-1' } },
    /** generate/encrypt/decrypt */
    RSAES: { 'name': 'RSAES-PKCS1-v1_5' },
    /** generate */
    RSASSA: { 'name': 'RSASSA-PKCS1-v1_5', 'hash': { 'name': 'SHA-1' } },
    /** sign/verify */
    RSASSA_SHA256: { 'name': 'RSASSA-PKCS1-v1_5', 'hash': { 'name': 'SHA-256' } },
    RSASSA_SHA1: { 'name': 'RSASSA-PKCS1-v1_5', 'hash': { 'name': 'SHA-1' } },
    /** deriveKey */
    AUTHENTICATED_DH: { 'name' : 'NFLX-DH' },
    /** digest */
    SHA_256: { 'name': 'SHA-256' },
    SHA_384: { 'name': 'SHA-384' },
};
