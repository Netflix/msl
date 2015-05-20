/**
 * Copyright (c) 2013 Netflix, Inc.  All rights reserved.
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

/**
 * <p>JCE standard algorithm name constants.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class JcaAlgorithm {
    /** AES. */
    public static final String AES = "AES";
    /** HMAC-SHA256. */
    public static final String HMAC_SHA256 = "HmacSHA256";
    /** AES key wrap. */
    public static final String AESKW = "AES";
    /** CMAC. */
    public static final String AES_CMAC = "AESCmac";
}
