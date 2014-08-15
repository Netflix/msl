/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
var SimpleConstants = {
    /** Default server port. */
    SERVER_PORT: 8080,
    /** MSL control timeout in milliseconds. */
    TIMEOUT_MS: 120 * 1000,
    
    /** Server entity ID. */
    SERVER_ID: "SimpleMslServer",
    /** Server 1024-bit RSA public key. */
    RSA_PUBKEY_B64:
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALeJpiH5nikd3XeAo2rHjLJVVChM/p6l" +
        "VnQHyFh77w0Efbppi1P1pNy8BxJ++iFKt2dV/4ZKkUKqtlIu3KX19kcCAwEAAQ==",
    
    /** Client entity ID. */
    CLIENT_ID: "SimpleMslClient",
    
    /** Email/Password set. */
    EMAIL_PASSWORDS: [
        [ "kirito", "asuna" ],
        [ "chie", "shuhei" ],
        [ "hideki", "chi" ]
    ],
    /** Server administrator. */
    ADMIN_USERNAME: "kirito",
    
    /**
     * Query data: user, key.
     *
     * If the first value is not null, only the listed user has permission to
     * access the data value.
     */
    QUERY_DATA: [
        [ null, "cat" ],
        [ "chie", "alien" ],
        [ "kirito", "sword" ],
        [ null, "dog" ],
        [ null, "bird" ],
        [ null, "turtle" ],
        [ null, "fish" ],
        [ "chie", "bathhouse" ],
        [ "hideki", "computer" ],
    ],
};