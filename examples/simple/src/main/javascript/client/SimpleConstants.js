/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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
(function(require, module) {
    var SimpleConstants = module.exports = {
        /** Default server port. */
        SERVER_PORT: 8080,
        /** MSL control timeout in milliseconds. */
        TIMEOUT_MS: 120 * 1000,

        /** Server entity ID. */
        SERVER_ID: "SimpleMslServer",
        /** Server 2048-bit RSA public key. */
        RSA_PUBKEY_B64:
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4feorj/FWQi8AhbvjK3G" +
        "L31ct6N+Ad/3FwqNsa4vAsfPmilLRx0DWhkxRycetmQEAa+1THyNCzobIduQE3UY" +
        "8NtdOiy1S3BtHDoiSNEITFPAs0l2OAZ2ZUv0KIr9sLWAznlXMclLOBXtLOQMCs2e" +
        "Ey4MO1m9uLywwc2SuAfoZe+wjEIauyoQK/M5miA0fbaEn4H+3m5aiP3Lb1X5Ss4b" +
        "4tuu0ENsO/ebgMx2ltZ4b9dkzA65DM6XxEC60jK1AW+/wvFb4+iPQqrA7mdiZWsp" +
        "zqMRTaAUDHKJo2LFBc6N0/wuTsXczHx6TYz5b2hrI6N+O7EEuxirAaU+xU7XEqv2" +
        "dQIDAQAB",


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
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleConstants'));
