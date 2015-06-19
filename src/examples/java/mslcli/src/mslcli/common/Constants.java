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

package mslcli.common;

public final class Constants {

    /** Client entity ID */
    public static final String CLIENT_ID            = "simpleMslClient";

    /** Client user ID */
    public static final String CLIENT_USER_ID       = "simpleMslClientUserId";

    /** Client user email */
    public static final String CLIENT_USER_EMAIL    = "simpleMslClientUser@foo.com";

    /** Client user password */
    public static final String CLIENT_USER_PASSWORD = "simpleMslClientUserPassword";

    /** client's pre-shared encryption key */
    public static final String CLIENT_ENCR_PSK_HEX = "DBD68AC676BFBA6641CA6A4C771053AC";

    /** client's pre-shared HMAC key */
    public static final String CLIENT_HMAC_PSK_HEX = "93EDD1DDB772CFCE217931265DBDB39C2BCDEEAE1BA45D7972A1BA354E9A38C9";

    /** client's pre-shared key wrapping key */
    public static final String CLIENT_WRAP_PSK_HEX = "8A27C28E6DE751E69F4E963E5E3569FA";

    /** default asymmetrik key wrap exchange key pair id */
    public static final String DEFAULT_AWE_KEY_PAIR_ID = "default_awe_key_id";

    /** Default server port. */
    public static final int DEFAULT_PORT = 8080;

    /** MSL control timeout in milliseconds. */
    public static final int TIMEOUT_MS = 120 * 1000;

    /** Server entity ID. */
    public static final String SERVER_ID = "SimpleMslServer";

    /** Server entity RSA KEY ID. */
    public static final String SERVER_RSA_KEY_ID = "SimpleMslServerRsaKeyId";

    /** Server 2048-bit RSA public key. */
    public static final String SERVER_RSA_PUBKEY_B64 = 
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4feorj/FWQi8AhbvjK3G" +
        "L31ct6N+Ad/3FwqNsa4vAsfPmilLRx0DWhkxRycetmQEAa+1THyNCzobIduQE3UY" +
        "8NtdOiy1S3BtHDoiSNEITFPAs0l2OAZ2ZUv0KIr9sLWAznlXMclLOBXtLOQMCs2e" +
        "Ey4MO1m9uLywwc2SuAfoZe+wjEIauyoQK/M5miA0fbaEn4H+3m5aiP3Lb1X5Ss4b" +
        "4tuu0ENsO/ebgMx2ltZ4b9dkzA65DM6XxEC60jK1AW+/wvFb4+iPQqrA7mdiZWsp" +
        "zqMRTaAUDHKJo2LFBc6N0/wuTsXczHx6TYz5b2hrI6N+O7EEuxirAaU+xU7XEqv2" +
        "dQIDAQAB";

    /** Server 2048-bit RSA private key. */
    public static final String SERVER_RSA_PRIVKEY_B64 =
        "MIIEowIBAAKCAQEA4feorj/FWQi8AhbvjK3GL31ct6N+Ad/3FwqNsa4vAsfPmilL" +
        "Rx0DWhkxRycetmQEAa+1THyNCzobIduQE3UY8NtdOiy1S3BtHDoiSNEITFPAs0l2" +
        "OAZ2ZUv0KIr9sLWAznlXMclLOBXtLOQMCs2eEy4MO1m9uLywwc2SuAfoZe+wjEIa" +
        "uyoQK/M5miA0fbaEn4H+3m5aiP3Lb1X5Ss4b4tuu0ENsO/ebgMx2ltZ4b9dkzA65" +
        "DM6XxEC60jK1AW+/wvFb4+iPQqrA7mdiZWspzqMRTaAUDHKJo2LFBc6N0/wuTsXc" +
        "zHx6TYz5b2hrI6N+O7EEuxirAaU+xU7XEqv2dQIDAQABAoIBAQCh/pEv8knBbXCT" +
        "Muwi90VYMFAy2oNwRqZ2Hzu7gHr1TFd5VldAMP2BLwRT1SjAau0wZE3d+oCG5u4i" +
        "lKwyNsVdjnXESd7iqUOfc9G2UBzZ00UXgve8bG2eaxgrpJEAiO5Bl126NGu3VojE" +
        "oOw9JnFHoMBmIAzSDnvNRFoFkq25vQYAG45l9ZeNJv8mJaJG5+DNr6xbAE5PmROc" +
        "qyDL7RrfSqLxALhgZzLjVAP99fBGpOw2dCGKbQRzkUY0bojO19G3UUtf3HCI005i" +
        "kYHuAPdvu4+AteOvKdnDeMcT1pDxiNZKO+kXumIGYaKul2k6t9UpsRvCSmrthFZx" +
        "t8izGEehAoGBAPJ7YiK6W6NrgVyW5PaDtDRTrwZb/1G/K+jvCzHhV8/X5KfmjsaA" +
        "kT5m2WS1/rMwJoyc45GmTyyy6reGqLs5zAdUVicRKjZZaQnj00QXHRlmAEiDtx2T" +
        "b0cagryVf79Ma5FgyOMmqHjS5Pob7RvI4UyzVhR/pYmOrqxWGZgmRlxNAoGBAO6Q" +
        "lfXvbL9JKZ3HXIVbrXS5QToACnQf19QH05LPJG4jni7ycoTZFOiFmJodP5ca+Gug" +
        "TLlPaeVu52dlbXM1k32tV+0ui6vn0ErE8ZsXTjbZ/KInx4munWrLP8w3Ju8MHPPl" +
        "sEgmeggL0xBtt5BFRKus0SWwImZ9rIzxFXdbanbJAoGAOrP4LCQlr0iFht7ZC30T" +
        "EV/5DXcUNrwrazcD5M2DLsQ7jRJaGmBhyVOo6aLNyJ+tlXkd9tLmdBHUlR26l6kE" +
        "Zfna6ZZUO9glf8lyChf2aYGyK9wHZtecpwAaCoG+7ZcYq5dcyvE+9BFKcep02rcl" +
        "JCZ+fnPwpX6vdvVZOOZ7PjkCgYAGMv2imWkjA1ywe+i8kmhMey/luPCMmfM60EVA" +
        "MF/K+OP4ZlZxe06eyDHx90aav5mq+kxkGFsxGhOrTSht8Pt3LZT2VdpNSkXQW5PH" +
        "qvBeXoXBFPWLb10p1ERBI0HAvnjWIabWCSHsqZn/eEpn1lT1fRUmPJB4R1W/h9g9" +
        "9MMseQKBgBVp+6dU2Rdf1jzwzDH3IRDIVgWeqLlQucbVr/Fipjooioq6nxH2oHUB" +
        "2Qmq7FjYLKfKdaIRRoJhgeUhjVOVdjyIKVhLlBYpztr48jrMD5e4ykvKdAV2tlNv" +
        "B/b+6sSJkqh7Qm6CMO29m+dE2PJBZCzviTkBMOzyme71phGsh//C";

    /** Default DH parameters ID. */
    public static final String DEFAULT_DH_PARAMS_ID = "default1";

    /** Default DH Parameters */
    public static final String DEFAULT_DH_PARAM_P_HEX =
        "C2048E076B268761DB1427BA3AD98473D32B0ABDEE98C0827923426F294EDA3392BF0032A1D8092055B58BAA07586A7D3E271C39A8C891F5CEEA4DEBDFA6B023";
    public static final String DEFAULT_DH_PARAM_G_HEX = "02";

    // MSL Encryption Key
    public static final String MSL_ENCRYPTION_KEY_HEX = "1d58f3b8f747d16ab1093c4ca624eacf";

    // MSL HMAC Key
    public static final String MSL_HMAC_KEY_HEX       = "d7aebfd5879bb0e0ad016a4cf3cb3982f5ba260da520245bb42275bd7947370c";

    // MSL Key Wrapping Key
    public static final String MSL_WRAPPING_KEY_HEX   = "83b69a1580d323a2e79dd9b22626b3f6";

    // key exchanges
    public static final String KX_DH   = "dh" ; // Diffie-Hellman             Key Exchange
    public static final String KX_SWE  = "sw" ; // Symmetric  Wrapped         Key Exchange
    public static final String KX_AWE  = "aw" ; // Asymmetric Wrapped         Key Exchange
    public static final String KX_JWEL = "jwe"; // JSON Web Encryption Ladder Key Exchange
    public static final String KX_JWKL = "jwk"; // JSON Web Key        Ladder Key Exchange
}
