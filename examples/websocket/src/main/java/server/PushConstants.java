/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
package server;

import com.netflix.msl.msg.MessageInputStream;

import io.netty.util.AttributeKey;

/**
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PushConstants {
    /** Server entity ID. */
    public static final String SERVER_ID = "PushMslServer";
    /** Server 2048-bit RSA public key. */
    public static final String RSA_PUBKEY_B64 =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4feorj/FWQi8AhbvjK3G" +
        "L31ct6N+Ad/3FwqNsa4vAsfPmilLRx0DWhkxRycetmQEAa+1THyNCzobIduQE3UY" +
        "8NtdOiy1S3BtHDoiSNEITFPAs0l2OAZ2ZUv0KIr9sLWAznlXMclLOBXtLOQMCs2e" +
        "Ey4MO1m9uLywwc2SuAfoZe+wjEIauyoQK/M5miA0fbaEn4H+3m5aiP3Lb1X5Ss4b" +
        "4tuu0ENsO/ebgMx2ltZ4b9dkzA65DM6XxEC60jK1AW+/wvFb4+iPQqrA7mdiZWsp" +
        "zqMRTaAUDHKJo2LFBc6N0/wuTsXczHx6TYz5b2hrI6N+O7EEuxirAaU+xU7XEqv2" +
        "dQIDAQAB";
    /** Server 2048-bit RSA private key. */
    public static final String RSA_PRIVKEY_B64 =
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

    /** Timeout in milliseconds. */
    public static final int TIMEOUT_MS = 60000;

    /** Channel message input stream attribute key. */
    public static final AttributeKey<MessageInputStream> ATTR_KEY_MIS = AttributeKey.valueOf("mis");
}
