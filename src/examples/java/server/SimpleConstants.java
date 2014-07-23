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
package server;

import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;

/**
 * <p>Server constants.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleConstants {
    /** Default server port. */
    public static final int DEFAULT_PORT = 8080;
    /** MSL control timeout in milliseconds. */
    public static final int TIMEOUT_MS = 120 * 1000;
    
    /** Server entity ID. */
    public static final String SERVER_ID = "SimpleMslServer";
    /** Server 1024-bit RSA public key. */
    public static String RSA_PUBKEY_B64 = 
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALeJpiH5nikd3XeAo2rHjLJVVChM/p6l" +
        "VnQHyFh77w0Efbppi1P1pNy8BxJ++iFKt2dV/4ZKkUKqtlIu3KX19kcCAwEAAQ==";
    /** Server 1024-bit RSA private key. */
    public static String RSA_PRIVKEY_B64 =
        "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAt4mmIfmeKR3dd4Cj" +
        "aseMslVUKEz+nqVWdAfIWHvvDQR9ummLU/Wk3LwHEn76IUq3Z1X/hkqRQqq2Ui7c" +
        "pfX2RwIDAQABAkEAlB6YXq7uv0wE4V6Fg7VLjNhkNKn+itXwMW/eddp/D8cC4QbH" +
        "+0Ejt0e3F+YcY0RBsTUk7hz89VW7BtpjXRrU0QIhAOyjvUsihGzImq+WDiEWvnXX" +
        "lVaUaJXaaNElE37V/BE1AiEAxo25k2z2SDbFC904Zk020kISi95KNNv5ceEFcGu0" +
        "dQsCIQDUgj7uCHNv1b7ETDcoE+q6nP2poOFDIb7bgzY8wyH4uQIgf+02YO82auam" +
        "5HL+8KLVLHkXm/h31UDZoe66Y2lxlmsCIQC+cKulQATpKNnMV1RVtpH07A0+X72s" +
        "wpu2pmaRSYgw/w==";

    /** Email/Password set. */
    public static String[][] EMAIL_PASSWORDS = {
        { "kirito", "asuna" },
        { "chie", "shuhei" },
        { "hideki", "chi" },
    };
    /** Server administrator. */
    public static final String ADMIN_USERNAME = "kirito";
    
    /** User profiles. */
    public static Map<String,JSONObject> PROFILES = new HashMap<String,JSONObject>();
    static {
        final String KEY_NAME = "name";
        final String KEY_SEX = "sex";
        final String KEY_AGE = "age";
        final String KEY_EYES = "eyes";
        final String KEY_HAIR = "hair";
        final String KEY_HEIGHT = "height";
        final String KEY_WEIGHT = "weight";
        
        final JSONObject kirito = new JSONObject();
        kirito.put(KEY_NAME, "Kazuto Kirigaya");
        kirito.put(KEY_SEX, "male");
        kirito.put(KEY_AGE, 14);
        kirito.put(KEY_EYES, "brown");
        kirito.put(KEY_HAIR, "black");
        kirito.put(KEY_HEIGHT, 172);
        kirito.put(KEY_WEIGHT, 59);
        PROFILES.put("kirito", kirito);
        
        final JSONObject chie = new JSONObject();
        chie.put(KEY_NAME, "Chie Karita");
        chie.put(KEY_SEX, "female");
        chie.put(KEY_EYES, "brown");
        chie.put(KEY_HAIR, "brown");
        PROFILES.put("chie", chie);
        
        final JSONObject hideki = new JSONObject();
        hideki.put(KEY_NAME, "Hideki Motosuwa");
        hideki.put(KEY_SEX, "male");
        hideki.put(KEY_AGE, 19);
        hideki.put(KEY_EYES, "brown");
        hideki.put(KEY_HAIR, "black");
        PROFILES.put("hideki", hideki);
    }
    
    /**
     * Query data: user, key, value.
     * 
     * If the first value is not null, only the listed user has permission to
     * access the data value.
     */
    public static String[][] QUERY_DATA = {
        { null, "cat", "neko" },
        { "chie", "alien", "uchujin" },
        { "kirito", "sword", "tsurugi" },
        { null, "dog", "inu" },
        { null, "bird", "tori" },
        { null, "turtle", "kame" },
        { null, "fish", "sakana" },
        { "chie", "bathhouse", "notenburo" },
        { "hideki", "computer", "persocom" },
    };
}
