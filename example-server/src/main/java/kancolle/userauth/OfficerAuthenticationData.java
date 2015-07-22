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
package kancolle.userauth;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * <p>Officers are identified by their name and fingerprint hash.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "name", "fingerprint" ],
 *   "name" : "string",
 *   "fingerprint" : "base64"
 * }} where:
 * <ul>
 * <li>{@code name} is the officer's name</li>
 * <li>{@code fingerprint} is the Base64-encoded SHA-256 hash of the officer's fingerprint</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class OfficerAuthenticationData extends UserAuthenticationData {
    /** JSON key name. */
    private static final String KEY_NAME = "name";
    /** JSON key fingerprint hash. */
    private static final String KEY_FINGERPRINT = "fingerprint";
    
    /**
     * <p>Create a new officer authentication data instance with the given name
     * and fingerprint SHA-256 hash.</p>
     * 
     * @param name the officer's name.
     * @param fingerprint the SHA-256 hash of the officer's fingerprint.
     */
    public OfficerAuthenticationData(final String name, final byte[] fingerprint) {
        super(KanColleUserAuthenticationScheme.OFFICER);
        this.name = name;
        this.fingerprint = fingerprint;
    }
    
    /**
     * Construct a new officer authentication data instance from the provided
     * JSON object.
     * 
     * @param officerJo the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the user
     *         authentication data.
     */
    public OfficerAuthenticationData(final JSONObject officerJo) throws MslEncodingException {
        super(KanColleUserAuthenticationScheme.OFFICER);
        try {
            this.name = officerJo.getString(KEY_NAME);
            this.fingerprint = DatatypeConverter.parseBase64Binary(officerJo.getString(KEY_FINGERPRINT));
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "officer authdata " + officerJo.toString(), e);
        }
    }
    
    /**
     * @return the officer's name.
     */
    public String getName() {
        return name;
    }
    
    /**
     * @return the SHA-256 hash of the officer's fingerprint.
     */
    public byte[] getFingerprint() {
        return fingerprint;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationData#getAuthData()
     */
    @Override
    public JSONObject getAuthData() throws MslEncodingException {
        try {
            final JSONObject jo = new JSONObject();
            jo.put(KEY_NAME, name);
            jo.put(KEY_FINGERPRINT, DatatypeConverter.printBase64Binary(fingerprint));
            return jo;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, this.getClass().getName(), e);
        }
    }

    /** Officer name. */
    private final String name;
    /** Fingerprint hash. */
    private final byte[] fingerprint;
}
