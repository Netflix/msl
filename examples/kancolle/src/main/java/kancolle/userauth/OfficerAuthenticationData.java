/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * <p>Officers are identified by their name and fingerprint hash.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "name", "fingerprint" ],
 *   "name" : "string",
 *   "fingerprint" : "binary"
 * }} where:
 * <ul>
 * <li>{@code name} is the officer's name</li>
 * <li>{@code fingerprint} is the SHA-256 hash of the officer's fingerprint</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class OfficerAuthenticationData extends UserAuthenticationData {
    /** Key name. */
    private static final String KEY_NAME = "name";
    /** Key fingerprint hash. */
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
     * MSL object.
     * 
     * @param officerMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the user
     *         authentication data.
     */
    public OfficerAuthenticationData(final MslObject officerMo) throws MslEncodingException {
        super(KanColleUserAuthenticationScheme.OFFICER);
        try {
            this.name = officerMo.getString(KEY_NAME);
            this.fingerprint = officerMo.getBytes(KEY_FINGERPRINT);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "officer authdata " + officerMo.toString(), e);
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
     * @see com.netflix.msl.userauth.UserAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        final MslObject mo = encoder.createObject();
        mo.put(KEY_NAME, name);
        mo.put(KEY_FINGERPRINT, fingerprint);
        return mo;
    }

    /** Officer name. */
    private final String name;
    /** Fingerprint hash. */
    private final byte[] fingerprint;
}
