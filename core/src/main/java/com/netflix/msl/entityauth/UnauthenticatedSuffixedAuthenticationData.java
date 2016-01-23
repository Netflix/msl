/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.entityauth;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;

/**
 * <p>Unauthenticated suffixed entity authentication data. This form of
 * authentication is used by entities that cannot provide any form of entity
 * authentication, and wish to share a root identity across themselves. This
 * scheme may also be useful in cases where multiple MSL stacks need to execute
 * independently on a single entity.</p>
 * 
 * <p>A suffixed scheme can expose an entity to cloning attacks of the root
 * identity as the master token sequence number will now be tied to the
 * root and suffix pair. This is probably acceptable for unauthenticated
 * entities anyway as they have no credentials to provide as proof of their
 * claimed identity.</p>
 * 
 * <p>Unauthenticated suffixed entity authentication data is represented as
 * {@code
 * unauthenticatedauthdata = {
 *   "#mandatory" : [ "root", "suffix" ],
 *   "root" : "string",
 *   "suffix" : "string"
 * }} where:
 * <ul>
 * <li>{@code root} is the entity identity root</li>
 * <li>{@code suffix} is the entity identity suffix</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@EqualsAndHashCode(callSuper = true)
@Getter
public class UnauthenticatedSuffixedAuthenticationData extends EntityAuthenticationData {
    /** JSON key entity root. */
    private static final String KEY_ROOT = "root";

    /** JSON key entity suffix. */
    private static final String KEY_SUFFIX = "suffix";

    /** Identity concatenation character. */
    private static final String CONCAT_CHAR = ".";

    /** Entity identity root. */
    private final String root;

    /** Entity identity suffix. */
    private final String suffix;

    /**
     * Construct a new unauthenticated suffixed entity authentication data
     * instance from the specified entity identity root and suffix.
     * 
     * @param root the entity identity root.
     * @param suffix the entity identity suffix.
     */
    public UnauthenticatedSuffixedAuthenticationData(final String root, final String suffix) {
        super(EntityAuthenticationScheme.NONE_SUFFIXED);
        this.root = root;
        this.suffix = suffix;
    }
    
    /**
     * Construct a new unauthenticated suffixed entity authentication data
     * instance from the provided JSON object.
     * 
     * @param unauthSuffixedAuthJO the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         representation.
     */
    UnauthenticatedSuffixedAuthenticationData(final JSONObject unauthSuffixedAuthJO) throws MslEncodingException {
        super(EntityAuthenticationScheme.NONE_SUFFIXED);
        try {
            root = unauthSuffixedAuthJO.getString(KEY_ROOT);
            suffix = unauthSuffixedAuthJO.getString(KEY_SUFFIX);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "unauthenticated suffixed authdata " + unauthSuffixedAuthJO.toString(), e);
        }
    }
    
    /**
     * <p>Returns the entity identity. This is equal to the root and suffix
     * strings joined with a period, e.g. {@code root.suffix}.</p>
     * 
     * @return the entity identity.
     */
    @Override
    public String getIdentity() {
        return root + CONCAT_CHAR + suffix;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData()
     */
    @Override
    public JSONObject getAuthData() throws MslEncodingException {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_ROOT, root);
            jsonObj.put(KEY_SUFFIX, suffix);
            return jsonObj;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "unauthenticated suffixed authdata", e);
        }
    }

}
