/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;

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
public class UnauthenticatedSuffixedAuthenticationData extends EntityAuthenticationData {
    /** Key entity root. */
    private static final String KEY_ROOT = "root";
    /** Key entity suffix. */
    private static final String KEY_SUFFIX = "suffix";
    
    /** Identity concatenation character. */
    private static final String CONCAT_CHAR = ".";
    
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
     * instance from the provided MSL object.
     * 
     * @param unauthSuffixedAuthMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the MSL data.
     */
    public UnauthenticatedSuffixedAuthenticationData(final MslObject unauthSuffixedAuthMo) throws MslEncodingException {
        super(EntityAuthenticationScheme.NONE_SUFFIXED);
        try {
            root = unauthSuffixedAuthMo.getString(KEY_ROOT);
            suffix = unauthSuffixedAuthMo.getString(KEY_SUFFIX);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "unauthenticated suffixed authdata " + unauthSuffixedAuthMo, e);
        }
    }
    
    /**
     * <p>Returns the entity identity. This is equal to the root and suffix
     * strings moined with a period, e.g. {@code root.suffix}.</p>
     * 
     * @return the entity identity.
     */
    @Override
    public String getIdentity() {
        return root + CONCAT_CHAR + suffix;
    }

    /**
     * @return the entity identity root.
     */
    public String getRoot() {
       return root; 
    }
    
    /**
     * @return the entity identity suffix.
     */
    public String getSuffix() {
        return suffix;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) {
        final MslObject mo = encoder.createObject();
        mo.put(KEY_ROOT, root);
        mo.put(KEY_SUFFIX, suffix);
        return mo;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof UnauthenticatedSuffixedAuthenticationData)) return false;
        final UnauthenticatedSuffixedAuthenticationData that = (UnauthenticatedSuffixedAuthenticationData)obj;
        return super.equals(obj) && this.root.equals(that.root) && this.suffix.equals(that.suffix);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode() ^ root.hashCode() ^ suffix.hashCode();
    }

    /** Entity identity root. */
    private final String root;
    /** Entity identity suffix. */
    private final String suffix;
}
