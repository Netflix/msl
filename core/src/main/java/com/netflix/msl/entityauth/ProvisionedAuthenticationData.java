/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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

import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;

/**
 * <p>Provisioned entity authentication data. This form of authentication is
 * used by entities that cannot provide any form of entity authentication and
 * also want to delegate the generation or assignment of their identity to the
 * remote entity.</p>
 * 
 * <p>Provisioned entity authentication data is represented as
 * {@code
 * provisionedauthdata = {
 * }}</p>
 * 
 * <p>Until the entity identity has been provisioned, the entity identity will
 * be equal to the empty string.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProvisionedAuthenticationData extends EntityAuthenticationData {
    /**
     * Construct a new provisioned entity authentication data instance. 
     */
    public ProvisionedAuthenticationData() {
        super(EntityAuthenticationScheme.PROVISIONED);
    }
    
    /**
     * Construct a new provisioned entity authentication data instance from the
     * provided JSON object.
     * 
     * @param provisionedAuthMo the authentication data JSON object.
     */
    public ProvisionedAuthenticationData(final MslObject provisionedAuthMo) {
        super(EntityAuthenticationScheme.PROVISIONED);
    }
    
    /**
     * <p>Sets the entity identity.</p>
     * 
     * @param identity the entity identity.
     */
    void setIdentity(final String identity) {
        this.identity = identity;
    }
    
    /**
     * <p>Return the entity identity. Prior to provisioning, this function will
     * return the empty string. After an identity has been provisioned, this
     * function will return the provisioned identity.</p>
     * 
     * @see #setIdentity(String)
     */
    @Override
    public String getIdentity() {
        return identity;
    }

    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        return encoder.createObject();
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof ProvisionedAuthenticationData)) return false;
        return super.equals(obj);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode();
    }
    
    /** Entity identity. */
    private String identity = "";
}
