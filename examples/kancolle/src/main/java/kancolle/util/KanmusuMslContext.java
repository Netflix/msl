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
package kancolle.util;

import kancolle.crypto.KanColleCryptoContext;
import kancolle.entityauth.KanmusuAuthenticationData;
import kancolle.entityauth.KanmusuDatabase;
import kancolle.entityauth.NavalPortDatabase;
import kancolle.userauth.OfficerDatabase;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;

/**
 * <p>MSL context for Kanmusu ships.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanmusuMslContext extends KanColleMslContext {
    /** MSL crypto context key derivation secret suffix. */
    private static final String KEY_DERIVATION_SECRET = "KanColleKanmusuSecret";
    
    /**
     * Create a new Kanmusu MSL context for the specified ship.
     * 
     * @param type the ship type.
     * @param name the ship name.
     * @param ships Kanmusu ships database.
     * @param ports naval ports database.
     * @param officers officers database.
     * @throws MslCryptoException if there is an error accessing the entity
     *         authentication data identity.
     * @throws MslInternalException if the type or name are invalid.
     */
    public KanmusuMslContext(final String type, final String name, final KanmusuDatabase ships, final NavalPortDatabase ports, final OfficerDatabase officers) throws MslCryptoException {
        super(ships, ports, officers);
        
        // Entity authentication data.
        try {
            this.entityAuthData = new KanmusuAuthenticationData(type, name);
        } catch (final IllegalArgumentException e) {
            throw new MslInternalException("Invalid Kanmusu ship.", e);
        }
        
        // MSL crypto context individualized to this entity.
        final String identity = entityAuthData.getIdentity();
        final String secret = identity + ":" + KEY_DERIVATION_SECRET;
        this.mslCryptoContext = new KanColleCryptoContext(this, identity, secret);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslCryptoContext()
     */
    @Override
    public ICryptoContext getMslCryptoContext() throws MslCryptoException {
        return mslCryptoContext;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationData(com.netflix.msl.util.MslContext.ReauthCode)
     */
    @Override
    public EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode) {
        // We cannot provide new entity authentication data.
        if (reauthCode == ReauthCode.ENTITYDATA_REAUTH)
            return null;
        return entityAuthData;
    }

    /** Entity authentication data. */
    private final EntityAuthenticationData entityAuthData;
    /** MSL crypto context. */
    private final ICryptoContext mslCryptoContext;
}
