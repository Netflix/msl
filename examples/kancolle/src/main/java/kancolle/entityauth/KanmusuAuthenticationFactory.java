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
package kancolle.entityauth;

import kancolle.KanColleMslError;
import kancolle.crypto.KanColleCryptoContext;
import kancolle.entityauth.KanmusuDatabase.Status;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;

/**
 * <p>Each Kanmusu ship is associated with a passphrase. The passphrase is used
 * with a {@link KanColleCryptoContext}.</p> 
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanmusuAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * Create a new Kanmusu authentication factory with the provided database.
     * 
     * @param database Kanmusu database.
     */
    public KanmusuAuthenticationFactory(final KanmusuDatabase database) {
        super(KanColleEntityAuthenticationScheme.KANMUSU);
        this.database = database;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException, MslEntityAuthException {
        return new KanmusuAuthenticationData(entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof KanmusuAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final KanmusuAuthenticationData kad = (KanmusuAuthenticationData)authdata;
        
        // Check ship status.
        final String type = kad.getType();
        final String name = kad.getName();
        final Status status = database.getStatus(type, name);
        if (status == null)
            throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "kanmusu " + kad.getIdentity()).setEntityAuthenticationData(kad);
        switch (status) {
            case DESTROYED:
                throw new MslEntityAuthException(KanColleMslError.ENTITYAUTH_KANMUSU_DESTROYED, "kanmusu " + kad.getIdentity()).setEntityAuthenticationData(kad);
            // We do not reject authentication for the other states.
            default:
                break;
        }
        
        // Return the crypto context.
        final String passphrase = database.getPassphrase(kad.getType(), kad.getName());
        if (passphrase == null)
            throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "kanmusu " + kad.getIdentity()).setEntityAuthenticationData(kad);
        final String identity = kad.getIdentity();
        return new KanColleCryptoContext(ctx, identity, passphrase);
    }
    
    /** Kanmusu database. */
    private final KanmusuDatabase database;
}
