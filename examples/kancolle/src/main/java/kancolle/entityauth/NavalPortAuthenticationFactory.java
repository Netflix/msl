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
import kancolle.entityauth.NavalPortDatabase.Status;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;

/**
 * <p>Each naval port is associated with a codebook. The codebook is used to
 * look up a secret word based off a page and word number. The word is used
 * with a {@link KanColleCryptoContext}.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class NavalPortAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * Create a new naval port authentication factory with the provided
     * database.
     * 
     * @param database naval port database.
     */
    public NavalPortAuthenticationFactory(final NavalPortDatabase database) {
        super(KanColleEntityAuthenticationScheme.NAVAL_PORT);
        this.database = database;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthJO) throws MslEncodingException, MslEntityAuthException {
        try {
            return new NavalPortAuthenticationData(entityAuthJO);
        } catch (final MslException e) {
            throw new MslEntityAuthException(KanColleMslError.NAVALPORT_ILLEGAL_IDENTITY, e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
     // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof NavalPortAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final NavalPortAuthenticationData npad = (NavalPortAuthenticationData)authdata;

        // Check port status.
        final String identity = npad.getIdentity();
        final Status status = database.getStatus(identity);
        if (status == null)
            throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "naval port " + npad.getIdentity()).setEntityAuthenticationData(npad);
        switch (status) {
            case INACTIVE:
                throw new MslEntityAuthException(KanColleMslError.ENTITYAUTH_NAVALPORT_INACTIVE, "naval port " + npad.getIdentity());
            case DESTROYED:
                throw new MslEntityAuthException(KanColleMslError.ENTITYAUTH_NAVALPORT_DESTROYED, "naval port " + npad.getIdentity()).setEntityAuthenticationData(npad);
            // We do not reject authentication for the other states.
            default:
                break;
        }
        
        // Return the crypto context.
        final int page = npad.getPage();
        final int word = npad.getWord();
        final CodeBook book = database.getCodeBook(identity);
        final String secret = book.getWord(page, word);
        if (secret == null)
            throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "naval port " + npad.getIdentity()).setEntityAuthenticationData(npad);
        return new KanColleCryptoContext(ctx, identity, secret);
    }
    
    /** Naval port database. */
    private final NavalPortDatabase database;
}
