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

import java.util.Random;

import kancolle.crypto.KanColleCryptoContext;
import kancolle.entityauth.CodeBook;
import kancolle.entityauth.KanmusuDatabase;
import kancolle.entityauth.NavalPortAuthenticationData;
import kancolle.entityauth.NavalPortDatabase;
import kancolle.userauth.OfficerDatabase;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;

/**
 * <p>MSL context for naval ports.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class NavalPortMslContext extends KanColleMslContext {
    /** MSL crypto context key derivation secret suffix. */
    private static final String KEY_DERIVATION_SECRET = "KanColleNavalPortSecret";
    
    /**
     * Create a new naval port MSL context for the specified port.
     * 
     * @param callsign naval port callsign.
     * @param ships Kanmusu ships database.
     * @param ports naval ports database.
     * @param officers officers database.
     * @throws MslCryptoException if there is an error accessing the entity
     *         authentication data identity.
     * @throws MslInternalException if the callsign is invalid.
     */
    public NavalPortMslContext(final String callsign, final KanmusuDatabase ships, final NavalPortDatabase ports, final OfficerDatabase officers) {
        super(ships, ports, officers);
        
        // Entity authentication data is created on demand.
        this.callsign = callsign;
        this.ports = ports;
        
        // MSL crypto context individualized to this entity.
        final String secret = callsign + ":" + KEY_DERIVATION_SECRET;
        this.mslCryptoContext = new KanColleCryptoContext(this, callsign, secret);
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
    public synchronized EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode) {
        // We cannot provide new entity authentication data.
        if (reauthCode == ReauthCode.ENTITYDATA_REAUTH)
            return null;
        
        // When having to perform entity re-authentication, or if we don't yet
        // have entity authentication data, generate new entity authentication
        // data.
        if (entityAuthData == null || reauthCode != null) {
            // Grab the code book.
            final CodeBook book = ports.getCodeBook(callsign);
            if (book == null)
                throw new MslInternalException("No code book found for naval port " + callsign + ".");
            
            // Pick a random page and word.
            final Random r = getRandom();
            final int page = r.nextInt(book.getPageCount()) + 1;
            final int word = r.nextInt(book.getWordCount(page)) + 1;
            entityAuthData = new NavalPortAuthenticationData(callsign, page, word);
        }
        
        // Return the entity authentication data.
        return entityAuthData;
    }

    /** Entity authentication data. */
    private EntityAuthenticationData entityAuthData;

    /** Naval port callsign. */
    private final String callsign;
    /** Naval port database. */
    private final NavalPortDatabase ports;
    /** MSL crypto context. */
    private final ICryptoContext mslCryptoContext;
}
