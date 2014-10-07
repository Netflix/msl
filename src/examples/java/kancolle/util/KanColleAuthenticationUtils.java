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

import kancolle.KanColleMslError;
import kancolle.entityauth.KanColleEntityAuthenticationScheme;
import kancolle.entityauth.KanmusuAuthenticationData;
import kancolle.entityauth.KanmusuDatabase;
import kancolle.entityauth.NavalPortDatabase;
import kancolle.userauth.OfficerDatabase;
import kancolle.userauth.OfficerDatabase.Status;

import com.netflix.msl.MslError;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;

/**
 * <p>KanColle authentication utilities.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColleAuthenticationUtils implements AuthenticationUtils {
    /**
     * Create a new KanColle authentication utilities instance with the
     * provided entity and user databases.
     * 
     * @param ships Kanmusu ships database.
     * @param ports naval ports database.
     * @param officers officer database.
     */
    public KanColleAuthenticationUtils(final KanmusuDatabase ships, final NavalPortDatabase ports, final OfficerDatabase officers) {
        this.ships = ships;
        this.ports = ports;
        this.officers = officers;
    }
    
    /**
     * If the provided entity identity is a Kanmusu ship then check if it's
     * authentication has been revoked. A ship is revoked if it is unknown or
     * has been confirmed destroyed.
     * 
     * @param identity the Kanmusu ship identity.
     * @return a {@code MslError} if the identity identifies a Kanmusu ship
     *         that is revoked or {@code null} if it is not revoked or does not
     *         identify a Kanmusu ship.
     */
    public MslError isKanmusuRevoked(final String identity) {
        // Attempt to reconstruct the authentication data. This provides access
        // to the ship type and name.
        final KanmusuAuthenticationData kanmusu;
        try {
            kanmusu = new KanmusuAuthenticationData(identity);
        } catch (final IllegalArgumentException e) {
            // Not a Kanmusu. Not revoked.
            return null;
        }
        
        // Only revoke unknown or destroyed ships.
        final String type = kanmusu.getType();
        final String name = kanmusu.getName();
        final KanmusuDatabase.Status state = ships.getStatus(type, name);
        if (state == null)
            return KanColleMslError.KANMUSU_REVOKED_UNKNOWN;
        switch (state) {
            case DESTROYED:
                return KanColleMslError.KANMUSU_REVOKED_DESTROYED;
            default:
                return null;
        }
    }
    
    /**
     * Check if the identified naval port's authentication should be revoked. A
     * naval port is revoked if it is unknown or confirmed destroyed.
     * 
     * @param callsign the naval port callsign.
     * @return a {@code MslError} if the naval port identified by the callsign
     *         is revokved or unknown, {@code null} otherwise.
     */
    public MslError isNavalPortRevoked(final String callsign) {
        // Only revoke unknown or destroyed ports.
        final NavalPortDatabase.Status state = ports.getStatus(callsign);
        if (state == null)
            return KanColleMslError.NAVALPORT_REVOKED_UNKNOWN;
        switch (state) {
            case INACTIVE:
                return KanColleMslError.NAVALPORT_REVOKED_INACTIVE;
            case DESTROYED:
                return KanColleMslError.NAVALPORT_REVOKED_DESTROYED;
            default:
                return null;
        }
    }
    
    /**
     * Check if the specified officer's authentication should be revoked. An
     * officer is revoked if it is unknown, discharged, court martialed, or
     * dead.
     * 
     * @param name the officer name.
     * @return a {@code MslError} if the officer identified by the given name
     *         is revoked or unknown, {@code null} otherwise.
     */
    public MslError isOfficerRevoked(final String name) {
        // Revoke unknown or inactive officers.
        final Status status = officers.getStatus(name);
        if (status == null)
            return KanColleMslError.OFFICER_REVOKED_UNKNOWN;
        switch (status) {
            case DISCHARGED:
                return KanColleMslError.OFFICER_REVOKED_DISCHARGED;
            case COURT_MARTIALED:
                return KanColleMslError.OFFICER_REVOKED_COURT_MARTIALED;
            case KIA:
                return KanColleMslError.OFFICER_REVOKED_KIA;
            case DECEASED:
                return KanColleMslError.OFFICER_REVOKED_DECEASED;
            default:
                return null;
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isEntityRevoked(java.lang.String)
     */
    @Override
    public boolean isEntityRevoked(final String identity) {
        // Check for revocation. It may be a ship or a naval port.
        final MslError kanmusuRevoked = isKanmusuRevoked(identity);
        if (kanmusuRevoked != null) return true;
        final MslError navalPortRevoked = isNavalPortRevoked(identity);
        if (navalPortRevoked != null) return true;
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final EntityAuthenticationScheme scheme) {
        // Attempt to reconstruct the authentication data. This provides access
        // to the ship type and name.
        try {
            new KanmusuAuthenticationData(identity);
            return (KanColleEntityAuthenticationScheme.KANMUSU.equals(scheme)); 
        } catch (final IllegalArgumentException e) {
            // Not a Kanmusu. A ship. Fall through.
        }
        return KanColleEntityAuthenticationScheme.NAVAL_PORT.equals(scheme);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final UserAuthenticationScheme scheme) {
        // All configured user authentication schemes are permitted.
        return true;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.tokens.MslUser, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final MslUser user, final UserAuthenticationScheme scheme) {
        // All configured user authentication schemes are permitted.
        return true;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.keyx.KeyExchangeScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final KeyExchangeScheme scheme) {
        // All configured exchange schemes are permitted.
        return true;
    }

    /** Kanmusu ships. */
    private final KanmusuDatabase ships;
    /** Naval ports. */
    private final NavalPortDatabase ports;
    /** Officers. */
    private final OfficerDatabase officers;
}
