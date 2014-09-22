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
package kancolle;

import kancolle.entityauth.KanmusuDatabase;
import kancolle.entityauth.NavalPortDatabase;
import kancolle.userauth.OfficerDatabase;
import kancolle.util.ConsoleManager;
import kancolle.util.KanmusuMslContext;
import kancolle.util.NavalPortMslContext;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslInternalException;

/**
 * <p>KanColle Kanmusu ships and naval ports factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColleFactory {
    /**
     * <p>Create a new KanColle factory backed by the provided databases.</p>
     * 
     * @param ships ships database.
     * @param ports ports database.
     * @param officers officers database.
     */
    public KanColleFactory(final KanmusuDatabase ships, final NavalPortDatabase ports, final OfficerDatabase officers) {
        this.ships = ships;
        this.ports = ports;
        this.officers = officers;
    }
    
    /**
     * <p>Create a new naval port with the specified callsign.</p>
     * 
     * @param callsign port callsign.
     * @return a new naval port.
     */
    public NavalPort createNavalPort(final String callsign) {
        final NavalPortMslContext ctx = new NavalPortMslContext(callsign, ships, ports, officers);
        try {
            return new NavalPort(ctx, console);
        } catch (final MslCryptoException e) {
            throw new MslInternalException("Unable to retrieve entity authentication data identity.", e);
        }
    }
    
    /**
     * <p>Create a new Kanmusu ship with the specified type and name and origin
     * naval port.</p>
     * 
     * @param type ship type.
     * @param name ship name.
     * @param officer officer name.
     * @param fingerprint officer fingerprint.
     * @param port origin port.
     * @return a new Kanmusu ship.
     */
    public Kanmusu createKanmusu(final String type, final String name, final String officer, final byte[] fingerprint, final NavalPort port) {
        try {
            final KanmusuMslContext ctx = new KanmusuMslContext(type, name, ships, ports, officers);
            return new Kanmusu(ctx, officer, fingerprint, port, console);
        } catch (final MslCryptoException e) {
            throw new MslInternalException("Unable to retrieve entity authentication data identity.", e);
        }
    }
    
    /** Shared console manager. */
    private final ConsoleManager console = new ConsoleManager();
    /** Ships database. */
    private final KanmusuDatabase ships;
    /** Ports database. */
    private final NavalPortDatabase ports;
    /** Officers database. */
    private final OfficerDatabase officers;
}
