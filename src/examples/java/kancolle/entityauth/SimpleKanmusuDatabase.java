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
package kancolle.entityauth;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>A simple in-memory Kanmusu ship database.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleKanmusuDatabase implements KanmusuDatabase {
    /**
     * @param type ship type.
     * @param name ship name.
     * @return the constructed ship identity for internal use.
     */
    private static String getIdentity(final String type, final String name) {
        return type + ":" + name;
    }
    
    /**
     * <p>Create a new simple Kanmusu ship database instance that is unaware of
     * any existing ships.</p>
     */
    public SimpleKanmusuDatabase() {
    }

    /**
     * <p>Set the Kanmusu ship data. This adds the ship if previously
     * unknown.</p>
     * 
     * @param type ship type.
     * @param name ship name.
     * @param state ship state.
     * @param passphrase ship passphrase.
     */
    public void setKanmusu(final String type, final String name, final Status state, final String passphrase) {
        if (state == null)
            throw new IllegalArgumentException("Kanmusu ship state cannot be null.");
        if (passphrase == null)
            throw new IllegalArgumentException("Kanmusu ship passphrase cannot be null.");
        
        final String identity = getIdentity(type, name);
        states.put(identity, state);
        passphrases.put(identity, passphrase);
    }

    /**
     * <p>Set the Kanmusu ship state. The ship must already be known.</p>
     * 
     * @param type ship type.
     * @param name ship name.
     * @param state ship state.
     * @throws IllegalStateException if the ship is not known.
     */
    public void setStatus(final String type, final String name, final Status state) {
        if (state == null)
            throw new IllegalArgumentException("Kanmusu ship state cannot be null.");
        
        final String identity = getIdentity(type, name);
        if (!states.containsKey(identity))
            throw new IllegalStateException("Kanmusu ship " + identity + " is not known.");
        states.put(identity, state);
    }
    
    /* (non-Javadoc)
     * @see kancolle.entityauth.KanmusuDatabase#getStatus(java.lang.String, java.lang.String)
     */
    @Override
    public Status getStatus(final String type, final String name) {
        final String identity = getIdentity(type, name);
        return states.get(identity);
    }
    
    /* (non-Javadoc)
     * @see kancolle.entityauth.KanmusuDatabase#getPassphrase(java.lang.String, java.lang.String)
     */
    @Override
    public String getPassphrase(final String type, final String name) {
        final String identity = getIdentity(type, name);
        return passphrases.get(identity);
    }

    /** Kanmusu ship states by identity. */
    private final Map<String,Status> states = new HashMap<String,Status>();
    /** Kanmusu ship passphrases by identity. */
    private final Map<String,String> passphrases = new HashMap<String,String>();
}
