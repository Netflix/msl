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
 * <p>A simple in-memory naval port database.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleNavalPortDatabase implements NavalPortDatabase {
    /**
     * <p>Create a new simple naval port database instance that is unaware of
     * any existing ports.</p>
     */
    public SimpleNavalPortDatabase() {
    }
    
    /**
     * <p>Set the naval port data. This adds the port if previously
     * unknown.</p>
     *
     * @param callsign port callsign.
     * @param state port state.
     * @param book port codebook.
     */
    public void setNavalPort(final String callsign, final Status state, final CodeBook book) {
        if (state == null)
            throw new IllegalArgumentException("Naval port state cannot be null.");
        if (book == null)
            throw new IllegalArgumentException("Naval port code book cannot be null.");
        
        states.put(callsign, state);
        books.put(callsign, book);
    }

    /**
     * <p>Set the naval port state. The naval port must already been known.</p>
     * 
     * @param callsign port callsign.
     * @param state port state.
     */
    public void setStatus(final String callsign, final Status state) {
        if (state == null)
            throw new IllegalArgumentException("Naval port state cannot be null.");
        
        if (!states.containsKey(callsign))
            throw new IllegalStateException("Naval port " + callsign + " is not known.");
        states.put(callsign, state);
    }

    /* (non-Javadoc)
     * @see kancolle.entityauth.NavalPortDatabase#getStatus(java.lang.String)
     */
    @Override
    public Status getStatus(final String callsign) {
        return states.get(callsign);
    }
    
    /* (non-Javadoc)
     * @see kancolle.entityauth.NavalPortDatabase#getCodeBook(java.lang.String)
     */
    @Override
    public CodeBook getCodeBook(final String callsign) {
        return books.get(callsign);
    }

    /** Naval port states by callsign. */
    private final Map<String,Status> states = new HashMap<String,Status>();
    /** Naval port code books by callsign. */
    private final Map<String,CodeBook> books = new HashMap<String,CodeBook>();
}
