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
package kancolle.keyx;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;

/**
 * Key exchange factory comparator.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColleKeyxComparator implements Comparator<KeyExchangeFactory> {
    /** Scheme priorities. Lower values are higher priority. */
    private final Map<KeyExchangeScheme,Integer> schemePriorities = new HashMap<KeyExchangeScheme,Integer>();

    /**
     * Create a new key exchange factory comparator.
     */
    public KanColleKeyxComparator() {
        schemePriorities.put(KeyExchangeScheme.DIFFIE_HELLMAN, 0);
        schemePriorities.put(KeyExchangeScheme.ASYMMETRIC_WRAPPED, 1);
    }

    /* (non-Javadoc)
     * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
     */
    @Override
    public int compare(KeyExchangeFactory a, KeyExchangeFactory b) {
        final KeyExchangeScheme schemeA = a.getScheme();
        final KeyExchangeScheme schemeB = b.getScheme();
        final Integer priorityA = schemePriorities.get(schemeA);
        final Integer priorityB = schemePriorities.get(schemeB);
        return priorityA.compareTo(priorityB);
    }
}
