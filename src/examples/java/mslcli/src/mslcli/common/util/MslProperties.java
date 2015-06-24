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

package mslcli.common.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import static mslcli.common.Constants.*;

/**
 * Msl Properties
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class MslProperties {

    private static final String ENTITY_KX_SCHEMES = "entity.kx.schemes";

    private final Properties p;

    /**
     * Load properties from config file
     * TBD
     * Currently using hard-coded values
     *
     * @param configFile configuration file path
     */
    public static MslProperties getInstance(final String configFile) throws Exception {
        final Properties p = new Properties();
        p.setProperty(ENTITY_KX_SCHEMES + ".*", "JWK_LADDER JWE_LADDER DIFFIE_HELLMAN SYMMETRIC_WRAPPED ASYMMETRIC_WRAPPED");
        return new MslProperties(p);
    }

    private MslProperties(final Properties p) {
        if (p != null) {
            this.p = p;
        } else {
            throw new IllegalArgumentException("NULL Properties");
        }
    }

    /**
     * get the list of supported key exchange schemes for a give entity
     */
    public Set<String> getSupportedKeyExchangeSchemes(final String entityId) {
        String kxProp;
        kxProp = p.getProperty(ENTITY_KX_SCHEMES + "." + entityId);
        if (kxProp == null) {
            kxProp = p.getProperty(ENTITY_KX_SCHEMES + ".*");
            if (kxProp == null) return Collections.emptySet();
        }
        final Set<String> kx = new HashSet<String>();
        kx.addAll(Arrays.asList(kxProp.split("\\W+"))); // split by non-word characters, i.e. not [a-zA-Z_0-9]
        return Collections.unmodifiableSet(kx);
    }

    public Set<String> getSupportedKeyExchangeSchemes(final String entityId, final String userId) {
        return getSupportedKeyExchangeSchemes(entityId);
    }

    public int getNumMslControlThreads(final int defValue) {
        return defValue;
    }
}
