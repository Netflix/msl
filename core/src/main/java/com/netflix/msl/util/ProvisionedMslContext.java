/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.util;

/**
 * <p>This MSL context can be used as a base implementation for an entity that
 * must have its entity identity provisioned by the remote entity. The local
 * entity identity is tracked and when initialized or changed the MSL store
 * will be cleared.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class ProvisionedMslContext extends MslContext {
    /**
     * <p>Saves the local entity identity. If the value is being set for the
     * first time or has changed, the MSL store will be cleared.</p>
     * 
     * @param identity the local entity identity.
     */
    @Override
    public void setEntityIdentity(final String identity) {
        if (this.identity == null || !this.identity.equals(identity)) {
            final MslStore store = getMslStore();
            store.clearCryptoContexts();
            store.clearServiceTokens();
        }
        this.identity = identity;
    }
    
    /**
     * <p>Returns the local entity identity. Before the value has been set,
     * {@code null} will be returned.</p>
     * 
     * @return the local entity identity. May be {@code null}.
     */
    public String getEntityIdentity() {
        return identity;
    }
    
    /** Local entity identity. */
    private String identity = null;
}
