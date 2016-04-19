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
package com.netflix.msl.entityauth;

import java.util.Random;

import com.netflix.msl.entityauth.ProvisionedAuthenticationFactory.IdentityProvisioningService;
import com.netflix.msl.util.MslContext;

/**
 * <p>Test identity provisioning service.</p>
 * 
 * <p>This class creates entity identities from a prefix set equal to the
 * current time in milliseconds since the UNIX epoch and a suffix set equal a
 * random long number. The prefix and suffix are separated by a colon.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockIdentityProvisioningService implements IdentityProvisioningService {
    /**
     * <p>Create a new test identity provisioning service using the random
     * number generator from the provided MSL context.<p>
     * 
     * @param ctx MSL context.
     */
    public MockIdentityProvisioningService(final MslContext ctx) {
        this.ctx = ctx;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.ProvisionedAuthenticationFactory.IdentityProvisioningService#nextIdentity(com.netflix.msl.util.MslContext)
     */
    @Override
    public String nextIdentity() {
        final long now = ctx.getTime();
        final Random r = ctx.getRandom();
        final long suffix = r.nextLong();
        return Long.toString(now) + ":" + Long.toString(suffix);
    }
    
    /** MSL context. */
    private final MslContext ctx;
}
