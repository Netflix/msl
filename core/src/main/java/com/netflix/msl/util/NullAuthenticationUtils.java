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

import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * <p>An authentication utilities implementation where all operations are
 * permitted.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class NullAuthenticationUtils implements AuthenticationUtils {
	/* (non-Javadoc)
	 * @see com.netflix.msl.util.AuthenticationUtils#isEntityRevoked(java.lang.String)
	 */
	@Override
	public boolean isEntityRevoked(final String identity) {
		return false;
	}

	/* (non-Javadoc)
	 * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.entityauth.EntityAuthenticationScheme)
	 */
	@Override
	public boolean isSchemePermitted(final String identity, final EntityAuthenticationScheme scheme) {
		return true;
	}

	/* (non-Javadoc)
	 * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.userauth.UserAuthenticationScheme)
	 */
	@Override
	public boolean isSchemePermitted(final String identity, final UserAuthenticationScheme scheme) {
		return true;
	}

	/* (non-Javadoc)
	 * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.tokens.MslUser, com.netflix.msl.userauth.UserAuthenticationScheme)
	 */
	@Override
	public boolean isSchemePermitted(final String identity, final MslUser user, final UserAuthenticationScheme scheme) {
	    return true;
	}

	/* (non-Javadoc)
	 * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.keyx.KeyExchangeScheme)
	 */
	@Override
	public boolean isSchemePermitted(final String identity, final KeyExchangeScheme scheme) {
	    return true;
	}
}
