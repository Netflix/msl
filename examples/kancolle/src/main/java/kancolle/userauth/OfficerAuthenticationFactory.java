/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
package kancolle.userauth;

import java.util.Arrays;

import kancolle.KanColleMslError;
import kancolle.userauth.OfficerDatabase.Status;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.util.MslContext;

/**
 * <p>Each officer has an associated fingerprint SHA-256 hash that is used to
 * authenticate the officer.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class OfficerAuthenticationFactory extends UserAuthenticationFactory {
    /**
     * <p>Create a new officer authentication factory with the given officer
     * database.</p>
     * 
     * @param officers the officer database.
     */
    public OfficerAuthenticationFactory(final OfficerDatabase officers) {
        super(KanColleUserAuthenticationScheme.OFFICER);
        this.officers = officers;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
     */
    @Override
    public UserAuthenticationData createData(final MslContext ctx, final MasterToken masterToken, final MslObject userAuthMo) throws MslEncodingException {
        return new OfficerAuthenticationData(userAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#authenticate(com.netflix.msl.util.MslContext, java.lang.String, com.netflix.msl.userauth.UserAuthenticationData, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslUser authenticate(final MslContext ctx, final String identity, final UserAuthenticationData data, final UserIdToken userIdToken) throws MslUserAuthException {
        // Make sure we have the right kind of user authentication data.
        if (!(data instanceof OfficerAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + data.getClass().getName() + ".");
        final OfficerAuthenticationData oad = (OfficerAuthenticationData)data;
        
        // Check the officer status.
        final String name = oad.getName();
        final Status state = officers.getStatus(name);
        if (state == null)
            throw new MslUserAuthException(KanColleMslError.OFFICER_NOT_FOUND).setUserAuthenticationData(oad);
        switch (state) {
            case DISCHARGED:
                throw new MslUserAuthException(KanColleMslError.USERAUTH_OFFICER_DISCHARGED).setUserAuthenticationData(oad);
            case COURT_MARTIALED:
                throw new MslUserAuthException(KanColleMslError.USERAUTH_OFFICER_COURT_MARTIALED).setUserAuthenticationData(oad);
            case KIA:
                throw new MslUserAuthException(KanColleMslError.USERAUTH_OFFICER_KIA).setUserAuthenticationData(oad);
            case DECEASED:
                throw new MslUserAuthException(KanColleMslError.USERAUTH_OFFICER_DECEASED).setUserAuthenticationData(oad);
            default:
                break;
        }   
        
        // Verify the fingerprint.
        final byte[] fingerprint = oad.getFingerprint();
        final byte[] expectedFingerprint = officers.getFingerprint(name);
        if (expectedFingerprint == null || !Arrays.equals(fingerprint, expectedFingerprint))
            throw new MslUserAuthException(KanColleMslError.OFFICER_FINGERPRINT_INCORRECT).setUserAuthenticationData(oad);
        final MslUser user = new Officer(name);
        
        // If a user ID token was provided validate the user identities.
        if (userIdToken != null) {
            final MslUser uitUser = userIdToken.getUser();
            if (!user.equals(uitUser))
                throw new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " + user + "; uit user " + uitUser);
        }

        // Return the user.
        return user;
    }
    
    /** Officer database. */
    private final OfficerDatabase officers;
}
