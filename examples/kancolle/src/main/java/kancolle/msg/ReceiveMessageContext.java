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
package kancolle.msg;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MessageServiceTokenBuilder;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * <p>The receive message context is used when receiving messages. Since no
 * data will be returned this context does not specify any security
 * requirements.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ReceiveMessageContext implements MessageContext {
    @Override
    public Map<String, ICryptoContext> getCryptoContexts() {
        return Collections.emptyMap();
    }

    @Override
    public String getRemoteEntityIdentity() {
        return null;
    }

    @Override
    public boolean isEncrypted() {
        return false;
    }

    @Override
    public boolean isIntegrityProtected() {
        return false;
    }

    @Override
    public boolean isNonReplayable() {
        return false;
    }

    @Override
    public boolean isRequestingTokens() {
        return false;
    }

    @Override
    public String getUserId() {
        return null;
    }

    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
        return null;
    }

    @Override
    public MslUser getUser() {
        return null;
    }

    @Override
    public Set<KeyRequestData> getKeyRequestData() throws MslKeyExchangeException {
        return Collections.emptySet();
    }

    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) {
    }

    @Override
    public void write(final MessageOutputStream output) throws IOException {
        output.close();
    }

    @Override
    public MessageDebugContext getDebugContext() {
        return null;
    }
}
