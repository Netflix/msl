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

package mslcli.client;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;

import mslcli.client.msg.ClientRequestMessageContext;
import mslcli.client.msg.MessageConfig;
import mslcli.client.util.ClientMslContext;
import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.IllegalCmdArgumentRuntimeException;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.ConfigurationRuntimeException;
import mslcli.common.util.SharedUtil;

/**
 * <p>
 * MSL client. Hides some complexities of MSL core APIs and send/receive error handling.
 * Instance of thsi class is bound to a given client entity identity via an instance of
 * ClientMslConfig, which, in turn, is bound to a given client entity identity.
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class Client {

    /** timeout in milliseconds for processing request and composing response */
    private static final int TIMEOUT_MS = 120 * 1000;

    /**
     * Data object encapsulating payload and/or error header from the server
     */
    public static final class Response {
        /**
         * @param payload message application payload of the response, if any
         * @param errHeader MSL error header in the response, if any
         */
        private Response(final byte[] payload, final ErrorHeader errHeader) {
            this.payload = payload;
            this.errHeader = errHeader;
        }
        /**
         * @return application payload in the response, if any
         */
        public byte[] getPayload() {
            return payload;
        }
        /**
         * @return MSL error header in the response, if any
         */
        public ErrorHeader getErrorHeader() {
            return errHeader;
        }
        /** application payload */
        private final byte[] payload;
        /** MSL error header */
        private final ErrorHeader errHeader;
    }
        
    /**
     * @param appCtx application context
     * @param args command-line arguments (well, they may not be necessarily specified from the command line, just the same parsing scheme)
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public Client(final AppContext appCtx, final CmdArguments args)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        if (appCtx == null) {
            throw new IllegalArgumentException("NULL app context");
        }
        if (args == null) {
            throw new IllegalArgumentException("NULL arguments");
        }

        // Set app context.
        this.appCtx = appCtx;

        // Set args - create independent instance
        this.args = new CmdArguments(args);

        // Init MSL configuration
        this.mslCfg = new ClientMslConfig(appCtx, this.args);

        // Init up the MSL context
        this.mslCtx = new ClientMslContext(appCtx, mslCfg);

        // Set up the MSL Control
        this.mslCtrl = appCtx.getMslControl();

        // set up entity identity
        this.entityId = this.args.getEntityId();
    }

    /**
     * modify current args with the diff
     * @param diffArgs additional arguments to modify the existing configuration
     * @return copy of the current args
     * @throws IllegalCmdArgumentException
     */
    public CmdArguments modifyConfig(final CmdArguments diffArgs) throws IllegalCmdArgumentException {
       if (diffArgs.hasEntityId()) {
            throw new IllegalCmdArgumentException("Cannot Reset Entity Identity");
        }
        args.merge(diffArgs);
        appCtx.info(String.format("%s: %s", this, args.getParameters()));
        return new CmdArguments(args);
    }

    /**
     * @return current args as a string
     */
    public String getConfigInfo() {
        return args.getParameters();
    }

    /**
     * @return copy of the current args
     * @throws IllegalCmdArgumentException
     */
    public CmdArguments getConfig() throws IllegalCmdArgumentException {
        return new CmdArguments(args);
    }

    /**
     * Send single request.
     * @param request message payload to send
     * @return response encapsulating payload and/or error header
     * @throws ConfigurationException
     * @throws ExecutionException
     * @throws IllegalCmdArgumentException
     * @throws IOException
     * @throws InterruptedException
     * @throws MslException
     */
    public Response sendRequest(final byte[] request)
        throws ConfigurationException, ExecutionException, IllegalCmdArgumentException, IOException, InterruptedException, MslException
    {
        // set message mslProperties
        final MessageConfig cfg = new MessageConfig();
        cfg.userId = args.getUserId();
        cfg.isEncrypted = args.isEncrypted();
        cfg.isIntegrityProtected = args.isIntegrityProtected();
        cfg.isNonReplayable = args.isNonReplayable();

        // set remote URL
        final URL remoteUrl = args.getUrl();

        final MessageContext msgCtx = new ClientRequestMessageContext(mslCfg, cfg, request);

        final Future<MslChannel> f = mslCtrl.request(mslCtx, msgCtx, remoteUrl, TIMEOUT_MS);
        final MslChannel ch;
        ch = f.get();
        if (ch == null)
            return null;

        final ErrorHeader errHeader = ch.input.getErrorHeader();
        if (errHeader == null) {
            return new Response(SharedUtil.readIntoArray(ch.input), null);
        } else {
            return new Response(null, errHeader);
        }
    }

    /**
     * @return MSL Store
     */
    public MslStore getMslStore() {
        return mslCfg.getMslStore();
    }

    /**
     * save MSL Store
     * @throws IOException if cannot save MSL store
     */
    public void saveMslStore() throws IOException {
        mslCfg.saveMslStore();
    }

    /**
     * @return entity identity
     */
    public String getEntityId() {
        return entityId;
    }

    @Override
    public String toString() {
        return String.format("Client[%s]", entityId);
    }

    /** App context */
    private final AppContext appCtx;

    /** Args */
    private final CmdArguments args;

    /** MSL context */
    private final MslContext mslCtx;

    /** MSL config */
    private final ClientMslConfig mslCfg;

    /** MSL control */
    private final MslControl mslCtrl;

    /** Entity identity */
    private final String entityId;
}
