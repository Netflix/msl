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

package mslcli.server;

import java.io.IOException;
import java.util.Properties;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netflix.msl.MslException;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.MslProperties;
import mslcli.common.util.SharedUtil;


/**
 * <p>
 *    An example Java MSL servlet that listens for requests from the example MSL client.
 * </p> 
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class SimpleServlet extends HttpServlet {
    /** for proper serialization */
    private static final long serialVersionUID = -4593207843035538485L;
    /** name of the servlet property for the configuration file path */
    private static final String CONFIG_FILE_PATH = "mslcli.cfg.file";
    /** name of the servlet property for the server entity identity */
    private static final String SERVER_ID = "mslcli.cfg.server.id";
    
    /**
     * <p>Initialize servlet instance and MSL server.</p>
     */
    @Override
    public void init(ServletConfig cfg) throws ServletException {
        super.init(cfg);

        final String configFile = cfg.getInitParameter(CONFIG_FILE_PATH);
        if (configFile == null)
            throw new ServletException("Missing Servlet Configuration Parameter " + CONFIG_FILE_PATH);

        final String serverId = cfg.getInitParameter(SERVER_ID);
        if (serverId == null)
            throw new ServletException("Missing Servlet Configuration Parameter " + SERVER_ID);

        final Properties prop;
        try {
            prop = SharedUtil.loadPropertiesFromFile(configFile);
        } catch (IOException e) {
            throw new ServletException("Error Loading Configuration File " + CONFIG_FILE_PATH, e);
        }

        final MslProperties mslProp = MslProperties.getInstance(prop);

        try {
            this.mslServer = new SimpleMslServer(mslProp, new CmdArguments(new String[] { CmdArguments.P_CFG, configFile, CmdArguments.P_EID, serverId } ));
        } catch (ConfigurationException e) {
            throw new ServletException(String.format("Server Configuration %s Validation Error", CONFIG_FILE_PATH), e);
        } catch (IllegalCmdArgumentException e) {
            throw new ServletException("Server Internal Initialization Error", e);
        }
    }
    
    /* (non-Javadoc)
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        // Allow requests from anywhere.
        resp.setHeader("Access-Control-Allow-Origin", "*");
        
        try {
            mslServer.processRequest(req.getInputStream(), resp.getOutputStream());
        } catch (ConfigurationException e) {
            log("Server Configuration Error: " + e.getMessage());
            throw new IOException("MslException", e);
        } catch (MslException e) {
            log(SharedUtil.getMslExceptionInfo(e));
            throw new IOException("MslException", e);
        }
    }
    
    /** MSL server. */
    private SimpleMslServer mslServer;
}
