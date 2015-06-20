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
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>
 *    An example Java MSL servlet that listens for requests from the example MSL client.
 * </p> 
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class SimpleServlet extends HttpServlet {
    private static final long serialVersionUID = -4593207843035538485L;
    
    /**
     * <p>Create a new servlet instance and initialize the simple MSL server.</p>
     */
    public SimpleServlet() {
        this.mslServer = new SimpleMslServer();
    }
    
    /* (non-Javadoc)
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        // Allow requests from anywhere.
        resp.setHeader("Access-Control-Allow-Origin", "*");
        
        mslServer.processRequest(req.getInputStream(), resp.getOutputStream());
    }
    
    /** MSL server. */
    private final SimpleMslServer mslServer;
}
