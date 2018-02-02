/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.netflix.msl.MslInternalException;

/**
 * Utility class to perform simple I/O for testing, not necessarily for
 * production use.
 */
public class IOUtils {
    /**
     * <p>Read an X.509 certificate from the specified resource.</p>
     * 
     * @param resourceName the resource name.
     * @return the X.509 certificate read from the resource.
     * @throws CertificateException if the resource does not contain a valid
     *         X.509 certificate.
     * @throws IOException if there is an error reading from the resource.
     */
    public static X509Certificate readX509(final String resourceName) throws CertificateException, IOException {
        final URL expiredUrl = IOUtils.class.getResource(resourceName);
        if (expiredUrl == null)
            throw new FileNotFoundException("Unable to load resource " + resourceName);
        final InputStream expiredInputStream = expiredUrl.openStream();
        final CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (final CertificateException e) {
            throw new MslInternalException("No X.509 certificate factory provider found.", e);
        }
        return (X509Certificate)factory.generateCertificate(expiredInputStream);
    }
    
    /**
     * <p>Read a resource and return its contents.</p>
     *
     * @param resourceName the resource name.
     * @return byte[] contents of file.
     */
    public static byte[] readResource(final String resourceName) throws IOException {
        // Avoid getClassloader() to make loading more compatible when running
        // in tests.
        final InputStream resourceAsStream = IOUtils.class.getResourceAsStream(resourceName);
        return readAllBytes(resourceAsStream);
    }

    /**
     * <p>Read and return all bytes from the provided InputStream. Closes the
     * input stream when done.</p>
     *
     * @param inputStream input stream to read from.
     * @return bytes read in from the input stream.
     * @throws IOException if there was an error reading from the input stream.
     */
    public static byte[] readAllBytes(final InputStream inputStream) throws IOException {
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        final byte[] data = new byte[16384];
        try {
            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }

            buffer.flush();
        } finally {
            inputStream.close();
        }

        return buffer.toByteArray();
    }
}
