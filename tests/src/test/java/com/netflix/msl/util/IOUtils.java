package com.netflix.msl.util;

import com.netflix.msl.entityauth.X509AuthenticationDataTest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Utility class to perform simple IO for testing, not necessarily for production use.
 */
public class IOUtils {

    public static X509Certificate readX509(String resourceName) throws CertificateException, IOException {
        final URL expiredUrl = X509AuthenticationDataTest.class.getResource(resourceName);
        final InputStream expiredInputStream = expiredUrl.openStream();
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate)factory.generateCertificate(expiredInputStream);
    }
    /**
     * Read in file from classpath and return contents.
     *
     * @param resourceName Name of file on the classpath to load and read
     * @return byte[] contents of file
     */
    public static byte[] readResource(String resourceName) throws IOException {
        // Avoid getClassloader() to make loading more compatible when running in tests
        InputStream resourceAsStream = IOUtils.class.getResourceAsStream(resourceName);
        return readAllBytes(resourceAsStream);
    }

    /**
     * Read in all bytes from provided InputStream.
     * Closes stream when done.
     *
     * @param inputStream to read from, should not be null
     * @return byte[] of bytes read in from inputStream
     * @throws IOException passed on from read's of the inputStream argument
     */
    public static byte[] readAllBytes(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            throw new IllegalArgumentException("inputStream should not be null");
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[1024];
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
