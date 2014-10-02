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
package kancolle.app;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import kancolle.entityauth.CodeBook;
import kancolle.entityauth.FivePageCodeBook;
import kancolle.kc.KcStreamHandlerFactory;

/**
 * <p>KanColle application.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanColle {
    /** Kanmusu database resource name. */
    private static final String KANMUSU_DB = "/kancolle/db/kanmusu.properties";
    /** Officer database resource name. */
    private static final String OFFICER_DB = "/kancolle/db/officers.properties";
    /** Naval port database resource name. */
    private static final String PORT_DB = "/kancolle/db/ports.properties";
    
    /** Code book resource directory. */
    private static final String CODEBOOK_DIRECTORY = "/kancolle/codebooks/";
    
    /**
     * <p>Load a properties resource.</p>
     * 
     * @param filename properties filename.
     * @return the loaded properties.
     * @throws IOException if there is an error loading the properties file.
     */
    private static Properties loadProperties(final String filename) throws IOException {
        final Properties p = new Properties();
        final InputStream in = KanColle.class.getResourceAsStream(filename);
        if (in == null)
            throw new FileNotFoundException(filename);
        try {
            p.load(in);
            return p;
        } finally {
            in.close();
        }
    }
    
    /**
     * <p>Load a code book resource.</p>
     * 
     * @param filename code book filename.
     * @return the loaded code book.
     * @throws IOException if there is an error reading the code book file.
     */
    private static CodeBook loadCodebook(final String filename) throws IOException {
        final InputStream in = KanColle.class.getResourceAsStream(filename);
        if (in == null)
            throw new FileNotFoundException(filename);
        try {
            return new FivePageCodeBook(in);
        } finally {
            in.close();
        }
    }
    
    /**
     * <p>Return all file resources found under the specified directory.</p>
     * 
     * @param directory resource directory.
     * @return the file resources found in the directory.
     * @throws IOException if there is an error accessing the directory.
     * @throws URISyntaxException if there is an error accessing the directory.
     */
    private static String[] getSubResources(final String directory) throws IOException, URISyntaxException {
        final URL dir = KanColle.class.getResource(directory);
        if (dir == null)
            throw new FileNotFoundException(directory);
        
        // Handle file loads.
        if (dir.getProtocol().equals("file")) {
            final Set<String> result = new HashSet<String>();
            final String[] files =  new File(dir.toURI()).list();
            for (final String file : files)
                result.add(directory + (directory.endsWith("/") ? "" : "/")+ file);
            return result.toArray(new String[result.size()]);
        }
        
        // Handle JAR loads.
        if (dir.getProtocol().equals("jar")) {
            // Courtesy {@link http://stackoverflow.com/questions/6247144/how-to-load-a-folder-from-a-jar}
            final String jarPath = dir.getPath().substring(5, dir.getPath().indexOf('!'));
            final JarFile jar = new JarFile(URLDecoder.decode(jarPath, "UTF-8"));
            try {
                final Enumeration<JarEntry> entries = jar.entries();
                final Set<String> result = new HashSet<String>();
                while (entries.hasMoreElements()) {
                    final String name = entries.nextElement().getName();
                    if (name.startsWith(directory)) {
                        final String entry = name.substring(directory.length());
                        // Skip sub-directories.
                        final int checkSubdir = entry.indexOf('/');
                        if (checkSubdir >= 0)
                            continue;
                        result.add(name);
                    }
                }
                return result.toArray(new String[result.size()]);
            } finally {
                jar.close();
            }
        }
        
        // Fail.
        throw new IOException("Unable to retrieve contents of " + directory + " using " + dir.toURI() + ".");
    }
    
    /**
     * @param args command line arguments.
     * @throws IOException if there is an error loading the configuration data.
     * @throws URISyntaxException if there is an error accessing the code book
     *         directory.
     */
    public static void main(final String[] args) throws IOException, URISyntaxException {
        // Register KanColle stream handler factory. The system property is an
        // alternative mechanism included for informational purposes.
        URL.setURLStreamHandlerFactory(new KcStreamHandlerFactory());
        System.setProperty("java.protocol.handler.pkgs", "kancolle.kc");
        
        // Read the databases.
        final Properties kanmusuProps = loadProperties(KANMUSU_DB);
        final Properties officerProps = loadProperties(OFFICER_DB);
        final Properties portProps = loadProperties(PORT_DB);
        
        // Read the codebooks.
        final String[] codebookUrls = getSubResources(CODEBOOK_DIRECTORY);
        final Set<CodeBook> codebooks = new HashSet<CodeBook>();
        for (final String codebookUrl : codebookUrls) {
            final CodeBook codebook = loadCodebook(codebookUrl);
            codebooks.add(codebook);
        }
        
        // Create officers.
        
        
        // Create ports.
        
        // Create Kanmusu.
    }
}
