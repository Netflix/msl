package mslcli.cli;

import java.io.File;

public final class Util {

    public static void assertIsFile(String parent, String child) {
        File f = new File(parent, child);
        if (!f.isFile())
            throw new IllegalArgumentException(f.getPath() + "not a file");
    }

    public static void assertIsDir(String dir) {
        File f = new File(dir);
        if (!f.isDirectory())
            throw new IllegalArgumentException(f.getPath() + "not a directory");
    }

    private Util() { }
}
