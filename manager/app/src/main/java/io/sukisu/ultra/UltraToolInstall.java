package io.sukisu.ultra;

import static com.sukisu.ultra.ui.util.KsuCliKt.*;
import android.annotation.SuppressLint;

public class UltraToolInstall {
    private static final String OUTSIDE_SUSFSD_PATH = "/data/adb/ksu/bin/susfsd";

    @SuppressLint("SetWorldReadable")
    public static void tryToInstall() {
        String SuSFSDaemonPath = getSuSFSDaemonPath();
        if (UltraShellHelper.isPathExists(OUTSIDE_SUSFSD_PATH)) {
            UltraShellHelper.CopyFileTo(SuSFSDaemonPath, OUTSIDE_SUSFSD_PATH);
            UltraShellHelper.runCmd("chmod a+rx " + OUTSIDE_SUSFSD_PATH);
        }
    }
}
