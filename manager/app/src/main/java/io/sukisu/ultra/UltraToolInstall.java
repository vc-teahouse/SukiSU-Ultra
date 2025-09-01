package io.sukisu.ultra;

import com.topjohnwu.superuser.io.SuFile;

import static com.sukisu.ultra.ui.util.KsuCliKt.getKpmmgrPath;
import static com.sukisu.ultra.ui.util.KsuCliKt.getSuSFSDaemonPath;

import android.annotation.SuppressLint;

public class UltraToolInstall {
    private static final String OUTSIDE_KPMMGR_PATH = "/data/adb/ksu/bin/kpmmgr";
    private static final String OUTSIDE_SUSFSD_PATH = "/data/adb/ksu/bin/susfsd";
    @SuppressLint("SetWorldReadable")
    @SuppressWarnings("ResultOfMethodCallIgnored")
    public static void tryToInstall() {
        SuFile KpmmgrFile = new SuFile(OUTSIDE_KPMMGR_PATH);
        if (KpmmgrFile.exists()) {
            UltraShellHelper.CopyFileTo(getKpmmgrPath(), OUTSIDE_KPMMGR_PATH);
            KpmmgrFile.setReadable(true, false);
            KpmmgrFile.setExecutable(true, false);
        }
        SuFile SuSFSDaemonFile = new SuFile(OUTSIDE_SUSFSD_PATH);
        if (SuSFSDaemonFile.exists()) {
            UltraShellHelper.CopyFileTo(getSuSFSDaemonPath(), OUTSIDE_SUSFSD_PATH);
            SuSFSDaemonFile.setReadable(true, false);
            SuSFSDaemonFile.setExecutable(true, false);
        }
    }
}
