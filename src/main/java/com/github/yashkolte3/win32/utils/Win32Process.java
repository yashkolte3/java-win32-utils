package com.github.yashkolte3.win32.utils;

import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * The Class Win32Process.
 */
public class Win32Process extends Process {

    private HANDLE processHandle;
    private long processId;

    /**
     * Instantiates a new win 32 process.
     *
     * @param processHandle
     *     the process handle
     * @param processId
     *     the process id
     */
    public Win32Process(HANDLE processHandle, long processId) {
        this.processHandle = processHandle;
        this.processId = processId;
    }

    /**
     * Instantiates a new win 32 process.
     *
     * @param processHandle
     *     the process handle
     */
    public Win32Process(HANDLE processHandle) {
        this(processHandle, Kernel32.INSTANCE.GetProcessId(processHandle));
    }

    @Override
    public OutputStream getOutputStream() {
        return null;
    }

    @Override
    public InputStream getInputStream() {
        return null;
    }

    @Override
    public InputStream getErrorStream() {
        return null;
    }

    @Override
    public int waitFor() throws InterruptedException {
        Kernel32.INSTANCE.WaitForSingleObject(processHandle, Kernel32.INFINITE);
        return getExitCode();
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) throws InterruptedException {
        int returnVal = Kernel32.INSTANCE.WaitForSingleObject(processHandle, (int) Duration.of(timeout, unit.toChronoUnit()).toMillis());
        return returnVal == Kernel32.WAIT_OBJECT_0;
    }

    private int getExitCode() {
        IntByReference lpExitCode = new IntByReference();
        Kernel32.INSTANCE.GetExitCodeProcess(processHandle, lpExitCode);
        return lpExitCode.getValue();
    }

    @Override
    public int exitValue() {
        int exitCode = getExitCode();
        if (exitCode == Kernel32.STILL_ACTIVE) {
            throw new IllegalThreadStateException(
                    "The Win32 process is still active, hence exit value can't be returned. PID: " + toHandle().pid());
        }
        return exitCode;
    }

    @Override
    public void destroy() {
        Kernel32.INSTANCE.TerminateProcess(processHandle, 0);
    }

    @Override
    public ProcessHandle toHandle() {
        return ProcessHandle.allProcesses().filter(p -> p.pid() == processId).findAny().orElse(null);
    }

}