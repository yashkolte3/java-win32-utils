package com.github.yashkolte3.win32.utils;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Kernel32Util;
import com.sun.jna.platform.win32.Tlhelp32;
import com.sun.jna.platform.win32.Tlhelp32.PROCESSENTRY32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinBase.SECURITY_ATTRIBUTES;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.platform.win32.Wincon;
import com.sun.jna.platform.win32.Wtsapi32;
import com.sun.jna.platform.win32.Wtsapi32.WTS_SESSION_INFO;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Class Win32ProcessUtil. This implementation is influenced by
 * http://jinyazhou.com/launching-a-gui-application-from-a-windows-service-using-c-sharp.html
 *
 * @author yashk1
 */
public class Win32ProcessUtil {

    private static final Supplier<Integer> GET_LAST_ERROR = Kernel32.INSTANCE::GetLastError;
    private static final String UNABLE_TO_FIND_THE_CURRENT_ACTIVE_USER_TOKEN_WITH_ERROR_0 = "Unable to find the current active user token with error: {0}";
    private static final int CREATE_NO_WINDOW = 0x08000000;
    private static final int MAXIMUM_ALLOWED = 0x02000000;
    private static final int TOKEN_PRIMARY = 1;
    private static final int STARTF_USESTDHANDLES = 0x00000100;

    private static final Logger LOGGER = LoggerFactory.getLogger(Win32ProcessUtil.class);

    private Win32ProcessUtil() {
        // utility class.
    }

    /**
     * Creates a process with the user which started the {@code referenceProcess}. This method might be useful when the
     * parent process is launched in a non-interactive session (Session 0) e.g. using Windows Service but wants to
     * launch a GUI process in the interactive session in the context of current user. It tries to get the user token
     * for the process supplied using {@code referenceProcess} and launches a new process by executing the
     * {@code command} in the context of that user.
     *
     * @param command
     *     the command to execute.
     * @param workingDirectory
     *     the working directory
     * @param referenceProcess
     *     the reference process to perform user token lookup for. Defaults to "explorer.exe".
     * @param processRedirects
     *     the process redirects
     *
     * @return the process handle
     */
    public static synchronized Process createProcessAs(String command, Optional<Path> workingDirectory, Optional<String> referenceProcess,
            Optional<RedirectHandles> processRedirects) {
        AtomicReference<HANDLE> userToken = new AtomicReference<>();
        AtomicReference<HANDLE> referenceProcessHandle = new AtomicReference<>();
        AtomicReference<HANDLE> primaryToken = new AtomicReference<>();
        try {
            int referencePidD = findReferenceProcessId(referenceProcess.orElse("explorer.exe")).orElseThrow(
                    () -> new IllegalStateException(MessageFormat.format("Unable to find the reference process {0}", referenceProcess)));
            LOGGER.debug("Found reference PID:{}", referencePidD);
            referenceProcessHandle.set(getProcessHandle(referencePidD).orElseThrow(() -> new IllegalStateException(MessageFormat
                    .format("Unable to get handle the reference process {0} with error: {1}", referencePidD, GET_LAST_ERROR.get()))));
            LOGGER.debug("Found reference process handle:{}", referenceProcessHandle.get());
            userToken.set(getUserToken(referenceProcessHandle.get()).orElseThrow(() -> new IllegalStateException(MessageFormat
                    .format("Unable to find the user token for process: {0} with error: {1}", referencePidD, GET_LAST_ERROR.get()))));
            LOGGER.debug("User Token:{}", userToken.get());
            primaryToken.set(duplicateToken(userToken.get()).orElseThrow(() -> new IllegalStateException(MessageFormat
                    .format("Token duplication failed PrimaryToken: {0} with error: {1}", userToken.get(), GET_LAST_ERROR.get()))));
            LOGGER.debug("Duplicated token:{}", primaryToken.get());

            return createProcessAsUser(command,
                    primaryToken.get(),
                    workingDirectory,
                    processRedirects.or(() -> Optional.of(RedirectHandles.builder().build())));
        } finally {
            Kernel32.INSTANCE.CloseHandle(userToken.get());
            Kernel32.INSTANCE.CloseHandle(referenceProcessHandle.get());
            Kernel32.INSTANCE.CloseHandle(primaryToken.get());
        }
    }

    /**
     * Tries to find the sessions currently running on the system and filters the active one. An active session is
     * generally the one which has recently accessed the standard I/O. This method can be used to launch a process under
     * the context of the user which currently has an "active" session. Please note that this requires an elevated
     * privilege, "SE_TCB_PRIVILEGE", to be present.
     *
     * @param command
     *     the normalized command to execute.
     * @param workingDirectory
     *     the working directory
     * @param processRedirects
     *     the process redirects
     *
     * @return the process handle
     */
    public static synchronized Process createProcessInCurrentActiveSession(String command, Optional<Path> workingDirectory,
            Optional<RedirectHandles> processRedirects) {
        AtomicReference<HANDLE> userToken = new AtomicReference<>();
        AtomicReference<HANDLE> primaryToken = new AtomicReference<>();
        try {
            userToken.set(getActiveUserToken().orElseThrow(() -> new IllegalStateException(
                    MessageFormat.format(UNABLE_TO_FIND_THE_CURRENT_ACTIVE_USER_TOKEN_WITH_ERROR_0, GET_LAST_ERROR.get()))));

            LOGGER.debug("User Token:{}", userToken.get());
            primaryToken.set(duplicateToken(userToken.get()).orElseThrow(() -> new IllegalStateException(MessageFormat
                    .format("Token duplication failed PrimaryToken: {0} with error: {1}", userToken.get(), GET_LAST_ERROR.get()))));
            LOGGER.debug("Duplicated token:{}", primaryToken.get());

            return createProcessAsUser(command,
                    primaryToken.get(),
                    workingDirectory,
                    processRedirects.or(() -> Optional.of(RedirectHandles.builder().build())));
        } finally {
            Kernel32.INSTANCE.CloseHandle(userToken.get());
            Kernel32.INSTANCE.CloseHandle(primaryToken.get());
        }
    }

    /**
     * Find reference process ID using the process "name".
     *
     * @param referenceProcess
     *     the reference process
     *
     * @return the optional
     */
    public static OptionalInt findReferenceProcessId(String referenceProcess) {
        WinNT.HANDLE snapshot = Kernel32.INSTANCE.CreateToolhelp32Snapshot(Tlhelp32.TH32CS_SNAPPROCESS, new WinDef.DWORD(0));
        PROCESSENTRY32 processEntry = new PROCESSENTRY32();
        processEntry.dwSize = new WinDef.DWORD(processEntry.size());

        while (Kernel32.INSTANCE.Process32Next(snapshot, processEntry)) {
            if (Native.toString(processEntry.szExeFile).equalsIgnoreCase(referenceProcess)) {
                int referencePid = processEntry.th32ProcessID.intValue();
                LOGGER.info("{} process found! PID: {}", referenceProcess, referencePid);
                Kernel32.INSTANCE.CloseHandle(snapshot);
                return OptionalInt.of(referencePid);
            }
        }

        Kernel32.INSTANCE.CloseHandle(snapshot);
        return OptionalInt.empty();
    }

    /**
     * Gets the process handle.
     *
     * @param pid
     *     the PID.
     *
     * @return the process handle
     */
    public static Optional<HANDLE> getProcessHandle(int pid) {
        return Optional.ofNullable(Kernel32.INSTANCE.OpenProcess(WinNT.PROCESS_QUERY_INFORMATION, false, pid));
    }

    /**
     * Gets the USER TOKEN of the user which has launched the process.
     *
     * @param processHandle
     *     the process handle
     *
     * @return the user token
     */
    public static Optional<HANDLE> getUserToken(HANDLE processHandle) {
        LOGGER.debug("Trying to get user token");
        WinNT.HANDLEByReference token = new WinNT.HANDLEByReference();
        boolean result = Advapi32.INSTANCE
                .OpenProcessToken(processHandle, WinNT.TOKEN_DUPLICATE | WinNT.TOKEN_ASSIGN_PRIMARY | WinNT.TOKEN_QUERY, token);

        if (!result) {
            LOGGER.error("OpenProcessToken failed: {}", GET_LAST_ERROR.get());
            return Optional.empty();
        }

        LOGGER.debug("User Token found: {}", token.getValue());
        return Optional.ofNullable(token.getValue());
    }

    /**
     * Gets the active user token.
     *
     * @return the active user token
     */
    public static Optional<HANDLE> getActiveUserToken() {
        OptionalInt findActiveSession = findActiveSession();
        if (findActiveSession.isEmpty()) {
            LOGGER.error("Could not find any active session: {}", GET_LAST_ERROR.get());
            return Optional.empty();
        }
        WinNT.HANDLEByReference token = new WinNT.HANDLEByReference();

        boolean result = WtsApiExt.INSTANCE.WTSQueryUserToken(new DWORD(findActiveSession.getAsInt()), token);
        if (!result) {
            LOGGER.error("OpenProcessToken failed: {}", GET_LAST_ERROR.get());
            return Optional.empty();
        }

        LOGGER.debug("User Token found: {}", token.getValue());
        return Optional.ofNullable(token.getValue());

    }

    /**
     * Tries to find an active session from the currently running session which could be used to further find the User
     * under which context a new process shall be started.
     *
     * @return the optional of the session id.
     */
    public static OptionalInt findActiveSession() {
        IntByReference sessionCount = new IntByReference();
        PointerByReference sessionInfoPtr = new PointerByReference();
        if (Wtsapi32.INSTANCE.WTSEnumerateSessions(Wtsapi32.WTS_CURRENT_SERVER_HANDLE, 0, 1, sessionInfoPtr, sessionCount)) {
            Pointer sessionInfo = sessionInfoPtr.getValue();
            int count = sessionCount.getValue();
            Wtsapi32.WTS_SESSION_INFO arrRef = new Wtsapi32.WTS_SESSION_INFO(sessionInfo);
            Wtsapi32.WTS_SESSION_INFO[] sessions = (Wtsapi32.WTS_SESSION_INFO[]) arrRef.toArray(count);

            LOGGER.info("Found sessions: {}", Arrays.asList(sessions));
            for (WTS_SESSION_INFO session : sessions) {
                if (session.State == 0) {
                    LOGGER.info("Found an active session: {}", session);
                    return OptionalInt.of(session.SessionId);
                }
            }
            Wtsapi32.INSTANCE.WTSFreeMemory(sessionInfo);
        } else {
            LOGGER.info("Unable to enumerate current sessions... now trying to get the ActiveConsoleSessionId");
            DWORD wtsGetActiveConsoleSessionId = Kernel32Ext.INSTANCE.WTSGetActiveConsoleSessionId();
            LOGGER.info("Found an active session: {}", wtsGetActiveConsoleSessionId.intValue());
            return OptionalInt.of(wtsGetActiveConsoleSessionId.intValue());
        }
        LOGGER.error("Unable to find any current active session !");
        return OptionalInt.empty();
    }

    /**
     * Duplicate a token.
     *
     * @param tokenHandle
     *     the token handle
     *
     * @return the optional of new token handle.
     */
    public static Optional<HANDLE> duplicateToken(HANDLE tokenHandle) {
        LOGGER.info("Duplicating the user token");
        WinNT.HANDLEByReference token = new WinNT.HANDLEByReference();
        boolean result = Advapi32.INSTANCE.DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, null, TOKEN_PRIMARY, TOKEN_PRIMARY, token);

        if (!result) {
            LOGGER.error("DuplicateTokenEx failed: {}", GET_LAST_ERROR.get());
            return Optional.empty();
        }

        return Optional.of(token.getValue());
    }

    /**
     * Create process as a user.
     *
     * @param command
     *     the command to execute
     * @param token
     *     the token of user with which the process shall be created.
     * @param workingDirectory
     *     the working directory
     * @param processRedirects
     *     the process redirects
     *
     * @return the process handle
     */
    public static Process createProcessAsUser(String command, WinNT.HANDLE token, Optional<Path> workingDirectory,
            Optional<RedirectHandles> processRedirects) {
        final String environmentBlock = getEnvironmentVariablesBlock(token).orElseThrow(() -> new IllegalStateException(MessageFormat
                .format("Unable to find environment variables for user token {0} with error {1}", token, GET_LAST_ERROR.get())));
        final String workingDirString = workingDirectory.map(Path::toString).orElse(null);
        WinBase.STARTUPINFO si = new WinBase.STARTUPINFO();
        si.lpDesktop = "winsta0\\default";
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = processRedirects.map(RedirectHandles::getInputHandle).orElse(WinBase.INVALID_HANDLE_VALUE);
        si.hStdOutput = processRedirects.map(RedirectHandles::getOutputHandle).orElse(WinBase.INVALID_HANDLE_VALUE);
        si.hStdError = processRedirects.map(RedirectHandles::getErrorHandle).orElse(WinBase.INVALID_HANDLE_VALUE);
        WinBase.PROCESS_INFORMATION pi = new WinBase.PROCESS_INFORMATION();
        LOGGER.debug("Creating process with COMMAND: {}, ENVBLOCK: {}, WORKINGDIRECTORY: {}, STARTUPINFO: {}",
                command,
                environmentBlock,
                workingDirString,
                si);
        boolean result = Advapi32.INSTANCE.CreateProcessAsUser(token,
                null,
                command,
                new SECURITY_ATTRIBUTES(),
                new SECURITY_ATTRIBUTES(),
                true,
                WinBase.CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environmentBlock,
                workingDirString,
                si,
                pi);

        if (!result) {
            throw new IllegalStateException(
                    MessageFormat.format("Unable to execute command: {0} with error:{1}", command, GET_LAST_ERROR.get()));
        }
        LOGGER.info("Process started successfully pid: {}, with command:{}", pi.dwProcessId.longValue(), command);
        return new Win32Process(pi.hProcess, pi.dwProcessId.longValue());
    }

    /**
     * Gets the environment variables block.
     *
     * @param token
     *     the token of the user.
     *
     * @return the environment variables block
     */
    public static Optional<String> getEnvironmentVariablesBlock(WinNT.HANDLE token) {
        Map<String, String> environmentVariables = getEnvironmentVariables(token);
        String environmentBlock = Advapi32Util.getEnvironmentBlock(environmentVariables);
        LOGGER.trace("Converted Environment variables: {} to environment block {}", environmentVariables, environmentBlock);
        return Optional.ofNullable(environmentBlock);
    }

    /**
     * Gets the environment variables in key value pair for the given user token.
     *
     * @param token
     *     the token
     *
     * @return the environment variables
     */
    public static Map<String, String> getEnvironmentVariables(WinNT.HANDLE token) {
        final PointerByReference lpEnvironment = new PointerByReference();
        if (!UserEnv.INSTANCE.CreateEnvironmentBlock(lpEnvironment, token, false)) {
            LOGGER.error("Failed to get Environment variables for user token {} with error:{}", token, GET_LAST_ERROR.get());
            return Collections.emptyMap();
        }
        Pointer pointer = lpEnvironment.getValue();
        final Map<String, String> environmentVariables = Kernel32Util.getEnvironmentVariables(pointer, 0);
        if (!UserEnv.INSTANCE.DestroyEnvironmentBlock(pointer)) {
            LOGGER.error("Failed to destroy environment block for user token {} with error:{}", token, GET_LAST_ERROR.get());
        }
        LOGGER.trace("Found Environment variables {} for user token: {},", environmentVariables, token);
        return environmentVariables;
    }

    static interface UserEnv extends StdCallLibrary {

        public static UserEnv INSTANCE = Native.load("userenv", UserEnv.class, W32APIOptions.DEFAULT_OPTIONS);

        boolean CreateEnvironmentBlock(PointerByReference lpEnvironment, WinNT.HANDLE hToken, boolean bInherit);

        boolean DestroyEnvironmentBlock(Pointer lpEnvironment);
    }

    static interface Kernel32Ext extends Kernel32 {
        Kernel32Ext INSTANCE = Native.load("kernel32", Kernel32Ext.class, W32APIOptions.DEFAULT_OPTIONS);

        DWORD WTSGetActiveConsoleSessionId();

    }

    static interface WtsApiExt extends Wtsapi32 {

        WtsApiExt INSTANCE = Native.load("Wtsapi32", WtsApiExt.class, W32APIOptions.DEFAULT_OPTIONS);

        boolean WTSQueryUserToken(WinDef.DWORD SessionId, WinNT.HANDLEByReference token);

    }

    /**
     * The Class RedirectHandles.
     */
    public static class RedirectHandles {

        private HANDLE inHandle = WinBase.INVALID_HANDLE_VALUE;

        private HANDLE outHandle = WinBase.INVALID_HANDLE_VALUE;

        private HANDLE errHandle = WinBase.INVALID_HANDLE_VALUE;

        /**
         * Instantiates a new redirect handle.
         */
        private RedirectHandles() {
        }

        /**
         * Gets the error handle.
         *
         * @return the error handle
         */
        public HANDLE getErrorHandle() {
            return errHandle;
        }

        /**
         * Gets the input handle.
         *
         * @return the input handle
         */
        public HANDLE getInputHandle() {
            return inHandle;
        }

        /**
         * Gets the output handle.
         *
         * @return the output handle
         */
        public HANDLE getOutputHandle() {
            return outHandle;
        }

        /**
         * Builder.
         *
         * @return the redirect handle builder
         */
        public static RedirectHandleBuilder builder() {
            return new RedirectHandles().new RedirectHandleBuilder();
        }

        /**
         * The Class RedirectHandleBuilder.
         */
        public class RedirectHandleBuilder {

            /**
             * With input handle.
             *
             * @param inputHandle
             *     the input handle
             *
             * @return the redirect handle builder
             */
            public RedirectHandleBuilder withInputHandle(HANDLE inputHandle) {
                inHandle = inputHandle;
                return this;
            }

            /**
             * With output handle.
             *
             * @param outputHandle
             *     the output handle
             *
             * @return the redirect handle builder
             */
            public RedirectHandleBuilder withOutputHandle(HANDLE outputHandle) {
                outHandle = outputHandle;
                return this;
            }

            /**
             * With erro handle.
             *
             * @param errorHandle
             *     the error handle
             *
             * @return the redirect handle builder
             */
            public RedirectHandleBuilder withErroHandle(HANDLE errorHandle) {
                errHandle = errorHandle;
                return this;
            }

            /**
             * To current process.
             *
             * @return the redirect handle builder
             */
            public RedirectHandleBuilder toCurrentProcess() {
                inHandle = Kernel32.INSTANCE.GetStdHandle(Wincon.STD_INPUT_HANDLE);
                outHandle = Kernel32.INSTANCE.GetStdHandle(Wincon.STD_OUTPUT_HANDLE);
                errHandle = Kernel32.INSTANCE.GetStdHandle(Wincon.STD_ERROR_HANDLE);
                return this;
            }

            /**
             * Null redirect.
             *
             * @return the redirect handle builder
             */
            public RedirectHandleBuilder nullRedirect() {
                inHandle = WinBase.INVALID_HANDLE_VALUE;
                outHandle = WinBase.INVALID_HANDLE_VALUE;
                errHandle = WinBase.INVALID_HANDLE_VALUE;
                return this;
            }

            /**
             * Builds the.
             *
             * @return the redirect handles
             */
            public RedirectHandles build() {
                return RedirectHandles.this;
            }

        }
    }
}