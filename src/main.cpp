// SPDX-FileCopyrightText: Copyright 2025-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <utility>
#include <vector>
#include <CLI/CLI.hpp>
#include <SDL3/SDL_messagebox.h>

#include "common/arch.h"
#include "common/key_manager.h"
#include "common/logging/log.h"
#include "common/memory_patcher.h"
#include "common/path_util.h"
#include "core/debugger.h"
#include "core/emulator_settings.h"
#include "core/emulator_state.h"
#include "core/file_sys/fs.h"
#include "core/file_sys/saf_fs_backend.h"
#include "core/ipc/ipc.h"
#include "core/loader/elf.h"
#include "core/user_settings.h"
#include "common/singleton.h"
#include "emulator.h"
#include "input/controller.h"
#include "imgui/big_picture/big_picture.h"
#ifdef ENABLE_BACHATA_RUNTIME
#include "platform/bachata/runtime_client.h"
#endif

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <ucontext.h>
#include <cstdio>
#include <cstring>
#include <execinfo.h>
#include <fcntl.h>
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif
#if defined(__aarch64__)
#ifndef SYS_faccessat
#define SYS_faccessat 48
#endif
#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#endif

static struct sigaction g_old_sigsys_action;
// Alternate signal stack so the handler can run even if the crashing thread's
// stack is exhausted. SA_ONSTACK (set below) routes the signal here.
static std::array<unsigned char, 65536> g_sigsys_altstack alignas(16) {};

#ifdef SHADPS4_ENABLE_FEX_GUEST_CPU
#include "core/fex/fex_guest_engine.h"
#endif

#if defined(__aarch64__)
// Android app seccomp traps faccessat2 (issue #17, exit 159). Replay as faccessat
// when no FEX guest thread owns the SIGSYS. Kernel ABI: x0 = 0 or -errno.
static bool BachataEmulateSeccompFaccessat2(siginfo_t* info, ucontext_t* ctx) {
    if (info == nullptr || ctx == nullptr) {
        return false;
    }
    if (info->si_code != SYS_SECCOMP || info->si_syscall != SYS_faccessat2) {
        return false;
    }
    register long x8 asm("x8") = SYS_faccessat;
    register long x0 asm("x0") = static_cast<long>(ctx->uc_mcontext.regs[0]);
    register long x1 asm("x1") = static_cast<long>(ctx->uc_mcontext.regs[1]);
    register long x2 asm("x2") = static_cast<long>(ctx->uc_mcontext.regs[2]);
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    ctx->uc_mcontext.regs[0] = static_cast<uint64_t>(x0);
    ctx->uc_mcontext.pc += 4;
    return true;
}
#endif

static void BachataSigsysHandler(int signo, siginfo_t* info, void* uctx) {
    ucontext_t* _ctx = reinterpret_cast<ucontext_t*>(uctx);
    uint64_t pc = 0, sp = 0, x8 = 0;
    uint64_t x0 = 0, x1 = 0, x2 = 0, x3 = 0, x4 = 0, x5 = 0, x29 = 0, x30 = 0;
#ifdef __aarch64__
    if (_ctx) {
        pc = _ctx->uc_mcontext.pc;
        sp = _ctx->uc_mcontext.sp;
        x8 = _ctx->uc_mcontext.regs[8];
        x0 = _ctx->uc_mcontext.regs[0];
        x1 = _ctx->uc_mcontext.regs[1];
        x2 = _ctx->uc_mcontext.regs[2];
        x3 = _ctx->uc_mcontext.regs[3];
        x4 = _ctx->uc_mcontext.regs[4];
        x5 = _ctx->uc_mcontext.regs[5];
        x29 = _ctx->uc_mcontext.regs[29];
        x30 = _ctx->uc_mcontext.regs[30];
    }
#endif

    // Best-effort guest RIP/syscall capture. On the FEX guest CPU path, mid-JIT
    // guest state lives in SRA host regs, but at a host syscall boundary the
    // CurrentFrame holds the spilled guest RIP and RAX. Returns false (leaves
    // guest_rip/guest_syscall as the "unavailable" sentinels) when no FEX thread
    // is active (e.g. crash during host-only init or in a non-FEX host library).
    uint64_t guest_rip = 0;
    uint64_t guest_syscall = 0;
    bool have_guest = false;
#ifdef SHADPS4_ENABLE_FEX_GUEST_CPU
    have_guest = Core::Fex::BachataQueryGuestRipSyscall(&guest_rip, &guest_syscall);
#endif

#if defined(__aarch64__)
    if (!have_guest && BachataEmulateSeccompFaccessat2(info, _ctx)) {
        return;
    }
#endif

    char buf[1024];
    int len = snprintf(buf, sizeof(buf),
        "[Bachata.FEX.SIGSYS] signo=%d\n"
        "[Bachata.FEX.SIGSYS] code=%d\n"
        "[Bachata.FEX.SIGSYS] errno=%d\n"
        "[Bachata.FEX.SIGSYS] syscall=%d\n"
        "[Bachata.FEX.SIGSYS] arch=0x%x\n"
        "[Bachata.FEX.SIGSYS] call_addr=0x%lx\n"
        "[Bachata.FEX.SIGSYS] host_pc=0x%lx\n"
        "[Bachata.FEX.SIGSYS] host_x8=%lu\n"
        "[Bachata.FEX.SIGSYS] guest_rip=0x%lx\n"
        "[Bachata.FEX.SIGSYS] guest_syscall=%s%lu\n"
        "[Bachata.FEX.SIGSYS] host_sp=0x%lx host_x0=0x%lx host_x1=0x%lx host_x2=0x%lx host_x3=0x%lx host_x4=0x%lx host_x5=0x%lx host_x29=0x%lx host_x30=0x%lx pid=%d tid=%ld\n",
        info ? info->si_signo : signo,
        info ? info->si_code : 0,
        info ? info->si_errno : 0,
        info ? info->si_syscall : -1,
        info ? info->si_arch : 0,
        info ? (unsigned long)(uintptr_t)info->si_call_addr : 0UL,
        (unsigned long)pc,
        (unsigned long)x8,
        (unsigned long)guest_rip,
        have_guest ? "" : "unavailable ",
        (unsigned long)guest_syscall,
        (unsigned long)sp, (unsigned long)x0, (unsigned long)x1, (unsigned long)x2,
        (unsigned long)x3, (unsigned long)x4, (unsigned long)x5, (unsigned long)x29,
        (unsigned long)x30, ::getpid(), (long)::syscall(SYS_gettid));

    if (len > 0) {
        ::write(STDERR_FILENO, buf, static_cast<size_t>(len));
    }

    if (g_old_sigsys_action.sa_flags & SA_SIGINFO) {
        if (g_old_sigsys_action.sa_sigaction) {
            g_old_sigsys_action.sa_sigaction(signo, info, uctx);
        }
    } else if (g_old_sigsys_action.sa_handler != SIG_DFL && g_old_sigsys_action.sa_handler != SIG_IGN) {
        g_old_sigsys_action.sa_handler(signo);
    } else {
        signal(signo, SIG_DFL);
        raise(signo);
    }
}

static void InstallBachataSigsysTrap() {
    // Install an alternate stack first: SA_ONSTACK redirects the signal here so
    // the handler runs even on an exhausted main stack.
    stack_t ss{};
    ss.ss_sp = g_sigsys_altstack.data();
    ss.ss_size = g_sigsys_altstack.size();
    ss.ss_flags = 0;
    sigaltstack(&ss, nullptr);

    struct sigaction sa{};
    sa.sa_sigaction = BachataSigsysHandler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, &g_old_sigsys_action);
}

#ifdef ENABLE_BACHATA_RUNTIME
namespace {
std::shared_ptr<Core::FileSys::SafBrokerClient> BachataSafClient() {
    if (Core::FileSys::g_saf_socket.empty() || Core::FileSys::g_saf_token.empty()) {
        return nullptr;
    }
    return std::make_shared<Core::FileSys::SafBrokerClient>(Core::FileSys::g_saf_socket,
                                                            Core::FileSys::g_saf_token);
}

// A PS4 eboot is usually a SELF container (magic 4F 15 3D 1D) wrapping the real ELF, and
// occasionally a bare ELF (7F 45 4C 46). Accept both so broker-delivered content is not
// rejected merely for being a SELF; the loader decrypts SELF containers itself.
bool BachataIsExecutable(const std::filesystem::path& path) {
    if (path.empty()) {
        return false;
    }
    Core::Loader::Elf probe;
    probe.Open(path);
    return probe.IsSelfFile() || probe.IsElfFile();
}

// The Android frontend can serve game content either from a real directory tree staged under
// --override-root ("direct runtime") or through the SAF broker when the content lives on
// external storage. Returns true when an executable eboot is reachable from either source.
bool BachataContentReachable(const std::filesystem::path& override_root,
                             const std::filesystem::path& direct_hint) {
    if (BachataIsExecutable(direct_hint)) {
        return true;
    }
    if (!override_root.empty() && BachataIsExecutable(override_root / "eboot.bin")) {
        return true;
    }
    auto client = BachataSafClient();
    if (!client) {
        return false;
    }
    const auto mirror = Core::FileSys::SafMirrorRoot() / "probe";
    Core::FileSys::SafFsBackend backend(client, "/app0", mirror);
    return BachataIsExecutable(backend.Resolve("/app0/eboot.bin"));
}
} // namespace
#endif

#ifdef ENABLE_BACHATA_RUNTIME
static void BachataCrashHandler(int signo, siginfo_t* info, void* uctx) {
    const int fd = ::open("/sdcard/Download/bachata-crash.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        char hdr[160];
        const int len = ::snprintf(hdr, sizeof(hdr), "\n=== signal %d errno %d pid %d thread %ld ===\n",
                                   signo, info != nullptr ? info->si_errno : 0,
                                   static_cast<int>(::getpid()), static_cast<long>(::syscall(SYS_gettid)));
        if (len > 0) {
            ::write(fd, hdr, static_cast<size_t>(len));
        }
        void* frames[64];
        const int count = ::backtrace(frames, 64);
        ::backtrace_symbols_fd(frames, count, fd);
        ::close(fd);
    }
    signal(signo, SIG_DFL);
    raise(signo);
}

static void InstallBachataCrashHandlers() {
    struct sigaction sa{};
    sa.sa_sigaction = BachataCrashHandler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    for (const int sig : {SIGTRAP, SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE}) {
        sigaction(sig, &sa, nullptr);
    }
}
#endif

int main(int argc, char* argv[]) {
    InstallBachataSigsysTrap();
#ifdef ENABLE_BACHATA_RUNTIME
    InstallBachataCrashHandlers();
#endif
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

#if defined(__APPLE__) && defined(ARCH_X86_64)
    // KosmicKrisp only supports Apple Silicon. Check that we are not running on an Intel Mac.
    int sysctl_ret = 0;
    size_t sysctl_size = sizeof(sysctl_ret);
    sysctlbyname("sysctl.proc_translated", &sysctl_ret, &sysctl_size, nullptr, 0);
    if (sysctl_ret != 1) {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "shadPS4",
                                 "shadPS4 only supports Apple Silicon Macs.", nullptr);
        std::cout << "shadPS4 only supports Apple Silicon Macs." << std::endl;
        return -1;
    }
#endif

    CLI::App app{"shadPS4 Emulator CLI"};

    // ---- CLI state ----
    std::optional<std::string> gamePath;
    std::vector<std::string> gameArgs;
    std::optional<std::filesystem::path> overrideRoot;
#ifdef ENABLE_BACHATA_RUNTIME
    std::optional<std::filesystem::path> bachataSocket;
    std::optional<std::filesystem::path> bachataStorageRoot;
    std::optional<std::filesystem::path> patchSessionPath;
    std::optional<std::string> bachataSafSocket;
    std::optional<std::string> bachataSafToken;
#endif
    std::optional<int> waitPid;
    bool waitForDebugger = false;

    std::optional<std::string> fullscreenStr;
    bool ignoreGamePatch = false;
    bool showFps = false;
    bool configClean = false;
    bool configGlobal = false;
    bool bigPicture = false;

    std::optional<std::filesystem::path> addGameFolder;
    std::optional<std::filesystem::path> setAddonFolder;
    std::optional<std::string> patchFile;

    // ---- Options ----
    app.add_option("-g,--game", gamePath, "Game path or ID");
    app.add_option("-p,--patch", patchFile, "Patch file to apply");
    app.add_flag("-i,--ignore-game-patch", ignoreGamePatch,
                 "Disable automatic loading of game patches");

    app.add_flag("-b,--big-picture", bigPicture, "Start in Big Picture Mode");

    // FULLSCREEN: behavior-identical
    app.add_option("-f,--fullscreen", fullscreenStr, "Fullscreen mode (true|false)");

    app.add_option("--override-root", overrideRoot)->check(CLI::ExistingDirectory);
#ifdef ENABLE_BACHATA_RUNTIME
    app.add_option("--bachata-socket", bachataSocket, "Bachata Android runtime control socket");
    app.add_option("--bachata-storage-root", bachataStorageRoot,
                   "Bachata Android app-private storage root")
        ->check(CLI::ExistingDirectory);
    app.add_option("--patch-session", patchSessionPath,
                   "Managed patch launch session file (frozen snapshot staged by Android)");
    app.add_option("--bachata-saf-socket", bachataSafSocket,
                   "Android SAF broker abstract socket name");
    app.add_option("--bachata-saf-token", bachataSafToken, "Android SAF broker session token");
#endif

    app.add_flag("--wait-for-debugger", waitForDebugger);
    app.add_option("--wait-for-pid", waitPid);

    app.add_flag("--show-fps", showFps);
    app.add_flag("--config-clean", configClean);
    app.add_flag("--config-global", configGlobal);
    app.add_flag("--log-append", Common::Log::g_should_append);

    app.add_option("--add-game-folder", addGameFolder)->check(CLI::ExistingDirectory);
    app.add_option("--set-addon-folder", setAddonFolder)->check(CLI::ExistingDirectory);

    // ---- Capture args after `--` verbatim ----
    app.allow_extras();
    app.parse_complete_callback([&]() {
        const auto& extras = app.remaining();
        if (!extras.empty()) {
            gameArgs = extras;
        }
    });

    // ---- No-args behavior ----
    if (argc == 1) {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "shadPS4",
                                 "This is a CLI application. Please use the QTLauncher for a GUI:\n"
                                 "https://github.com/shadps4-emu/shadps4-qtlauncher/releases",
                                 nullptr);
        std::cout << app.help();
        return -1;
    }

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

#ifdef ENABLE_BACHATA_RUNTIME
    auto runtime_client = Platform::Bachata::RuntimeClient::Disabled();
    if (bachataSocket.has_value()) {
        if (!bachataStorageRoot.has_value() ||
            !Platform::Bachata::ValidateSocketPath(*bachataSocket, *bachataStorageRoot)) {
            std::cerr << "--bachata-socket must be absolute and inside --bachata-storage-root\n";
            return 1;
        }
        auto connected = Platform::Bachata::RuntimeClient::Connect(*bachataSocket);
        if (!connected.has_value() || !connected->SendHello()) {
            std::cerr << "Failed to connect Bachata runtime socket\n";
            return 1;
        }
        runtime_client = std::move(*connected);
        if (!runtime_client.SendStarting()) {
            std::cerr << "Failed to send Bachata Starting event\n";
            return 1;
        }
    }
    if (bachataStorageRoot.has_value()) {
        // The storage root drives the managed patch layout: patches/repository/<id> and
        // patches/session/<serial>.json both live under it.
        MemoryPatcher::g_managed_storage_root = *bachataStorageRoot;
        // Android has no writable /tmp; stage SAF fd symlinks inside app-private storage.
        Core::FileSys::g_saf_mirror_root = *bachataStorageRoot / "saf-mirror";
    }
    if (patchSessionPath.has_value()) {
        if (!bachataStorageRoot.has_value() ||
            !Platform::Bachata::ValidateSocketPath(*patchSessionPath, *bachataStorageRoot)) {
            std::cerr << "--patch-session must be absolute and inside --bachata-storage-root\n";
            return 1;
        }
        MemoryPatcher::g_managed_session_path = *patchSessionPath;
    }
    if (bachataSafSocket.has_value() != bachataSafToken.has_value()) {
        std::cerr << "SAF launch requires both broker socket and token\n";
        return 1;
    }
    if (bachataSafSocket.has_value()) {
        Core::FileSys::g_saf_socket = *bachataSafSocket;
        Core::FileSys::g_saf_token = *bachataSafToken;
        // Read broker-backed content through the broker fd instead of re-opening the path.
        Common::FS::SetFdOpenHook(&Core::FileSys::OpenSafMirrorFd);
    }
#endif

#ifdef ENABLE_BACHATA_RUNTIME
    // The Android frontend launches `-g eboot.bin --override-root <game dir>`: the game path is
    // relative to the managed override root, so resolve it before any host filesystem probe.
    if (gamePath.has_value() && !std::filesystem::path(*gamePath).is_absolute() &&
        overrideRoot.has_value()) {
        *gamePath = (*overrideRoot / *gamePath).string();
    }

    bool bachata_content_validated = false;
    {
        std::string dbg_args = "DBGARGS\n";
        std::error_code ec;
        dbg_args += "cwd\n";
        dbg_args += std::filesystem::current_path(ec).string();
        dbg_args += "\noverride_root\n";
        dbg_args += overrideRoot.has_value() ? overrideRoot->string() : std::string{"<none>"};
        dbg_args += "\ngame\n";
        dbg_args += gamePath.has_value() ? *gamePath : std::string{"<none>"};
        dbg_args += "\nargv\n";
        for (int i = 0; i < argc; ++i) {
            dbg_args += argv[i];
            dbg_args += '\n';
        }
        dbg_args += "----\n";

        if (overrideRoot.has_value()) {
            // Bounded recursive listing so a nested eboot layout is visible.
            dbg_args += "override_root_tree\n";
            std::vector<std::pair<std::filesystem::path, int>> stack{{*overrideRoot, 0}};
            while (!stack.empty()) {
                const auto [dir, depth] = stack.back();
                stack.pop_back();
                if (depth > 3) {
                    continue;
                }
                std::error_code lec;
                for (const auto& entry : std::filesystem::directory_iterator(dir, lec)) {
                    for (int i = 0; i < depth; ++i) {
                        dbg_args += "  ";
                    }
                    dbg_args += entry.path().filename().string();
                    const bool is_dir = entry.is_directory(lec);
                    dbg_args += is_dir ? "/\n" : "\n";
                    if (is_dir) {
                        stack.emplace_back(entry.path(), depth + 1);
                    }
                }
            }
            dbg_args += "----\n";
            dbg_args += "direct_eboot\n";
            dbg_args += ((*overrideRoot / "eboot.bin").string());
            dbg_args += BachataIsExecutable(*overrideRoot / "eboot.bin") ? " exec\n" : " missing\n";
            dbg_args += "----\n";
        }

        if (bachataStorageRoot.has_value()) {
            dbg_args += "storage_root_tree\n";
            std::error_code sec;
            for (const auto& entry : std::filesystem::directory_iterator(*bachataStorageRoot, sec)) {
                dbg_args += entry.path().filename().string();
                dbg_args += entry.is_directory(sec) ? "/\n" : "\n";
            }
            dbg_args += "----\n";
        }

        if (auto client = BachataSafClient()) {
            dbg_args += "saf_probe\n";
            const char* probes[] = {"eboot.bin", "sce_sys/param.sfo", "sce_sys",
                                    "",          ".",                "/app0/eboot.bin"};
            for (const char* probe : probes) {
                int stage = -1;
                u8 status = 0;
                u8 flags = 0;
                std::vector<u8> payload;
                const bool ok = client->Probe(1, probe, stage, status, flags, payload);
                dbg_args += probe[0] != '\0' ? probe : "<empty>";
                dbg_args += " stage=";
                dbg_args += std::to_string(stage);
                dbg_args += " status=";
                dbg_args += std::to_string(status);
                dbg_args += " flags=";
                dbg_args += std::to_string(flags);
                dbg_args += " len=";
                dbg_args += std::to_string(payload.size());
                dbg_args += ok ? " ok" : " transportfail";
                dbg_args += '\n';
            }
            dbg_args += "saf_readdir\n";
            const char* dirs[] = {"", ".", "sce_sys"};
            for (const char* dir : dirs) {
                int stage = -1;
                u8 status = 0;
                u8 flags = 0;
                std::vector<u8> payload;
                const bool ok = client->Probe(2, dir, stage, status, flags, payload);
                dbg_args += dir[0] != '\0' ? dir : "<empty>";
                dbg_args += " stage=";
                dbg_args += std::to_string(stage);
                dbg_args += " status=";
                dbg_args += std::to_string(status);
                dbg_args += " flags=";
                dbg_args += std::to_string(flags);
                dbg_args += " len=";
                dbg_args += std::to_string(payload.size());
                dbg_args += ok ? " ok" : " transportfail";
                dbg_args += '\n';
            }
            {
                int stage = -1;
                u8 status = 0;
                u8 flags = 0;
                std::vector<u8> payload;
                client->Probe(1, "eboot.bin", stage, status, flags, payload);
                dbg_args += "stat_eboot_hex=";
                for (const u8 b : payload) {
                    char h[3];
                    std::snprintf(h, sizeof(h), "%02x", b);
                    dbg_args += h;
                }
                dbg_args += '\n';
            }
#if defined(__linux__)
            {
                const int fd = client->Open("eboot.bin");
                dbg_args += "open_eboot_fd=";
                dbg_args += std::to_string(fd);
                dbg_args += '\n';
                if (fd >= 0) {
                    struct stat st{};
                    if (::fstat(fd, &st) == 0) {
                        dbg_args += "fstat_size=";
                        dbg_args += std::to_string(static_cast<long long>(st.st_size));
                        dbg_args += " mode=";
                        dbg_args += std::to_string(static_cast<unsigned>(st.st_mode));
                        dbg_args += '\n';
                    }
                    u8 buf[16]{};
                    const ssize_t n = ::pread(fd, buf, sizeof(buf), 0);
                    dbg_args += "pread_n=";
                    dbg_args += std::to_string(n);
                    dbg_args += " hex=";
                    for (ssize_t i = 0; i < n && i < 16; ++i) {
                        char h[3];
                        std::snprintf(h, sizeof(h), "%02x", buf[i]);
                        dbg_args += h;
                    }
                    dbg_args += '\n';
                    ::close(fd);
                }
            }
#endif
            const auto mirror = Core::FileSys::SafMirrorRoot() / "probe";
            Core::FileSys::SafFsBackend backend(client, "/app0", mirror);
            const auto resolved = backend.Resolve("/app0/eboot.bin");
            dbg_args += "saf_resolved\n";
            dbg_args += resolved.empty() ? std::string{"<none>"} : resolved.string();
            dbg_args += BachataIsExecutable(resolved) ? " exec\n" : " notexec\n";
            if (!resolved.empty()) {
                Core::Loader::Elf elf;
                elf.Open(resolved);
                const auto sh = elf.GetSElfHeader();
                const auto eh = elf.GetElfHeader();
                dbg_args += "loader_is_self=";
                dbg_args += elf.IsSelfFile() ? "1" : "0";
                dbg_args += " loader_is_elf=";
                dbg_args += elf.IsElfFile() ? "1" : "0";
                dbg_args += " self_magic=";
                {
                    char h[16];
                    std::snprintf(h, sizeof(h), "%08x", sh.magic);
                    dbg_args += h;
                }
                dbg_args += " ver=";
                dbg_args += std::to_string(sh.version);
                dbg_args += " mode=";
                dbg_args += std::to_string(sh.mode);
                dbg_args += " endian=";
                dbg_args += std::to_string(sh.endian);
                dbg_args += " attr=";
                dbg_args += std::to_string(sh.attributes);
                dbg_args += " cat=";
                dbg_args += std::to_string(sh.category);
                dbg_args += " ptype=";
                dbg_args += std::to_string(sh.program_type);
                dbg_args += " hdrsize=";
                dbg_args += std::to_string(sh.header_size);
                dbg_args += " segcount=";
                dbg_args += std::to_string(sh.segment_count);
                dbg_args += " elf_magic=";
                {
                    char h[16];
                    std::snprintf(h, sizeof(h), "%02x%02x%02x%02x", eh.e_ident.magic[0],
                                  eh.e_ident.magic[1], eh.e_ident.magic[2], eh.e_ident.magic[3]);
                    dbg_args += h;
                }
                dbg_args += '\n';
                std::error_code rec;
                dbg_args += "resolved_is_dir=";
                dbg_args += std::filesystem::is_directory(resolved, rec) ? "1" : "0";
                dbg_args += " is_symlink=";
                dbg_args += std::filesystem::is_symlink(resolved) ? "1" : "0";
                dbg_args += " target=";
                const auto target = std::filesystem::read_symlink(resolved, rec);
                dbg_args += rec ? std::string{"<err>"} : target.string();
                dbg_args += '\n';
                std::vector<unsigned char> head(0x2000, 0);
                ssize_t got = 0;
                const int hook_fd = Core::FileSys::OpenSafMirrorFd(resolved);
                if (hook_fd >= 0) {
                    got = ::pread(hook_fd, head.data(), head.size(), 0);
                    ::close(hook_fd);
                }
                dbg_args += "head_len=";
                dbg_args += std::to_string(got);
                dbg_args += " head32=";
                for (ssize_t i = 0; i < 32 && i < got; ++i) {
                    char h[3];
                    std::snprintf(h, sizeof(h), "%02x", head[static_cast<size_t>(i)]);
                    dbg_args += h;
                }
                long elf_off = -1;
                for (ssize_t i = 0; i + 4 <= got; ++i) {
                    if (head[static_cast<size_t>(i)] == 0x7F &&
                        head[static_cast<size_t>(i) + 1] == 'E' &&
                        head[static_cast<size_t>(i) + 2] == 'L' &&
                        head[static_cast<size_t>(i) + 3] == 'F') {
                        elf_off = static_cast<long>(i);
                        break;
                    }
                }
                dbg_args += " elf_magic_off=";
                dbg_args += std::to_string(elf_off);
                if (got >= 26) {
                    const unsigned seg = static_cast<unsigned>(head[24]) |
                                         (static_cast<unsigned>(head[25]) << 8);
                    dbg_args += " self_segcount=";
                    dbg_args += std::to_string(seg);
                }
                dbg_args += '\n';
            }
            dbg_args += "----\n";
        }

        if (gamePath.has_value() && std::filesystem::path(*gamePath).is_absolute()) {
            bachata_content_validated =
                BachataContentReachable(overrideRoot.value_or(std::filesystem::path{}),
                                        std::filesystem::path(*gamePath));
            dbg_args += "reachable\n";
            dbg_args += bachata_content_validated ? "1\n" : "0\n";
            dbg_args += "----\n";
        }

        const char* dbg_dirs[] = {
            "/sdcard/Download",
            "/storage/emulated/0/Download",
            "/sdcard/Android/data/com.bachatas4.android.github/files",
            "/storage/emulated/0/Android/data/com.bachatas4.android.github/files",
            "/data/local/tmp",
        };
        for (const char* dir : dbg_dirs) {
            std::error_code dec;
            std::filesystem::create_directories(dir, dec);
            std::ofstream dump(std::string(dir) + "/bachata-argv.txt", std::ios::app);
            if (dump) {
                dump << dbg_args;
            }
        }
        std::ofstream cwd_dump("bachata-argv.txt", std::ios::app);
        if (cwd_dump) {
            cwd_dump << dbg_args;
        }
    }

    // Content can come from the direct runtime folder or the SAF broker. Validate that an
    // executable eboot is reachable before IPC, settings, SDL or X11 initialization can block
    // the managed session, otherwise the frontend hangs waiting for a runtime event.
    if (gamePath.has_value() && std::filesystem::path(*gamePath).is_absolute()) {
        const std::filesystem::path early_eboot_path(*gamePath);
        if (!bachata_content_validated) {
            std::cerr << "Invalid PS4 executable: " << early_eboot_path << '\n';
            runtime_client.SendError("CONTENT_INVALID");
            runtime_client.SendStopped(1);
            return 1;
        }
    }
#endif

    if (waitPid)
        Core::Debugger::WaitForPid(*waitPid);

#ifdef ENABLE_BACHATA_RUNTIME
    // Android keeps logs in app-private storage that is unreachable without root. Redirect the log
    // directory to a readable location so a crash can be diagnosed from the device.
    {
        std::error_code lec;
        const std::filesystem::path readable_logs{"/sdcard/Download/bachata-logs"};
        std::filesystem::create_directories(readable_logs, lec);
        if (!lec) {
            Common::FS::SetUserPath(Common::FS::PathType::LogDir, readable_logs);
        }
    }
#endif

    // Initialize main log with default config
    Common::Log::Setup("shadps4.log");

    LOG_INFO(Debug, "Run: {}", std::span(argv, argc));

    IPC::Instance().Init();

    auto emu_state = std::make_shared<EmulatorState>();
    EmulatorState::SetInstance(emu_state);
    UserSettings.Load();
#ifdef ENABLE_BACHATA_RUNTIME
    // Desktop input discovery logs in player one during its first controller scan. The
    // Android runtime bypasses that scan, so bootstrap the same user-service login event.
    UserManagement.LoginUser(UserManagement.GetUserByPlayerIndex(1), 1);
    if (auto* user = UserManagement.GetUserByPlayerIndex(1)) {
        auto* controllers = Common::Singleton<Input::GameControllers>::Instance();
        (*controllers)[0]->user_id = user->user_id;
        (*controllers)[0]->ConnectController(nullptr);
    }
#endif

    // Initialize key manager
    auto key_manager = KeyManager::GetInstance();
    key_manager->LoadFromFile();

    // Load configurations
    std::shared_ptr<EmulatorSettingsImpl> emu_settings = std::make_shared<EmulatorSettingsImpl>();
    EmulatorSettingsImpl::SetInstance(emu_settings);
    emu_settings->Load();

    // Configure logger appropriately
    Common::Log::g_should_append |= EmulatorSettings.IsLogAppend();

    if (bigPicture) {
        BigPictureMode::Launch(argv[0]);
        return 0;
    }

    // ---- Utility commands ----
    if (addGameFolder) {
        EmulatorSettings.AddGameInstallDir(*addGameFolder);
        EmulatorSettings.Save();
        LOG_INFO(Config, "Game folder successfully saved.");
        return 0;
    }

    if (setAddonFolder) {
        EmulatorSettings.SetAddonInstallDir(*setAddonFolder);
        EmulatorSettings.Save();
        LOG_INFO(Config, "Addon folder successfully saved.");
        return 0;
    }

    if (!gamePath.has_value()) {
        if (!gameArgs.empty()) {
            gamePath = gameArgs.front();
            gameArgs.erase(gameArgs.begin());
        } else {
            LOG_ERROR(Debug, "Please provide a game path or ID.");
#ifdef ENABLE_BACHATA_RUNTIME
            runtime_client.SendError("CONTENT_INVALID");
            runtime_client.SendStopped(1);
#endif
            return 1;
        }
    }
    if (!gameArgs.empty()) {
        if (gameArgs.front() == "--") {
            gameArgs.erase(gameArgs.begin());
        } else {
            LOG_ERROR(Debug, "unhandled flags");
            return 1;
        }
    }

    // ---- Apply flags ----
    if (patchFile)
        MemoryPatcher::patch_file = *patchFile;

    if (ignoreGamePatch)
        Core::FileSys::MntPoints::ignore_game_patches = true;

    if (fullscreenStr) {
        if (*fullscreenStr == "true") {
            EmulatorSettings.SetFullScreen(true);
        } else if (*fullscreenStr == "false") {
            EmulatorSettings.SetFullScreen(false);
        } else {
            LOG_ERROR(Debug, "Invalid argument for --fullscreen (use true|false)");
            return 1;
        }
    }

    if (showFps)
        EmulatorSettings.SetShowFpsCounter(true);

    if (configClean)
        EmulatorSettings.SetConfigMode(ConfigMode::Clean);

    if (configGlobal)
        EmulatorSettings.SetConfigMode(ConfigMode::Global);

    // ---- Resolve game path or ID ----
    std::filesystem::path ebootPath(*gamePath);
#ifdef ENABLE_BACHATA_RUNTIME
    // Content was already validated (possibly through the SAF broker) before initialization,
    // so skip the host-filesystem probes that would reject broker-backed paths.
    const bool bachata_skip_disk_checks = bachata_content_validated;
#else
    constexpr bool bachata_skip_disk_checks = false;
#endif
    if (!bachata_skip_disk_checks && !std::filesystem::exists(ebootPath)) {
        bool found = false;
        constexpr int maxDepth = 5;
        for (const auto& installDir : EmulatorSettings.GetGameInstallDirs()) {
            if (auto foundPath = Common::FS::FindGameByID(installDir, *gamePath, maxDepth)) {
                ebootPath = *foundPath;
                found = true;
                break;
            }
        }
        if (!found) {
            LOG_ERROR(Debug, "Game ID or file path not found: {}", *gamePath);
#ifdef ENABLE_BACHATA_RUNTIME
            runtime_client.SendError("CONTENT_INVALID");
            runtime_client.SendStopped(1);
#endif
            return 1;
        }
    }

#ifdef ENABLE_BACHATA_RUNTIME
    if (!bachata_skip_disk_checks) {
        Core::Loader::Elf executable;
        executable.Open(ebootPath);
        if (!executable.IsElfFile()) {
            LOG_ERROR(Debug, "Invalid PS4 executable: {}", ebootPath.string());
            runtime_client.SendError("CONTENT_INVALID");
            runtime_client.SendStopped(1);
            return 1;
        }
    }
#endif

    auto* emulator = Common::Singleton<Core::Emulator>::Instance();
    emulator->executableName = argv[0];
    emulator->waitForDebuggerBeforeRun = waitForDebugger;
#ifdef ENABLE_BACHATA_RUNTIME
    if (runtime_client.IsEnabled() &&
        !runtime_client.StartInputReader([](const Platform::Bachata::ControllerSnapshot& snapshot) {
            auto* controllers = Common::Singleton<Input::GameControllers>::Instance();
            const std::array<int, 6> axes = {
                snapshot.left_x,       snapshot.left_y, snapshot.right_x,
                snapshot.right_y,      snapshot.left_trigger, snapshot.right_trigger,
            };
            auto* controller = (*controllers)[snapshot.slot];
            controller->ApplyRemoteState(
                static_cast<Libraries::Pad::OrbisPadButtonDataOffset>(snapshot.buttons), axes,
                snapshot.touch_down, snapshot.touch_x / 1920.0f, snapshot.touch_y / 1080.0f);
            if (snapshot.has_motion) {
                // Mirror the SDL path: stage into the sensor buffers, then push into the pad
                // state that scePadRead reads. On Android no SDL timer does this for us.
                controller->UpdateGyro(snapshot.gyro);
                controller->UpdateAcceleration(snapshot.accel);
                controller->Gyro(0);
                controller->Acceleration(0);
                // SDL hotplug sets this when a sensor-bearing gamepad connects; without a
                // non-zero rate pad.cpp skips CalculateOrientation and orientation stays
                // identity, which freezes games that steer by attitude.
                if (controller->accel_poll_rate == 0.0f) {
                    controller->accel_poll_rate = 60.0f;
                }
                static std::atomic<u64> motion_frames{0};
                if (motion_frames.fetch_add(1) % 3000 == 0) {
                    LOG_INFO(Debug,
                             "BACHATA_INPUT motion frame #{}: gyro=({:.3f},{:.3f},{:.3f}) "
                             "accel=({:.2f},{:.2f},{:.2f})",
                             motion_frames.load(), snapshot.gyro[0], snapshot.gyro[1],
                             snapshot.gyro[2], snapshot.accel[0], snapshot.accel[1],
                             snapshot.accel[2]);
                }
            }
        })) {
        std::cerr << "Failed to start Bachata input reader\n";
        runtime_client.SendError("INPUT_UNAVAILABLE");
        runtime_client.SendStopped(1);
        return 1;
    }
    emulator->onRuntimeRunning = [&runtime_client]() { runtime_client.SendRunning(); };
    Platform::Bachata::SetActiveRuntimeClient(&runtime_client);
    emulator->onRuntimeError = [&runtime_client](std::string_view code) {
        runtime_client.SendError(code);
    };
    emulator->onRuntimeStopped = [&runtime_client](int exit_code) {
        runtime_client.SendStopped(exit_code);
    };
#endif
    emulator->Run(ebootPath, gameArgs, overrideRoot);

    return 0;
}
