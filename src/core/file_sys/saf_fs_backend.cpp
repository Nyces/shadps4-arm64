// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/file_sys/saf_fs_backend.h"

#include <system_error>
#include <utility>

#ifdef __linux__
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Core::FileSys {

std::string g_saf_socket;
std::string g_saf_token;
std::filesystem::path g_saf_mirror_root;

std::filesystem::path SafMirrorRoot() {
    if (!g_saf_mirror_root.empty()) {
        return g_saf_mirror_root;
    }
    std::error_code ec;
    const auto tmp = std::filesystem::temp_directory_path(ec);
    if (!ec && !tmp.empty()) {
        const auto candidate = tmp / "bachata-saf";
        std::filesystem::create_directories(candidate, ec);
        if (!ec) {
            return candidate;
        }
    }
    ec.clear();
    const auto cwd = std::filesystem::current_path(ec);
    if (!ec && !cwd.empty()) {
        const auto candidate = cwd / ".bachata-saf";
        std::filesystem::create_directories(candidate, ec);
        if (!ec) {
            return candidate;
        }
    }
    return std::filesystem::path{"/data/local/tmp/bachata-saf"};
}

namespace {
std::mutex g_mirror_mutex;
std::unordered_map<std::string, std::function<int()>> g_mirror_openers;
} // namespace

int OpenSafMirrorFd(const std::filesystem::path& path) {
    std::scoped_lock lock{g_mirror_mutex};
    const auto it = g_mirror_openers.find(path.string());
    if (it == g_mirror_openers.end()) {
        return -1;
    }
    return it->second();
}

SafFsBackend::SafFsBackend(std::shared_ptr<SafBrokerClient> c, std::string root,
                           std::filesystem::path mirror, std::filesystem::path fallback)
    : client(std::move(c)), guest_root(std::move(root)), mirror_root(std::move(mirror)),
      fallback_root(std::move(fallback)) {}

SafFsBackend::~SafFsBackend() {
#ifdef __linux__
    for (const auto& [path, fd] : fd_cache) {
        if (fd >= 0) {
            ::close(fd);
        }
    }
#endif
    fd_cache.clear();
}

bool SafFsBackend::Matches(std::string_view guest_path) const {
    if (guest_path.size() < guest_root.size()) {
        return false;
    }
    if (!guest_path.starts_with(guest_root)) {
        return false;
    }
    return guest_path.size() == guest_root.size() || guest_path[guest_root.size()] == '/';
}

std::string SafFsBackend::RelativePath(std::string_view guest_path) const {
    std::string rel{guest_path};
    if (rel.size() >= guest_root.size()) {
        rel = rel.substr(guest_root.size());
    }
    while (!rel.empty() && rel.front() == '/') {
        rel.erase(rel.begin());
    }
    return rel;
}

std::filesystem::path SafFsBackend::MirrorPath(std::string_view guest_path) const {
    const std::string rel = RelativePath(guest_path);
    if (rel.empty()) {
        return mirror_root;
    }
    return mirror_root / rel;
}

std::filesystem::path SafFsBackend::FallbackPath(std::string_view guest_path) const {
    if (fallback_root.empty()) {
        return {};
    }
    const std::string rel = RelativePath(guest_path);
    if (rel.empty()) {
        return fallback_root;
    }
    return fallback_root / rel;
}

int SafFsBackend::AcquireFd(const std::string& broker_path) {
    std::scoped_lock lock{mutex};
    if (const auto it = fd_cache.find(broker_path); it != fd_cache.end()) {
        return it->second;
    }
    const int fd = client->Open(broker_path);
    if (fd < 0) {
        return -1;
    }
    fd_cache.emplace(broker_path, fd);
    fd_order.push_back(broker_path);
    EvictLocked();
    return fd;
}

void SafFsBackend::EvictLocked() {
    while (fd_order.size() > MaxCachedFds) {
        const std::string victim = fd_order.front();
        fd_order.erase(fd_order.begin());
        const auto it = fd_cache.find(victim);
        if (it == fd_cache.end()) {
            continue;
        }
#ifdef __linux__
        if (it->second >= 0) {
            ::close(it->second);
        }
#endif
        fd_cache.erase(it);
    }
}

std::filesystem::path SafFsBackend::Resolve(std::string_view guest_path) {
    if (!Matches(guest_path)) {
        return {};
    }
    std::error_code ec;
    // Prefer content that the frontend materialized on the real filesystem.
    const auto fallback = FallbackPath(guest_path);
    if (!fallback.empty() && std::filesystem::exists(fallback, ec)) {
        return fallback;
    }
    // The SAF broker addresses files relative to its own root (no /app0 prefix, no leading
    // slash): /app0/sce_sys/param.sfo -> "sce_sys/param.sfo".
    const std::string rel = RelativePath(guest_path);
    const auto mirror = MirrorPath(guest_path);
    if (rel.empty()) {
        // Mount root: the mirror directory represents the broker root.
        std::filesystem::create_directories(mirror, ec);
        return ec ? std::filesystem::path{} : mirror;
    }
    if (!client) {
        return {};
    }
    const int fd = AcquireFd(rel);
    if (fd >= 0) {
        // The broker fd is authoritative for the entry type, so probe it with fstat instead of
        // guessing the stat payload field offsets.
        bool is_dir = false;
#ifdef __linux__
        struct stat st{};
        is_dir = ::fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
#endif
        if (is_dir) {
            std::filesystem::create_directories(mirror, ec);
            return ec ? std::filesystem::path{} : mirror;
        }
        std::filesystem::create_directories(mirror.parent_path(), ec);
        std::filesystem::remove(mirror, ec);
#ifdef __linux__
        std::filesystem::create_symlink("/proc/self/fd/" + std::to_string(fd), mirror, ec);
#endif
        if (ec) {
            return {};
        }
        // Register a fresh-fd opener so IOFile can read broker content without re-opening the
        // underlying path (denied under scoped storage).
        if (client) {
            std::scoped_lock lock{g_mirror_mutex};
            g_mirror_openers[mirror.string()] = [c = client, r = rel] { return c->Open(r); };
        }
        return mirror;
    }
    // Some brokers refuse to open directories; fall back to Stat for those.
    SafEntry entry;
    if (client->Stat(rel, entry) && entry.is_directory) {
        std::filesystem::create_directories(mirror, ec);
        return ec ? std::filesystem::path{} : mirror;
    }
    return {};
}

bool SafFsBackend::Iterate(
    std::string_view guest_path,
    const std::function<void(const std::filesystem::path&, bool)>& callback) {
    if (!Matches(guest_path)) {
        return false;
    }
    std::error_code ec;
    const auto fallback = FallbackPath(guest_path);
    if (!fallback.empty() && std::filesystem::is_directory(fallback, ec)) {
        for (const auto& entry : std::filesystem::directory_iterator(fallback, ec)) {
            callback(entry.path(), !entry.is_directory(ec));
        }
        return true;
    }
    if (!client) {
        return false;
    }
    const std::string rel = RelativePath(guest_path);
    std::vector<SafEntry> entries;
    bool listed = client->ReadDir(rel, entries);
    if (!listed && rel.empty()) {
        // Some brokers spell the root as "." rather than the empty string.
        listed = client->ReadDir(".", entries);
    }
    if (!listed) {
        return false;
    }
    for (const auto& entry : entries) {
        std::string child{guest_path};
        if (child.back() != '/') {
            child.push_back('/');
        }
        child += entry.name;
        const auto resolved = Resolve(child);
        if (!resolved.empty()) {
            callback(resolved, !entry.is_directory);
        }
    }
    return true;
}

} // namespace Core::FileSys
