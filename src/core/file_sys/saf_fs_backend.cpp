// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/file_sys/saf_fs_backend.h"

#include <system_error>
#include <utility>

#ifdef __linux__
#include <unistd.h>
#endif

namespace Core::FileSys {

std::string g_saf_socket;
std::string g_saf_token;

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

std::filesystem::path SafFsBackend::MirrorPath(std::string_view guest_path) const {
    std::string rel{guest_path};
    if (rel.size() >= guest_root.size()) {
        rel = rel.substr(guest_root.size());
    }
    while (!rel.empty() && rel.front() == '/') {
        rel.erase(rel.begin());
    }
    if (rel.empty()) {
        return mirror_root;
    }
    return mirror_root / rel;
}

std::filesystem::path SafFsBackend::FallbackPath(std::string_view guest_path) const {
    if (fallback_root.empty()) {
        return {};
    }
    std::string rel{guest_path};
    if (rel.size() >= guest_root.size()) {
        rel = rel.substr(guest_root.size());
    }
    while (!rel.empty() && rel.front() == '/') {
        rel.erase(rel.begin());
    }
    if (rel.empty()) {
        return fallback_root;
    }
    return fallback_root / rel;
}

int SafFsBackend::AcquireFd(const std::string& guest_path) {
    std::scoped_lock lock{mutex};
    if (const auto it = fd_cache.find(guest_path); it != fd_cache.end()) {
        return it->second;
    }
    const int fd = client->Open(guest_path);
    if (fd < 0) {
        return -1;
    }
    fd_cache.emplace(guest_path, fd);
    fd_order.push_back(guest_path);
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
    if (!client) {
        return {};
    }
    SafEntry entry;
    if (!client->Stat(guest_path, entry)) {
        return {};
    }
    const auto mirror = MirrorPath(guest_path);
    if (entry.is_directory) {
        std::filesystem::create_directories(mirror, ec);
        return ec ? std::filesystem::path{} : mirror;
    }
    const int fd = AcquireFd(std::string{guest_path});
    if (fd < 0) {
        return {};
    }
    std::filesystem::create_directories(mirror.parent_path(), ec);
    std::filesystem::remove(mirror, ec);
#ifdef __linux__
    std::filesystem::create_symlink("/proc/self/fd/" + std::to_string(fd), mirror, ec);
#endif
    return ec ? std::filesystem::path{} : mirror;
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
    std::vector<SafEntry> entries;
    if (!client->ReadDir(guest_path, entries)) {
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
