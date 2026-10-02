// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "common/types.h"
#include "core/file_sys/saf_broker_client.h"

namespace Core::FileSys {

extern std::string g_saf_socket;
extern std::string g_saf_token;
// Writable directory used to stage fd symlinks. Android has no writable /tmp, so the frontend
// points this at an app-private folder under --bachata-storage-root. Falls back to the
// platform temp directory when empty.
extern std::filesystem::path g_saf_mirror_root;

std::filesystem::path SafMirrorRoot();

// Fd hook implementation: returns a fresh read descriptor for a staged mirror path, or -1 when the
// path is not SAF-backed. Installed into Common::FS so IOFile opens broker content directly.
int OpenSafMirrorFd(const std::filesystem::path& path);

class SafFsBackend {
public:
    SafFsBackend(std::shared_ptr<SafBrokerClient> client, std::string guest_root,
                 std::filesystem::path mirror_root,
                 std::filesystem::path fallback_root = std::filesystem::path{});
    ~SafFsBackend();

    SafFsBackend(const SafFsBackend&) = delete;
    SafFsBackend& operator=(const SafFsBackend&) = delete;

    bool Matches(std::string_view guest_path) const;
    std::filesystem::path Resolve(std::string_view guest_path);
    bool Iterate(std::string_view guest_path,
                 const std::function<void(const std::filesystem::path&, bool)>& callback);

private:
    std::filesystem::path MirrorPath(std::string_view guest_path) const;
    std::filesystem::path FallbackPath(std::string_view guest_path) const;
    std::string RelativePath(std::string_view guest_path) const;
    int AcquireFd(const std::string& broker_path);
    void EvictLocked();

    std::shared_ptr<SafBrokerClient> client;
    std::string guest_root;
    std::filesystem::path mirror_root;
    // When set, a real directory tree is preferred over the SAF broker. This lets the
    // Android frontend materialize content in an app-private "direct runtime" folder
    // while still serving paths that only exist behind the SAF broker.
    std::filesystem::path fallback_root;

    std::mutex mutex;
    std::unordered_map<std::string, int> fd_cache;
    std::vector<std::string> fd_order;
    static constexpr size_t MaxCachedFds = 512;
};

} // namespace Core::FileSys
