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
    int AcquireFd(const std::string& guest_path);
    void EvictLocked();

    std::filesystem::path FallbackPath(std::string_view guest_path) const;

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
