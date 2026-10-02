// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "common/types.h"

namespace Core::FileSys {

struct SafEntry {
    std::string name;
    bool is_directory{};
    u64 size{};
    u64 mtime{};
};

class SafBrokerClient {
public:
    SafBrokerClient() = default;
    SafBrokerClient(std::string socket_name, std::string token);
    ~SafBrokerClient();

    SafBrokerClient(const SafBrokerClient&) = delete;
    SafBrokerClient& operator=(const SafBrokerClient&) = delete;
    SafBrokerClient(SafBrokerClient&& other) noexcept;
    SafBrokerClient& operator=(SafBrokerClient&& other) noexcept;

    bool IsValid() const {
        return !socket_name.empty() && !token.empty();
    }

    bool Stat(std::string_view guest_path, SafEntry& out) const;
    bool ReadDir(std::string_view guest_path, std::vector<SafEntry>& out) const;
    int Open(std::string_view guest_path) const;

    // Diagnostic probe: performs a raw transaction and reports the transport stage plus the
    // raw response status/flags, so a caller can tell a protocol mismatch apart from a path
    // error. stage: 0 = response received, 1 = socket() failed, 2 = connect() failed,
    // 3 = send failed, 4 = recv failed, 5 = bad magic, 6 = invalid client, 7 = oversized reply.
    bool Probe(u8 opcode, std::string_view guest_path, int& stage, u8& status, u8& flags,
               std::vector<u8>& payload) const;

private:
    bool RawTransact(u8 opcode, std::string_view path, bool want_fd, int& stage, u8& out_status,
                     u8& out_flags, std::vector<u8>& payload, int& out_fd) const;
    bool Transact(u8 opcode, std::string_view path, bool want_fd, std::vector<u8>& payload,
                  int& out_fd) const;

    std::string socket_name;
    std::string token;
};

} // namespace Core::FileSys
