// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/file_sys/saf_broker_client.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <utility>

#ifdef __linux__

#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
constexpr u32 SAF_MAGIC = 0x42534631u;
constexpr u8 SAF_PROTO_VERSION = 1;
constexpr u8 SAF_OP_STAT = 1;
constexpr u8 SAF_OP_READDIR = 2;
constexpr u8 SAF_OP_OPEN = 3;

constexpr size_t SAF_REQ_HEADER = 12;
constexpr size_t SAF_RSP_HEADER = 10;
constexpr size_t SAF_MAX_PAYLOAD = 0x400000;

void PushBe16(std::vector<u8>& out, u16 v) {
    out.push_back(static_cast<u8>(v >> 8));
    out.push_back(static_cast<u8>(v));
}

void PushBe32(std::vector<u8>& out, u32 v) {
    out.push_back(static_cast<u8>(v >> 24));
    out.push_back(static_cast<u8>(v >> 16));
    out.push_back(static_cast<u8>(v >> 8));
    out.push_back(static_cast<u8>(v));
}

u16 ReadBe16(const u8* p) {
    return static_cast<u16>((static_cast<u16>(p[0]) << 8) | p[1]);
}

u32 ReadBe32(const u8* p) {
    return (static_cast<u32>(p[0]) << 24) | (static_cast<u32>(p[1]) << 16) |
           (static_cast<u32>(p[2]) << 8) | static_cast<u32>(p[3]);
}

u64 ReadBe64(const u8* p) {
    return (static_cast<u64>(ReadBe32(p)) << 32) | ReadBe32(p + 4);
}

bool SendAll(int fd, const u8* data, size_t size) {
    size_t sent = 0;
    while (sent < size) {
        const ssize_t n = ::send(fd, data + sent, size - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool RecvAll(int fd, u8* data, size_t size) {
    size_t got = 0;
    while (got < size) {
        const ssize_t n = ::recv(fd, data + got, size - got, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        got += static_cast<size_t>(n);
    }
    return true;
}
} // namespace

#endif

namespace Core::FileSys {

SafBrokerClient::SafBrokerClient(std::string socket, std::string tok)
    : socket_name(std::move(socket)), token(std::move(tok)) {}

SafBrokerClient::~SafBrokerClient() = default;

SafBrokerClient::SafBrokerClient(SafBrokerClient&& other) noexcept
    : socket_name(std::move(other.socket_name)), token(std::move(other.token)) {}

SafBrokerClient& SafBrokerClient::operator=(SafBrokerClient&& other) noexcept {
    if (this != &other) {
        socket_name = std::move(other.socket_name);
        token = std::move(other.token);
    }
    return *this;
}

#ifdef __linux__
bool SafBrokerClient::Transact(u8 opcode, std::string_view path, bool want_fd,
                               std::vector<u8>& payload, int& out_fd) const {
    out_fd = -1;
    if (!IsValid()) {
        return false;
    }

    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    const size_t name_len = std::min(socket_name.size(), sizeof(addr.sun_path) - 2);
    std::memcpy(addr.sun_path + 1, socket_name.data(), name_len);
    const socklen_t addr_len =
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name_len);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), addr_len) != 0) {
        ::close(fd);
        return false;
    }

    std::vector<u8> req;
    req.reserve(SAF_REQ_HEADER + token.size() + path.size());
    PushBe32(req, SAF_MAGIC);
    req.push_back(SAF_PROTO_VERSION);
    req.push_back(opcode);
    PushBe16(req, static_cast<u16>(token.size()));
    PushBe32(req, static_cast<u32>(path.size()));
    req.insert(req.end(), token.begin(), token.end());
    req.insert(req.end(), path.begin(), path.end());

    if (!SendAll(fd, req.data(), req.size())) {
        ::close(fd);
        return false;
    }

    u8 header[SAF_RSP_HEADER]{};
    if (want_fd) {
        u8 cbuf[CMSG_SPACE(sizeof(int))]{};
        iovec iov{};
        iov.iov_base = header;
        iov.iov_len = sizeof(header);
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);
        const ssize_t n = ::recvmsg(fd, &msg, 0);
        if (n < static_cast<ssize_t>(sizeof(header))) {
            ::close(fd);
            return false;
        }
        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                int received = -1;
                std::memcpy(&received, CMSG_DATA(cmsg), sizeof(received));
                out_fd = received;
            }
        }
    } else {
        if (!RecvAll(fd, header, sizeof(header))) {
            ::close(fd);
            return false;
        }
    }

    if (ReadBe32(header) != SAF_MAGIC || header[4] != 1) {
        if (out_fd >= 0) {
            ::close(out_fd);
            out_fd = -1;
        }
        ::close(fd);
        return false;
    }

    const u32 length = ReadBe32(header + 6);
    if (length > SAF_MAX_PAYLOAD) {
        if (out_fd >= 0) {
            ::close(out_fd);
            out_fd = -1;
        }
        ::close(fd);
        return false;
    }

    payload.resize(length);
    if (length != 0 && !RecvAll(fd, payload.data(), length)) {
        if (out_fd >= 0) {
            ::close(out_fd);
            out_fd = -1;
        }
        ::close(fd);
        return false;
    }

    ::close(fd);
    return true;
}
#else
bool SafBrokerClient::Transact(u8, std::string_view, bool, std::vector<u8>&, int& out_fd) const {
    out_fd = -1;
    return false;
}
#endif

bool SafBrokerClient::Stat(std::string_view guest_path, SafEntry& out) const {
    std::vector<u8> payload;
    int fd = -1;
    if (!Transact(SAF_OP_STAT, guest_path, false, payload, fd)) {
        return false;
    }
    if (payload.size() != 17) {
        return false;
    }
    out.name = std::string{guest_path};
    out.is_directory = payload[0] != 0;
    out.mtime = ReadBe64(payload.data() + 1);
    out.size = ReadBe64(payload.data() + 9);
    return true;
}

bool SafBrokerClient::ReadDir(std::string_view guest_path, std::vector<SafEntry>& out) const {
    std::vector<u8> payload;
    int fd = -1;
    if (!Transact(SAF_OP_READDIR, guest_path, false, payload, fd)) {
        return false;
    }
    if (payload.size() < 4) {
        return false;
    }
    const u32 count = ReadBe32(payload.data());
    out.clear();
    out.reserve(count);
    size_t pos = 4;
    for (u32 i = 0; i < count; ++i) {
        if (pos + 2 > payload.size()) {
            return false;
        }
        const u16 name_len = ReadBe16(payload.data() + pos);
        pos += 2;
        if (pos + name_len + 0x11 > payload.size()) {
            return false;
        }
        SafEntry entry;
        entry.name.assign(reinterpret_cast<const char*>(payload.data() + pos), name_len);
        pos += name_len;
        entry.is_directory = payload[pos] != 0;
        entry.mtime = ReadBe64(payload.data() + pos + 1);
        entry.size = ReadBe64(payload.data() + pos + 9);
        pos += 0x11;
        out.push_back(std::move(entry));
    }
    return true;
}

int SafBrokerClient::Open(std::string_view guest_path) const {
    std::vector<u8> payload;
    int fd = -1;
    if (!Transact(SAF_OP_OPEN, guest_path, true, payload, fd)) {
        return -1;
    }
    return fd;
}

} // namespace Core::FileSys
