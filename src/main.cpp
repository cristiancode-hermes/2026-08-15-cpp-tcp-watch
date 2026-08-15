// SPDX-License-Identifier: MIT
// cpp-tcp-watch — Linux TCP connection monitor (/proc/net/tcp + /proc/net/tcp6)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o tcp-watch
// Usage: ./tcp-watch [--top N] [--watch N] [--ports] [--state NAME] [--json]
//                    [--demo] [--no-resolve] [--no-color] [--selftest]

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it — see skill pitfall)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET  = "\x1b[0m";
static std::string C_BOLD   = "\x1b[1m";
static std::string C_DIM    = "\x1b[2m";
static std::string C_RED    = "\x1b[31m";
static std::string C_GREEN  = "\x1b[32m";
static std::string C_YELLOW = "\x1b[33m";
static std::string C_BLUE   = "\x1b[34m";
static std::string C_CYAN   = "\x1b[36m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = "";
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// std::from_chars does NOT skip leading whitespace — trim first.
static std::optional<unsigned long long> parse_ull(std::string_view s, int base = 10) {
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return std::nullopt;
  s.remove_prefix(start);
  unsigned long long v = 0;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  if (ec != std::errc()) return std::nullopt;
  if (ptr != s.data() + s.size()) return std::nullopt;  // trailing garbage
  return v;
}

static std::optional<unsigned long long> parse_hex(std::string_view s) {
  return parse_ull(s, 16);
}

static std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  std::istringstream ss{std::string(s)};
  std::string tok;
  while (ss >> tok) out.push_back(tok);
  return out;
}

static std::string fmt_num(unsigned long long v) {
  char buf[24];
  if (v >= 1000000000ULL)      std::snprintf(buf, sizeof(buf), "%.1fG", static_cast<double>(v) / 1e9);
  else if (v >= 1000000ULL)    std::snprintf(buf, sizeof(buf), "%.1fM", static_cast<double>(v) / 1e6);
  else if (v >= 1000ULL)       std::snprintf(buf, sizeof(buf), "%.1fk", static_cast<double>(v) / 1e3);
  else                         std::snprintf(buf, sizeof(buf), "%llu", v);
  return buf;
}

static std::string fmt_rate(double v) {
  char buf[24];
  if (v >= 1e9)      std::snprintf(buf, sizeof(buf), "%.1fG/s", v / 1e9);
  else if (v >= 1e6) std::snprintf(buf, sizeof(buf), "%.1fM/s", v / 1e6);
  else if (v >= 1e3) std::snprintf(buf, sizeof(buf), "%.1fk/s", v / 1e3);
  else               std::snprintf(buf, sizeof(buf), "%.1f/s", v);
  return buf;
}

static std::string fmt_signed_rate(long long delta, double dt) {
  char buf[32];
  double rate = dt > 0 ? static_cast<double>(delta) / dt : 0.0;
  if (delta >= 0) std::snprintf(buf, sizeof(buf), "+%s", fmt_rate(rate).c_str());
  else            std::snprintf(buf, sizeof(buf), "%s", fmt_rate(rate).c_str());
  return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP state decode (hex value in /proc/net/tcp column 3)
// ─────────────────────────────────────────────────────────────────────────────
static std::string state_name(uint8_t code) {
  switch (code) {
    case 0x01: return "ESTABLISHED";
    case 0x02: return "SYN_SENT";
    case 0x03: return "SYN_RECV";
    case 0x04: return "FIN_WAIT1";
    case 0x05: return "FIN_WAIT2";
    case 0x06: return "TIME_WAIT";
    case 0x07: return "CLOSE";
    case 0x08: return "CLOSE_WAIT";
    case 0x09: return "LAST_ACK";
    case 0x0A: return "LISTEN";
    case 0x0B: return "CLOSING";
    case 0x0C: return "NEW_SYN_RECV";
    default:   return "UNKNOWN";
  }
}

// Display order for summaries (stable, logical)
static const std::vector<std::string>& state_order() {
  static const std::vector<std::string> order = {
    "LISTEN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
    "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "CLOSING", "NEW_SYN_RECV", "UNKNOWN"};
  return order;
}

// Short state for narrow tables
static std::string state_short(const std::string& s) {
  if (s == "ESTABLISHED") return "ESTAB";
  if (s == "SYN_RECV")    return "SYN_RECV";
  if (s == "FIN_WAIT1")   return "FIN_WAIT1";
  if (s == "FIN_WAIT2")   return "FIN_WAIT2";
  if (s == "TIME_WAIT")   return "TIME_WAIT";
  if (s == "CLOSE_WAIT")  return "CLOSE_WAIT";
  if (s == "LAST_ACK")    return "LAST_ACK";
  if (s == "NEW_SYN_RECV")return "NEW_SYN";
  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Address decoding
//   /proc/net/tcp   : "0100007F" -> 127.0.0.1   (little-endian uint32)
//   /proc/net/tcp6  : 32 hex chars = 4 uint32 words. Each group g is the
//                     LITTLE-ENDIAN memory image of network word W_g (kernel
//                     prints __be32 words with %08X on a LE host), and the
//                     groups are in order: group 0 = W0 ... group 3 = W3.
//                     "0000000000000000FFFF00000100007F" -> ::ffff:127.0.0.1
//                     Verified against real /proc/net/tcp6 (172.16.1.2 host):
//                     "0000000000000000FFFF0000020110AC" -> ::ffff:172.16.1.2
// ─────────────────────────────────────────────────────────────────────────────
static bool decode_addr(std::string_view hex, bool ipv6, std::array<uint8_t, 16>& out, int& len) {
  if (ipv6) {
    if (hex.size() != 32) return false;
    for (int g = 0; g < 4; ++g) {
      auto v = parse_hex(hex.substr(static_cast<size_t>(g) * 8, 8));
      if (!v) return false;
      uint32_t w = static_cast<uint32_t>(*v);  // byte-swapped image of W_g (kernel %08X on LE host)
      int off = g * 4;                         // W_g occupies bytes [g*4 .. g*4+3]
      out[static_cast<size_t>(off) + 0] = static_cast<uint8_t>(w & 0xff);
      out[static_cast<size_t>(off) + 1] = static_cast<uint8_t>((w >> 8) & 0xff);
      out[static_cast<size_t>(off) + 2] = static_cast<uint8_t>((w >> 16) & 0xff);
      out[static_cast<size_t>(off) + 3] = static_cast<uint8_t>((w >> 24) & 0xff);
    }
    len = 16;
    return true;
  }
  if (hex.size() != 8) return false;
  auto v = parse_hex(hex);
  if (!v) return false;
  uint32_t w = static_cast<uint32_t>(*v);
  out[0] = static_cast<uint8_t>(w & 0xff);
  out[1] = static_cast<uint8_t>((w >> 8) & 0xff);
  out[2] = static_cast<uint8_t>((w >> 16) & 0xff);
  out[3] = static_cast<uint8_t>((w >> 24) & 0xff);
  len = 4;
  return true;
}

static std::string fmt_ipv4(const std::array<uint8_t, 16>& b) {
  char buf[24];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
  return buf;
}

static std::string fmt_ipv6(const std::array<uint8_t, 16>& b) {
  // IPv4-mapped ::ffff:a.b.c.d
  bool mapped = true;
  for (int i = 0; i < 10; ++i) if (b[static_cast<size_t>(i)] != 0) { mapped = false; break; }
  if (mapped && b[10] == 0xff && b[11] == 0xff) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "::ffff:%u.%u.%u.%u", b[12], b[13], b[14], b[15]);
    return buf;
  }
  uint16_t w[8];
  for (int i = 0; i < 8; ++i)
    w[i] = static_cast<uint16_t>((static_cast<uint16_t>(b[static_cast<size_t>(i) * 2]) << 8) |
                                  static_cast<uint16_t>(b[static_cast<size_t>(i) * 2 + 1]));
  // longest run of zero words (>= 2) -> "::"
  int best_start = -1, best_len = 0;
  for (int i = 0; i < 8;) {
    if (w[i] == 0) {
      int j = i;
      while (j < 8 && w[j] == 0) ++j;
      if (j - i >= 2 && j - i > best_len) { best_start = i; best_len = j - i; }
      i = j;
    } else ++i;
  }
  std::string out;
  for (int i = 0; i < 8;) {
    if (i == best_start) {
      out += "::";
      i += best_len;
      continue;
    }
    if (!out.empty() && out.back() != ':') out += ':';
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%x", w[i]);
    out += buf;
    ++i;
  }
  if (out.empty()) out = "::";
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Data model — one TCP connection from /proc/net/tcp(|6)
// ─────────────────────────────────────────────────────────────────────────────
struct TcpConn {
  std::array<uint8_t, 16> local{};
  int local_len = 0;
  uint16_t lport = 0;
  std::array<uint8_t, 16> remote{};
  int remote_len = 0;
  uint16_t rport = 0;
  uint8_t state_code = 0;
  std::string state;
  unsigned uid = 0;
  unsigned long long tx = 0, rx = 0;
  std::string inode;
  int pid = -1;
  std::string proc;
  bool ipv6 = false;

  std::string local_str() const {
    char buf[80];
    if (local_len == 16)
      std::snprintf(buf, sizeof(buf), "[%s]:%u", fmt_ipv6(local).c_str(), lport);
    else
      std::snprintf(buf, sizeof(buf), "%s:%u", fmt_ipv4(local).c_str(), lport);
    return buf;
  }
  std::string remote_str() const {
    bool wildcard = rport == 0;
    for (int i = 0; wildcard && i < remote_len; ++i)
      if (remote[static_cast<size_t>(i)] != 0) wildcard = false;
    if (wildcard) return "*";
    char buf[80];
    if (remote_len == 16)
      std::snprintf(buf, sizeof(buf), "[%s]:%u", fmt_ipv6(remote).c_str(), rport);
    else
      std::snprintf(buf, sizeof(buf), "%s:%u", fmt_ipv4(remote).c_str(), rport);
    return buf;
  }
  std::string proc_str() const {
    if (pid < 0) return "-";
    if (proc.empty()) return std::to_string(pid);
    return proc;
  }
};

struct Snapshot {
  std::vector<TcpConn> conns;
  long long ts = 0;

  std::map<std::string, unsigned long long> by_state() const {
    std::map<std::string, unsigned long long> m;
    for (auto& c : conns) ++m[c.state];
    return m;
  }
  unsigned long long count_state(const std::string& s) const {
    unsigned long long n = 0;
    for (auto& c : conns) if (c.state == s) ++n;
    return n;
  }
  unsigned long long total() const { return conns.size(); }
  unsigned long long ipv4() const {
    unsigned long long n = 0;
    for (auto& c : conns) if (!c.ipv6) ++n;
    return n;
  }
  unsigned long long ipv6() const {
    unsigned long long n = 0;
    for (auto& c : conns) if (c.ipv6) ++n;
    return n;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Parsing
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_tcp_file(const std::string& path, bool ipv6, std::vector<TcpConn>& out) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  bool first = true;
  while (std::getline(f, line)) {
    if (first) { first = false; continue; }  // header: sl local rem st tx:rx ...
    auto toks = split_ws(line);
    if (toks.size() < 10) continue;  // malformed -> skip, never break the rest
    auto parse_endpoint = [&](const std::string& ep, std::array<uint8_t, 16>& addr,
                              int& len, uint16_t& port) -> bool {
      auto colon = ep.find(':');
      if (colon == std::string::npos) return false;
      auto p = parse_hex(std::string_view(ep).substr(colon + 1));
      if (!p || *p > 65535) return false;
      port = static_cast<uint16_t>(*p);
      return decode_addr(std::string_view(ep).substr(0, colon), ipv6, addr, len);
    };
    TcpConn c;
    c.ipv6 = ipv6;
    if (!parse_endpoint(toks[1], c.local, c.local_len, c.lport)) continue;
    if (!parse_endpoint(toks[2], c.remote, c.remote_len, c.rport)) continue;
    auto st = parse_hex(toks[3]);
    c.state_code = st ? static_cast<uint8_t>(*st) : 0;
    c.state = state_name(c.state_code);
    auto qpos = toks[4].find(':');
    if (qpos != std::string::npos) {
      if (auto tx = parse_hex(std::string_view(toks[4]).substr(0, qpos))) c.tx = *tx;
      if (auto rx = parse_hex(std::string_view(toks[4]).substr(qpos + 1))) c.rx = *rx;
    }
    if (auto uid = parse_ull(toks[7])) c.uid = static_cast<unsigned>(*uid);
    c.inode = toks[9];
    out.push_back(std::move(c));
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// inode -> pid -> process name resolution (scan /proc/*/fd socket symlinks)
// ─────────────────────────────────────────────────────────────────────────────
static std::map<std::string, int> scan_socket_pids() {
  std::map<std::string, int> out;
  std::error_code ec;
  std::filesystem::directory_iterator proc_it("/proc", ec);
  std::filesystem::directory_iterator proc_end;
  for (; proc_it != proc_end; proc_it.increment(ec)) {
    if (ec) { ec.clear(); continue; }
    const std::string name = proc_it->path().filename().string();
    if (name.empty() || !std::all_of(name.begin(), name.end(),
                                     [](unsigned char c) { return std::isdigit(c); }))
      continue;
    auto pidv = parse_ull(name);
    if (!pidv) continue;
    const std::string fd_dir = proc_it->path().string() + "/fd";
    std::filesystem::directory_iterator fd_it(fd_dir, ec);
    std::filesystem::directory_iterator fd_end;
    for (; fd_it != fd_end; fd_it.increment(ec)) {
      if (ec) { ec.clear(); continue; }
      char buf[256];
      ssize_t n = readlink(fd_it->path().c_str(), buf, sizeof(buf) - 1);
      if (n <= 0) continue;
      buf[n] = '\0';
      std::string_view t{buf, static_cast<size_t>(n)};
      constexpr std::string_view prefix = "socket:[";
      if (t.starts_with(prefix) && t.size() > prefix.size() + 1 && t.back() == ']') {
        std::string inode{t.substr(prefix.size(), t.size() - prefix.size() - 1)};
        if (!out.contains(inode)) out[std::move(inode)] = static_cast<int>(*pidv);
      }
    }
  }
  return out;
}

static std::string read_comm(int pid) {
  std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
  std::string s;
  std::getline(f, s);
  return s;
}

static void resolve_procs(std::vector<TcpConn>& conns) {
  auto inode_map = scan_socket_pids();
  if (inode_map.empty()) return;
  std::map<int, std::string> comm_cache;
  for (auto& c : conns) {
    if (c.inode.empty()) continue;
    auto it = inode_map.find(c.inode);
    if (it == inode_map.end()) continue;
    c.pid = it->second;
    auto cit = comm_cache.find(c.pid);
    if (cit == comm_cache.end()) {
      auto comm = read_comm(c.pid);
      if (comm.size() > 15) comm = comm.substr(0, 15);
      cit = comm_cache.emplace(c.pid, std::move(comm)).first;
    }
    c.proc = cit->second;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot read
// ─────────────────────────────────────────────────────────────────────────────
static Snapshot read_snapshot(bool resolve) {
  Snapshot s;
  s.ts = static_cast<long long>(std::chrono::system_clock::now().time_since_epoch().count() /
                                std::chrono::system_clock::period::den *
                                std::chrono::system_clock::period::num);
  parse_tcp_file("/proc/net/tcp", false, s.conns);
  parse_tcp_file("/proc/net/tcp6", true, s.conns);
  if (resolve) resolve_procs(s.conns);
  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────────────────────────
static std::string state_color(const std::string& s) {
  if (s == "LISTEN")        return C_CYAN;
  if (s == "ESTABLISHED")   return C_GREEN;
  if (s == "TIME_WAIT")     return C_DIM;
  if (s == "CLOSE")         return C_DIM;
  if (s == "CLOSING")       return C_RED;
  if (s == "NEW_SYN_RECV")  return C_YELLOW;
  if (s == "SYN_SENT" || s == "SYN_RECV" || s == "FIN_WAIT1" || s == "FIN_WAIT2" ||
      s == "CLOSE_WAIT" || s == "LAST_ACK")
    return C_YELLOW;
  return C_RESET;
}

static std::string colorize(const std::string& s, const std::string& color) {
  return color + s + C_RESET;
}

static void render_snapshot(const Snapshot& s, int top) {
  std::cout << C_BOLD << "  TCP WATCH — /proc/net/tcp + tcp6" << C_RESET << "\n";
  std::cout << "  ------------------------------------------------------------------------------\n";

  // Listeners
  std::vector<const TcpConn*> listeners, active;
  for (auto& c : s.conns) {
    if (c.state == "LISTEN") listeners.push_back(&c);
    else active.push_back(&c);
  }
  std::sort(listeners.begin(), listeners.end(),
            [](const TcpConn* a, const TcpConn* b) { return a->lport < b->lport; });
  std::sort(active.begin(), active.end(), [](const TcpConn* a, const TcpConn* b) {
    auto qa = a->tx + a->rx, qb = b->tx + b->rx;
    if (qa != qb) return qa > qb;
    return a->lport < b->lport;
  });

  std::cout << C_CYAN << "  LISTENERS (" << listeners.size() << ")" << C_RESET << "\n";
  std::cout << C_DIM << "  LOCAL                          STATE        UID    PID  PROCESS       INODE" << C_RESET << "\n";
  for (auto* c : listeners) {
    char buf[160];
    std::snprintf(buf, sizeof(buf), "  %-30s %-13s %-6u %-5d %-13s %s",
                  c->local_str().c_str(), c->state.c_str(), c->uid,
                  c->pid < 0 ? -1 : c->pid, c->proc_str().c_str(), c->inode.c_str());
    std::cout << colorize(buf, state_color(c->state)) << "\n";
  }

  std::cout << "\n";
  std::cout << C_GREEN << "  ACTIVE CONNECTIONS" << C_RESET;
  if (top > 0 && static_cast<int>(active.size()) > top)
    std::cout << C_DIM << "  (top " << top << " of " << active.size() << " by queue bytes)" << C_RESET;
  std::cout << "\n";
  std::cout << C_DIM << "  LOCAL                          REMOTE                         STATE        UID    PID  PROCESS       TX/RX" << C_RESET << "\n";
  size_t shown = 0;
  for (auto* c : active) {
    if (top > 0 && shown >= static_cast<size_t>(top)) break;
    char buf[180];
    std::snprintf(buf, sizeof(buf), "  %-30s %-30s %-13s %-6u %-5d %-13s %s",
                  c->local_str().c_str(), c->remote_str().c_str(), state_short(c->state).c_str(),
                  c->uid, c->pid < 0 ? -1 : c->pid, c->proc_str().c_str(),
                  (fmt_num(c->tx) + ":" + fmt_num(c->rx)).c_str());
    std::cout << colorize(buf, state_color(c->state)) << "\n";
    ++shown;
  }

  // Summary
  auto by = s.by_state();
  std::cout << "  ------------------------------------------------------------------------------\n";
  std::string summary = "  SUMMARY  total " + fmt_num(s.total()) +
                        "  ipv4 " + fmt_num(s.ipv4()) + "  ipv6 " + fmt_num(s.ipv6());
  for (auto& st : state_order()) {
    auto it = by.find(st);
    if (it != by.end() && it->second > 0)
      summary += "   " + colorize(state_short(st) + " " + fmt_num(it->second), state_color(st));
  }
  std::cout << summary << "\n";
}

static void render_ports(const Snapshot& s, int top) {
  std::map<uint16_t, std::map<std::string, unsigned long long>> by_port;
  for (auto& c : s.conns) ++by_port[c.lport][c.state];
  std::vector<std::pair<uint16_t, unsigned long long>> ports;
  for (auto& [p, m] : by_port) {
    unsigned long long n = 0;
    for (auto& [st, cnt] : m) n += cnt;
    ports.emplace_back(p, n);
  }
  std::sort(ports.begin(), ports.end(),
            [](auto& a, auto& b) { return a.second != b.second ? a.second > b.second : a.first < b.first; });
  int n = top > 0 ? std::min<int>(top, static_cast<int>(ports.size())) : static_cast<int>(ports.size());
  std::cout << C_BOLD << "  TCP WATCH — top " << n << " local ports by connections" << C_RESET << "\n";
  std::cout << "  ------------------------------------------------------------------------------\n";
  std::cout << C_DIM << "  PORT   CONNS  STATE BREAKDOWN" << C_RESET << "\n";
  for (int i = 0; i < n; ++i) {
    auto [p, total] = ports[static_cast<size_t>(i)];
    auto& m = by_port[p];
    std::string states;
    for (auto& st : state_order()) {
      auto it = m.find(st);
      if (it != m.end() && it->second > 0) {
        if (!states.empty()) states += "  ";
        states += colorize(state_short(st) + " " + fmt_num(it->second), state_color(st));
      }
    }
    char buf[160];
    std::snprintf(buf, sizeof(buf), "  %-6u %-6s %s", p, fmt_num(total).c_str(), states.c_str());
    std::cout << buf << "\n";
  }
}

static void render_watch(const Snapshot& prev, const Snapshot& cur, double dt, int top) {
  auto pb = prev.by_state(), cb = cur.by_state();
  std::cout << "\x1b[2J\x1b[H";  // clear screen
  std::cout << C_BOLD << "  TCP WATCH — /proc/net/tcp + tcp6 — live (elapsed " << dt << "s)" << C_RESET << "\n";
  std::cout << "  ------------------------------------------------------------------------------\n";
  std::string line;
  for (auto& st : state_order()) {
    auto itc = cb.find(st);
    if (itc == cb.end() || itc->second == 0) continue;
    auto itp = pb.find(st);
    long long delta = itp == pb.end() ? static_cast<long long>(itc->second)
                                      : static_cast<long long>(itc->second) - static_cast<long long>(itp->second);
    if (!line.empty()) line += "   ";
    line += colorize(state_short(st) + " " + fmt_num(itc->second), state_color(st));
    if (dt > 0 && delta != 0)
      line += C_DIM + " (" + fmt_signed_rate(delta, dt) + ")" + C_RESET;
  }
  long long tdelta = static_cast<long long>(cur.total()) - static_cast<long long>(prev.total());
  line += "   " + colorize("TOTAL " + fmt_num(cur.total()), C_BOLD);
  if (dt > 0) line += C_DIM + " (" + fmt_signed_rate(tdelta, dt) + ")" + C_RESET;
  std::cout << "  " << line << "\n";
  std::cout << "  ------------------------------------------------------------------------------\n";

  // Top listeners by port + busiest established (from current snapshot)
  std::vector<const TcpConn*> listeners, active;
  for (auto& c : cur.conns) {
    if (c.state == "LISTEN") listeners.push_back(&c);
    else active.push_back(&c);
  }
  std::sort(listeners.begin(), listeners.end(),
            [](const TcpConn* a, const TcpConn* b) { return a->lport < b->lport; });
  std::sort(active.begin(), active.end(), [](const TcpConn* a, const TcpConn* b) {
    auto qa = a->tx + a->rx, qb = b->tx + b->rx;
    if (qa != qb) return qa > qb;
    return a->lport < b->lport;
  });
  std::cout << C_CYAN << "  LISTENERS" << C_RESET << "  ";
  size_t shown = 0;
  for (auto* c : listeners) {
    if (shown >= 8) break;
    if (shown) std::cout << "  ";
    std::cout << colorize(c->local_str(), C_CYAN);
    ++shown;
  }
  std::cout << "\n";
  std::cout << C_GREEN << "  BUSIEST ESTABLISHED" << C_RESET << "\n";
  std::cout << C_DIM << "  LOCAL                          REMOTE                         STATE  PID  PROCESS       TX/RX" << C_RESET << "\n";
  shown = 0;
  for (auto* c : active) {
    if (c->state != "ESTABLISHED") continue;
    if (shown >= static_cast<size_t>(top > 0 ? top : 10)) break;
    char buf[180];
    std::snprintf(buf, sizeof(buf), "  %-30s %-30s %-6s %-5d %-13s %s",
                  c->local_str().c_str(), c->remote_str().c_str(), "ESTAB",
                  c->pid < 0 ? -1 : c->pid, c->proc_str().c_str(),
                  (fmt_num(c->tx) + ":" + fmt_num(c->rx)).c_str());
    std::cout << colorize(buf, state_color(c->state)) << "\n";
    ++shown;
  }
  std::cout << "  ------------------------------------------------------------------------------\n";
  std::cout << C_DIM << "  Ctrl+C para salir — " << cur.conns.size() << " conexiones, "
            << cur.ipv4() << " ipv4 / " << cur.ipv6() << " ipv6" << C_RESET << "\n";
  std::cout << std::flush;  // fully-buffered stdout on pipes — flush every frame
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON output
// ─────────────────────────────────────────────────────────────────────────────
static std::string json_escape(const std::string& s) {
  std::string out;
  for (char ch : s) {
    if (ch == '"' || ch == '\\') { out += '\\'; out += ch; }
    else if (ch == '\n') out += "\\n";
    else out += ch;
  }
  return out;
}

static void render_json(const Snapshot& s) {
  std::cout << "{\n";
  std::cout << "  \"timestamp\": " << s.ts << ",\n";
  std::cout << "  \"connections\": {\n";
  std::cout << "    \"total\": " << s.total() << ",\n";
  std::cout << "    \"ipv4\": " << s.ipv4() << ",\n";
  std::cout << "    \"ipv6\": " << s.ipv6() << ",\n";
  auto by = s.by_state();
  std::cout << "    \"by_state\": {";
  bool first = true;
  for (auto& [st, cnt] : by) {
    if (!first) std::cout << ",";
    first = false;
    std::cout << "\"" << st << "\": " << cnt;
  }
  std::cout << "}\n";
  std::cout << "  },\n";
  std::cout << "  \"connections_list\": [\n";
  for (size_t i = 0; i < s.conns.size(); ++i) {
    auto& c = s.conns[i];
    char buf[256];
    std::snprintf(buf, sizeof(buf),
      "    {\"local\":\"%s\",\"remote\":\"%s\",\"state\":\"%s\",\"uid\":%u,\"pid\":%d,"
      "\"proc\":\"%s\",\"tx\":%llu,\"rx\":%llu,\"inode\":\"%s\",\"family\":\"%s\"}",
      json_escape(c.local_str()).c_str(), json_escape(c.remote_str()).c_str(),
      c.state.c_str(), c.uid, c.pid, json_escape(c.proc).c_str(),
      static_cast<unsigned long long>(c.tx), static_cast<unsigned long long>(c.rx),
      c.inode.c_str(), c.ipv6 ? "ipv6" : "ipv4");
    std::cout << buf << (i + 1 < s.conns.size() ? "," : "") << "\n";
  }
  std::cout << "  ],\n";
  std::cout << "  \"summary\": {"
            << "\"established\": " << s.count_state("ESTABLISHED") << ", "
            << "\"listeners\": " << s.count_state("LISTEN") << ", "
            << "\"time_wait\": " << s.count_state("TIME_WAIT") << ", "
            << "\"close_wait\": " << s.count_state("CLOSE_WAIT") << ", "
            << "\"syn_sent\": " << s.count_state("SYN_SENT") << ", "
            << "\"others\": " << (s.total() - s.count_state("ESTABLISHED") - s.count_state("LISTEN") -
                                  s.count_state("TIME_WAIT") - s.count_state("CLOSE_WAIT") -
                                  s.count_state("SYN_SENT"))
            << "}\n";
  std::cout << "}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo mode — synthetic connections for containers/VMs where /proc is masked
// ─────────────────────────────────────────────────────────────────────────────
static uint32_t g_lcg = 0x2F6E2B1;
static uint32_t lcg() {
  g_lcg = g_lcg * 1664525u + 1013904223u;
  return g_lcg;
}

static TcpConn demo_conn(const std::string& local, uint16_t lport,
                         const std::string& remote, uint16_t rport,
                         const std::string& state, unsigned uid, int pid,
                         const std::string& proc, const std::string& inode,
                         bool ipv6) {
  TcpConn c;
  c.ipv6 = ipv6;
  auto fill = [&](const std::string& host, std::array<uint8_t, 16>& addr, int& len) {
    if (ipv6 && host.find('.') == std::string::npos) {
      // parse "a:b:c:d:e:f:g:h" with optional "::" compression
      std::vector<std::string> parts;
      std::istringstream ss{host};
      std::string part;
      while (std::getline(ss, part, ':')) parts.push_back(part);
      size_t non_empty = 0;
      for (auto& p : parts) if (!p.empty()) ++non_empty;
      size_t zeros = 8 - non_empty;
      size_t idx = 0;
      bool expanded = false;
      for (auto& p : parts) {
        if (p.empty() && !expanded && zeros > 0) {
          idx += zeros;
          expanded = true;
          continue;
        }
        if (p.empty()) continue;
        auto v = parse_hex(p);
        if (v && idx < 8) {
          addr[idx * 2] = static_cast<uint8_t>(*v >> 8);
          addr[idx * 2 + 1] = static_cast<uint8_t>(*v & 0xff);
        }
        ++idx;
      }
      len = 16;
    } else {
      // dotted quad
      std::istringstream ss{host};
      std::string part;
      int idx = 0;
      while (std::getline(ss, part, '.') && idx < 4) {
        auto v = parse_ull(part);
        if (v) addr[static_cast<size_t>(idx)] = static_cast<uint8_t>(*v);
        ++idx;
      }
      len = 4;
    }
  };
  fill(local, c.local, c.local_len);
  c.lport = lport;
  fill(remote, c.remote, c.remote_len);
  c.rport = rport;
  c.state = state;
  c.uid = uid;
  c.pid = pid;
  c.proc = proc;
  c.inode = inode;
  c.tx = lcg() % 65536;
  c.rx = lcg() % 65536;
  return c;
}

static Snapshot demo_snapshot(int tick) {
  Snapshot s;
  s.ts = tick;
  // Listeners
  s.conns.push_back(demo_conn("0.0.0.0", 22, "0.0.0.0", 0, "LISTEN", 0, 812, "sshd", "3E8B", false));
  s.conns.push_back(demo_conn("0.0.0.0", 80, "0.0.0.0", 0, "LISTEN", 0, 1042, "nginx", "3F0A", false));
  s.conns.push_back(demo_conn("0.0.0.0", 443, "0.0.0.0", 0, "LISTEN", 0, 1042, "nginx", "3F0B", false));
  s.conns.push_back(demo_conn("127.0.0.1", 3000, "0.0.0.0", 0, "LISTEN", 1000, 5123, "node", "401F", false));
  s.conns.push_back(demo_conn("0.0.0.0", 5432, "0.0.0.0", 0, "LISTEN", 111, 918, "postgres", "3D2C", false));
  s.conns.push_back(demo_conn("127.0.0.1", 8080, "0.0.0.0", 0, "LISTEN", 1000, 3311, "java", "4210", false));
  s.conns.push_back(demo_conn("::", 22, "::", 0, "LISTEN", 0, 812, "sshd", "3E8C", true));
  s.conns.push_back(demo_conn("::", 443, "::", 0, "LISTEN", 0, 1042, "nginx", "3F0D", true));
  // Established (grow with tick)
  struct Row { const char* local; uint16_t lp; const char* remote; uint16_t rp; const char* proc; int pid; const char* inode; bool v6; };
  static const Row rows[] = {
    {"10.0.0.5", 51234, "142.250.184.46", 443, "chrome", 4821, "44A1", false},
    {"10.0.0.5", 51235, "142.250.184.46", 443, "chrome", 4821, "44A2", false},
    {"10.0.0.5", 52110, "151.101.1.69", 443, "firefox", 4902, "44B0", false},
    {"10.0.0.5", 53001, "8.8.8.8", 443, "curl", 7777, "44C5", false},
    {"10.0.0.5", 54000, "20.54.36.21", 443, "node", 5123, "44D9", false},
    {"10.0.0.5", 54443, "13.107.42.14", 443, "code", 5330, "44E2", false},
    {"192.168.1.10", 22, "192.168.1.1", 51222, "sshd", 812, "44F1", false},
    {"10.0.0.5", 49152, "172.217.16.14", 5228, "chrome", 4821, "4500", false},
    {"10.0.0.5", 55001, "140.82.112.4", 443, "git", 5490, "4511", false},
    {"10.0.0.5", 56000, "34.120.208.123", 443, "docker", 6012, "4522", false},
    {"10.0.0.5", 57001, "35.186.224.25", 443, "kubectl", 6020, "4533", false},
    {"2001:db8::5", 51000, "2606:4700::6810", 443, "curl", 7777, "45A1", true},
    {"2001:db8::5", 52000, "2a00:1450:4001:81f::200e", 443, "firefox", 4902, "45B2", true},
  };
  size_t base = sizeof(rows) / sizeof(rows[0]);
  size_t est = base + static_cast<size_t>(tick % 3);
  for (size_t i = 0; i < est && i < base + 3; ++i) {
    auto& r = rows[i % base];
    char inode[16];
    std::snprintf(inode, sizeof(inode), "%X", 0x4400u + static_cast<uint32_t>(i) + static_cast<uint32_t>(tick) * 17u);
    s.conns.push_back(demo_conn(r.local, static_cast<uint16_t>(r.lp + (i == est - 1 ? 1 : 0)), r.remote, r.rp, "ESTABLISHED", 1000, r.pid, r.proc, inode, r.v6));
  }
  // TIME_WAIT — grows with tick
  int tw = 4 + (tick % 3);
  for (int i = 0; i < tw; ++i) {
    char inode[16];
    std::snprintf(inode, sizeof(inode), "%X", 0x5000u + static_cast<uint32_t>(i) + static_cast<uint32_t>(tick) * 7u);
    s.conns.push_back(demo_conn("10.0.0.5", static_cast<uint16_t>(59000 + i), "93.184.216.34", 443, "TIME_WAIT", 1000, -1, "", inode, false));
  }
  // SYN_SENT — 1 or 2
  for (int i = 0; i < 1 + (tick % 2); ++i) {
    char inode[16];
    std::snprintf(inode, sizeof(inode), "%X", 0x6000u + static_cast<uint32_t>(i) + static_cast<uint32_t>(tick) * 11u);
    s.conns.push_back(demo_conn("10.0.0.5", static_cast<uint16_t>(58000 + i), "104.26.3.99", 443, "SYN_SENT", 1000, -1, "", inode, false));
  }
  // CLOSE_WAIT — 1 stable
  s.conns.push_back(demo_conn("10.0.0.5", 59099, "104.26.10.99", 443, "CLOSE_WAIT", 1000, 5490, "git", "4700", false));
  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-test
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0, g_skip = 0;

static void check(const std::string& name, bool ok) {
  if (ok) {
    ++g_pass;
    std::cout << C_GREEN << "  PASS" << C_RESET << "  " << name << "\n";
  } else {
    ++g_fail;
    std::cout << C_RED << "  FAIL" << C_RESET << "  " << name << "\n";
  }
}

static void run_selftest() {
  // ── Address decoding ──
  std::array<uint8_t, 16> addr{};
  int len = 0;
  check("addr: ipv4 0100007F -> 127.0.0.1",
        decode_addr("0100007F", false, addr, len) && len == 4 && fmt_ipv4(addr) == "127.0.0.1");
  check("addr: ipv4 00000000 -> 0.0.0.0",
        decode_addr("00000000", false, addr, len) && fmt_ipv4(addr) == "0.0.0.0");
  check("addr: ipv4 E000010A -> 10.1.0.224",
        decode_addr("E000010A", false, addr, len) && fmt_ipv4(addr) == "10.1.0.224");
  check("addr: ipv6 ::1",
        decode_addr("00000000000000000000000001000000", true, addr, len) &&
        len == 16 && fmt_ipv6(addr) == "::1");
  check("addr: ipv6 ipv4-mapped ::ffff:127.0.0.1",
        decode_addr("0000000000000000FFFF00000100007F", true, addr, len) &&
        fmt_ipv6(addr) == "::ffff:127.0.0.1");
  check("addr: ipv6 2001:db8::1",
        decode_addr("B80D0120000000000000000001000000", true, addr, len) &&
        fmt_ipv6(addr) == "2001:db8::1");
  check("addr: ipv6 real del host (172.16.1.2 mapeado)",
        decode_addr("0000000000000000FFFF0000020110AC", true, addr, len) &&
        fmt_ipv6(addr) == "::ffff:172.16.1.2");

  // ── Port decoding ──
  auto p8080 = parse_hex("1F90");
  auto p80 = parse_hex("0050");
  check("port: 1F90 -> 8080", p8080 && *p8080 == 8080);
  check("port: 0050 -> 80", p80 && *p80 == 80);

  // ── State decode ──
  check("state: 0A -> LISTEN", state_name(0x0A) == "LISTEN");
  check("state: 01 -> ESTABLISHED", state_name(0x01) == "ESTABLISHED");
  check("state: 06 -> TIME_WAIT", state_name(0x06) == "TIME_WAIT");
  check("state: 08 -> CLOSE_WAIT", state_name(0x08) == "CLOSE_WAIT");
  check("state: 0B -> CLOSING", state_name(0x0B) == "CLOSING");
  check("state: FF -> UNKNOWN", state_name(0xFF) == "UNKNOWN");

  // ── Line parsing (synthetic /proc/net/tcp) ──
  std::vector<TcpConn> conns;
  std::ofstream tmp("/tmp/tcp-watch-selftest-tcp");
  tmp << "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
  tmp << "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 258867 1 0000000000000000 100 0 0 10 0\n";
  tmp << "   1: 0100007F:9D1C 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 258868 1 0000000000000000 100 0 0 10 0\n";
  tmp << "   broken-line-that-is-too-short\n";
  tmp << "   2: 0100007F:9D1D 0100007F:1F90 06 00000000:00000000 00:00000000 00000000  1000        0 258869\n";
  tmp.close();
  bool ok = parse_tcp_file("/tmp/tcp-watch-selftest-tcp", false, conns);
  check("parse: archivo sintetico leido", ok);
  check("parse: linea malformada se salta sin romper el resto", conns.size() == 3);
  check("parse: listener local 127.0.0.1:8080",
        conns[0].local_str() == "127.0.0.1:8080" && conns[0].state == "LISTEN" && conns[0].uid == 0);
  check("parse: establecido uid e inode",
        conns[1].state == "ESTABLISHED" && conns[1].uid == 1000 && conns[1].inode == "258868");
  check("parse: TIME_WAIT con campos extra (kernel 4.1+)",
        conns[2].state == "TIME_WAIT" && conns[2].inode == "258869");
  std::remove("/tmp/tcp-watch-selftest-tcp");

  // ── Aggregation ──
  Snapshot s;
  s.conns = conns;
  auto by = s.by_state();
  check("agg: counts por estado", by["LISTEN"] == 1 && by["ESTABLISHED"] == 1 && by["TIME_WAIT"] == 1);
  check("agg: total/ipv4", s.total() == 3 && s.ipv4() == 3 && s.ipv6() == 0);

  // ── Delta math ──
  Snapshot s2 = s;
  s2.conns.push_back(demo_conn("10.0.0.5", 50000, "8.8.8.8", 443, "ESTABLISHED", 1000, 1, "x", "A1", false));
  long long delta = static_cast<long long>(s2.count_state("ESTABLISHED")) - static_cast<long long>(s.count_state("ESTABLISHED"));
  check("delta: +1 establecido", delta == 1);
  check("delta: tasa 2 conns/0.5s = +4.0/s", fmt_signed_rate(2, 0.5) == "+4.0/s");

  // ── JSON ──
  std::ostringstream cap;
  auto* old = std::cout.rdbuf(cap.rdbuf());
  render_json(s);
  std::cout.rdbuf(old);
  std::string j = cap.str();
  check("json: contiene connections_list", j.find("\"connections_list\"") != std::string::npos);
  check("json: contiene by_state", j.find("\"by_state\"") != std::string::npos);
  check("json: claves con comillas", j.find("\"local\":") != std::string::npos);

  // ── Demo ──
  auto d0 = demo_snapshot(0);
  check("demo: listeners presentes", d0.count_state("LISTEN") == 8);
  check("demo: establecidos > 0", d0.count_state("ESTABLISHED") > 10);
  check("demo: estados validos", d0.count_state("UNKNOWN") == 0);
  check("demo: ipv6 presentes", d0.ipv6() >= 2);

  // ── --no-color ──
  disable_color();
  check("no-color: paleta vacia", C_RESET.empty() && C_RED.empty() && C_GREEN.empty());

  // ── Smoke test contra /proc real (condicional) ──
  std::ifstream real("/proc/net/tcp");
  if (real) {
    Snapshot rs;
    parse_tcp_file("/proc/net/tcp", false, rs.conns);
    parse_tcp_file("/proc/net/tcp6", true, rs.conns);
    bool any_listener = rs.count_state("LISTEN") > 0;
    check("smoke: /proc/net/tcp(+6) legible y con listeners", any_listener);
  } else {
    ++g_skip;
    std::cout << C_DIM << "  SKIP" << C_RESET << "  smoke: /proc/net/tcp no legible en contenedor\n";
  }

  std::cout << "  " << C_BOLD << g_pass << " passed, " << g_fail << " failed" << C_RESET
            << (g_skip ? "  " + C_DIM + "(" + std::to_string(g_skip) + " skip)" + C_RESET : "") << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void apply_state_filter(Snapshot& s, const std::string& state_filter) {
  std::string want = state_filter;
  std::transform(want.begin(), want.end(), want.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  static const std::map<std::string, std::string> shortmap = {
    {"ESTAB", "ESTABLISHED"}, {"SYN", "SYN_SENT"}, {"SYN_RECV", "SYN_RECV"},
    {"FIN1", "FIN_WAIT1"}, {"FIN2", "FIN_WAIT2"}, {"TW", "TIME_WAIT"},
    {"TIME", "TIME_WAIT"}, {"CLOSE_WAIT", "CLOSE_WAIT"}, {"LAST", "LAST_ACK"},
    {"LISTEN", "LISTEN"}, {"CLOSING", "CLOSING"}, {"NEW_SYN", "NEW_SYN_RECV"},
  };
  auto it = shortmap.find(want);
  if (it != shortmap.end()) want = it->second;
  std::vector<TcpConn> filtered;
  for (auto& c : s.conns) if (c.state == want) filtered.push_back(c);
  s.conns = std::move(filtered);
}

int main(int argc, char** argv) {
  int top = 15;
  int watch = 0;
  bool json = false, demo = false, ports = false, selftest = false, no_resolve = false;
  std::string state_filter;

  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    if (a == "--top" && i + 1 < argc) top = std::atoi(argv[++i]);
    else if (a == "--watch" && i + 1 < argc) watch = std::atoi(argv[++i]);
    else if (a == "--state" && i + 1 < argc) state_filter = argv[++i];
    else if (a == "--json") json = true;
    else if (a == "--demo") demo = true;
    else if (a == "--ports") ports = true;
    else if (a == "--no-resolve") no_resolve = true;
    else if (a == "--no-color") disable_color();
    else if (a == "--selftest") selftest = true;
    else if (a == "--help" || a == "-h") {
      std::cout << "Usage: ./tcp-watch [--top N] [--watch N] [--ports] [--state NAME]\n"
                   "                [--json] [--demo] [--no-resolve] [--no-color] [--selftest]\n"
                   "  --top N       filas de la tabla activa (default 15, 0 = todas)\n"
                   "  --watch N     modo live cada N segundos con tasas delta por estado\n"
                   "  --ports       top-N puertos locales por numero de conexiones\n"
                   "  --state NAME  filtrar por estado (ESTAB, LISTEN, TIME_WAIT, ...)\n"
                   "  --json        salida JSON completa para scripting\n"
                   "  --demo        datos sinteticos (contenedores/VMs sin /proc)\n"
                   "  --no-resolve  no resolver inode -> pid -> proceso\n"
                   "  --no-color    sin codigos ANSI (pipes/logs)\n"
                   "  --selftest    auto-verificacion\n";
      return 0;
    } else {
      std::cerr << "opcion desconocida: " << a << " (--help para ayuda)\n";
      return 2;
    }
  }

  if (selftest) {
    run_selftest();
    return g_fail ? 1 : 0;
  }

  if (demo) {
    auto ds = demo_snapshot(0);
    if (!state_filter.empty()) apply_state_filter(ds, state_filter);
    if (json) { render_json(ds); return 0; }
    if (ports) { render_ports(ds, top); return 0; }
    if (watch > 0) {
      auto prev = demo_snapshot(0);
      std::this_thread::sleep_for(std::chrono::seconds(watch));
      int tick = 1;
      while (true) {
        auto cur = demo_snapshot(tick);
        render_watch(prev, cur, watch, top);
        prev = std::move(cur);
        ++tick;
        std::this_thread::sleep_for(std::chrono::seconds(watch));
      }
    }
    render_snapshot(ds, top);
    return 0;
  }

  if (watch > 0) {
    auto prev = read_snapshot(!no_resolve);
    std::this_thread::sleep_for(std::chrono::seconds(watch));
    while (true) {
      auto t0 = std::chrono::steady_clock::now();
      auto cur = read_snapshot(!no_resolve);
      auto t1 = std::chrono::steady_clock::now();
      double dt = std::chrono::duration<double>(t1 - t0).count();
      if (dt <= 0) dt = watch;
      render_watch(prev, cur, dt, top);
      prev = std::move(cur);
      std::this_thread::sleep_for(std::chrono::seconds(watch));
    }
  }

  auto s = read_snapshot(!no_resolve);

  if (!state_filter.empty()) apply_state_filter(s, state_filter);

  if (json) { render_json(s); return 0; }
  if (ports) { render_ports(s, top); return 0; }
  render_snapshot(s, top);
  return 0;
}
