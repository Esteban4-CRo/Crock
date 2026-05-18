#ifndef CROCK_H
#define CROCK_H

#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <thread>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/hmac.h>

struct CrackStatus {
    std::string bssid;
    std::string ssid;
    std::string current_key;
    std::string current_dict;
    long tried_keys;
    bool cracked;
    std::string result;
};

struct HandshakeData {
    u_char anonce[32], snonce[32];
    u_char ap_mac[6], cli_mac[6];
    std::vector<u_char> eapol_frame;
    u_char mic[16];
    bool complete;
    bool m1_seen;
};

struct APInfo {
  std::string bssid, ssid, encryption;
  int channel, signal;
  bool handshake_captured;
  std::vector<std::string> clients;
  HandshakeData handshake;
};

class Crock {
public:
  Crock();
  ~Crock();

  std::vector<std::string> list_interfaces();
  bool auto_monitor(const std::string &iface);
  bool restore_interface(const std::string &iface);
  bool set_interface(const std::string &iface);
  void set_channel(int channel);

  void start_scan();
  void targeted_attack(const std::string &bssid, const std::vector<std::string>& wordlists);
  void stop_scan();
  
  static CrackStatus global_status;
  const std::map<std::string, APInfo>& get_targets() const;
  void clear_targets();

  static std::atomic<bool> keep_running;
  static std::atomic<long> packet_count;

private:
  pcap_t *handle;
  std::string current_iface;
  char errbuf[PCAP_ERRBUF_SIZE];
  static std::mutex targets_mtx;
  std::thread hopper_thread;

  void channel_hopper();
  void crack_loop(std::string bssid, HandshakeData hs, std::string ssid, const std::vector<std::string>& wordlists);
  void send_deauth(const std::string &bssid_str);

  static std::map<std::string, APInfo> targets;
  static void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
  
  static void derive_pmk(const std::string &pass, const std::string &ssid, u_char *pmk);
  static void derive_ptk(const u_char *pmk, const u_char *ap_mac, const u_char *cli_mac, 
                        const u_char *anonce, const u_char *snonce, u_char *ptk);
  static bool verify_mic(const u_char *ptk, const std::vector<u_char> &frame, const u_char *orig_mic, bool use_md5 = false);
};

#endif
