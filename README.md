# Man-In-The-Chisme
Herramienta de reconocimiento pasivo/activo de red con GUI en Tkinter. 
Hace ARP spoofing de subred completa vía bettercap (opcional) y captura tráfico con tshark, infiriendo SO por dispositivo (User-Agent, cabecera Server de HTTP/SSDP, NBNS, LLMNR, DHCP) y catalogando dominios visitados por servicio (streaming, redes sociales, gaming, etc.). Incluye un grafo de topología en vivo (gateway al centro, dispositivos alrededor).

Este script envenena ARP en toda la subred indicada. No usar sin permiso del propietario de la red.

## Requisitos

- Linux, con permisos de root/sudo
- Python 3.8+
- `tshark` (Wireshark) en PATH
- `bettercap` en PATH (no se necesita si usas `--skip-arp-spoof`)
- Tkinter:
  - Debian/Ubuntu: `sudo apt install python3-tk`
  - Arch/Manjaro: `sudo pacman -S tk`
 
## Uso

```bash
sudo python3 mitc.py -i wlo1
sudo python3 mitc.py -i eth0 --subnet 192.168.0.0/24
sudo python3 mitc.py -i eth0 --skip-arp-spoof
sudo python3 mitc.py -i eth0 --oui-file ieee_oui.csv
```


### Argumentos principales

| Flag | Descripción |
|---|---|
| `-i`, `--iface` | Interfaz de red a usar (obligatorio) |
| `--subnet` | Subred CIDR a envenenar; si se omite, se autodetecta |
| `--skip-arp-spoof` | No lanza `bettercap`; solo corre el análisis pasivo |
| `--filter` | Filtro BPF de captura (default: `ip or arp`) |
| `--enrich-unknown N` | Nivel de enriquecimiento para dispositivos sin identificar |
| `--include-internet` | Incluye tráfico fuera de la red privada en el análisis |
| `--bettercap-log` | Ruta del log de bettercap (default: `bettercap_output.log`) |
| `--aliases` | JSON con alias de dispositivo, keyados por MAC (default: `device_aliases.json`) |
| `--oui-file` | CSV MAC→fabricante para ampliar la tabla OUI embebida |
| `--no-pcap` | No guarda la captura cruda en disco |
| `--pcap-out` | Ruta del `.pcapng` de salida |

## Salidas

Al cerrar la GUI se generan automáticamente:
- `reporte_YYYYmmdd_HHMMSS.txt` — reporte final en texto
- `reporte_YYYYmmdd_HHMMSS.json` — mismo reporte en JSON
- `captura_YYYYmmdd_HHMMSS.pcapng` — captura cruda (salvo `--no-pcap`)

## Qué hace internamente

1. Verifica que corres como root y que `tshark`/`bettercap` existen.
2. Valida contra `tshark -G fields` qué campos opcionales (NBNS, DHCP, ARP, User-Agent, etc.) soporta tu versión instalada, desactivando señales puntuales si faltan.
3. (Opcional) Lanza `bettercap` para envenenar ARP en la subred.
4. Lanza `tshark` en modo captura + análisis en vivo, parseando cada paquete en un hilo separado.
5. Clasifica dominios visitados contra un catálogo de firmas por regex (streaming, redes sociales, mensajería, nube, gaming, compras, etc.).
6. Infiere hostname/SO de cada dispositivo combinando DHCP, User-Agent, cabecera Server, NBNS y LLMNR.
7. Muestra todo en una GUI con tema oscuro: tabla de dispositivos, feed en vivo, detalle por dispositivo y grafo de topología.
