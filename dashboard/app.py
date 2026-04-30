from flask import Flask, jsonify, render_template_string
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
import json
import ipaddress
import subprocess
import time

app = Flask(__name__)
WHITELIST = {"127.0.0.1", "192.168.1.1", "192.168.1.21"}

INCIDENT_LOG = Path("/home/dark/soc-node/logs/incidents.json")
SURICATA_LOG = Path("/var/log/suricata/eve.json")
COWRIE_LOG = Path("/home/dark/soc-node/cowrie-full/var/log/cowrie/cowrie.json")

MANUAL_GEO = {
    "192.168.1.14": {"flag": "🛡️", "country": "SOC Lab", "city": "Raspberry SOC", "lat": 48.8566, "lon": 2.3522},
    "192.168.1.18": {"flag": "💻", "country": "SOC Lab", "city": "Mac Attacker", "lat": 48.8666, "lon": 2.3333},
    "192.168.1.1": {"flag": "🌐", "country": "SOC Lab", "city": "Livebox", "lat": 48.8580, "lon": 2.3470},
}

PRIVATE_GEO = {"flag": "🏠", "country": "Internal Network", "city": "LAN", "lat": 48.8566, "lon": 2.3522}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def geo_for_ip(ip):
    if ip in MANUAL_GEO:
        return MANUAL_GEO[ip]
    try:
        if ipaddress.ip_address(ip).is_private:
            return PRIVATE_GEO
    except Exception:
        pass
    return {"flag": "🌐", "country": "Unknown Public", "city": "Unresolved", "lat": 20.0, "lon": 0.0}


def read_json_lines(path, limit=800):
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f.readlines()[-limit:]:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows




def get_blocked_ips():
    blocked = set()
    try:
        r = subprocess.run(
            ["sudo", "-n", "iptables", "-L", "INPUT", "-n"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2
        )
        for line in r.stdout.splitlines():
            if "DROP" in line:
                for p in line.split():
                    try:
                        ipaddress.ip_address(p)
                        blocked.add(p)
                    except:
                        pass
    except:
        pass
    return blocked


def read_incidents():
    blocked = get_blocked_ips()
    out = []
    for x in read_json_lines(INCIDENT_LOG):
        ip = x.get("src_ip", "unknown")
        g = geo_for_ip(ip)
        activity = x.get("activity", {})
        commands = activity.get("command_samples", [])
        out.append({
            "timestamp": x.get("timestamp", utc_now()),
            "src_ip": ip,
            "flag": g["flag"],
            "country": g["country"],
            "city": g["city"],
            "lat": g["lat"],
            "lon": g["lon"],
            "attack_stage": x.get("attack_stage", "unknown"),
            "severity": x.get("severity", "low"),
            "score": int(x.get("score", 0)),
            "reason": x.get("reason", "correlated_soc_incident"),
            "blocked": x.get("response", {}).get("blocked", False) or ip in blocked,
            "commands": ", ".join(commands[-3:]) if isinstance(commands, list) else "",
        })
    return out[-700:]


def read_suricata():
    out = []
    for e in read_json_lines(SURICATA_LOG):
        if e.get("event_type") != "alert":
            continue
        ip = e.get("src_ip", "unknown")
        g = geo_for_ip(ip)
        alert = e.get("alert", {})
        sev_num = int(alert.get("severity", 3))
        sev = "critical" if sev_num <= 1 else "high" if sev_num == 2 else "medium"
        out.append({
            "timestamp": e.get("timestamp", utc_now()),
            "src_ip": ip,
            "dest_port": e.get("dest_port"),
            "proto": e.get("proto"),
            "signature": alert.get("signature", "unknown"),
            "severity": sev,
            "flag": g["flag"],
            "country": g["country"],
            "city": g["city"],
            "lat": g["lat"],
            "lon": g["lon"],
        })
    return out[-900:]


def read_cowrie():
    allowed = {
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.command.input",
        "cowrie.session.connect",
        "cowrie.session.closed",
    }
    out = []
    for e in read_json_lines(COWRIE_LOG):
        if e.get("eventid") not in allowed:
            continue
        ip = e.get("src_ip")
        if not ip:
            continue
        g = geo_for_ip(ip)
        cmd = e.get("input") or ""
        eventid = e.get("eventid")

        sev = "low"
        if eventid == "cowrie.login.failed":
            sev = "high"
        elif eventid == "cowrie.login.success":
            sev = "high"
        elif eventid == "cowrie.command.input":
            bad = ["wget", "curl", "chmod", "chown", "bash", "sh", "crontab", "nc", "/dev/tcp", "rm -rf"]
            sev = "critical" if any(b in cmd.lower() for b in bad) else "high"

        out.append({
            "timestamp": e.get("timestamp", utc_now()),
            "src_ip": ip,
            "eventid": eventid,
            "username": e.get("username"),
            "password": e.get("password"),
            "command": cmd,
            "session": e.get("session"),
            "severity": sev,
            "flag": g["flag"],
            "country": g["country"],
            "city": g["city"],
            "lat": g["lat"],
            "lon": g["lon"],
        })
    return out[-1300:]


def get_system_info():
    def run(cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True).strip()
        except:
            return "N/A"

    return {
        "hostname": run("hostname"),
        "ip": run("hostname -I | awk '{print $1}'"),
        "uptime": run("uptime -p"),
        "cpu": run("top -bn1 | grep 'Cpu(s)' | awk '{print 100 - $8}'"),
        "memory": run("free -m | awk '/Mem:/ {printf \"%s/%s MB\", $3, $2}'"),
        "disk": run("df -h / | awk 'NR==2 {print $3\" / \"$2\" (\"$5\")\"}'"),

        "eth0": run("ip -brief addr show eth0"),
        "wlan0": run("ip -brief addr show wlan0"),

        "ssh": run("systemctl is-active ssh"),
        "suricata": run("systemctl is-active suricata"),
        "cowrie": run("systemctl is-active cowrie"),
        "network": run("systemctl is-active NetworkManager"),
    }

CACHE = {"ts": 0, "data": None}
CACHE_TTL = 2

def build_dashboard():
    incidents = read_incidents()
    suricata = read_suricata()
    cowrie = read_cowrie()
    blocked = get_blocked_ips()

    failed = [c for c in cowrie if c["eventid"] == "cowrie.login.failed"]
    success = [c for c in cowrie if c["eventid"] == "cowrie.login.success"]
    commands = [c for c in cowrie if c["eventid"] == "cowrie.command.input"]

    critical_count = sum(1 for i in incidents if i["severity"] == "critical") + sum(1 for c in cowrie if c["severity"] == "critical")
    high_count = sum(1 for i in incidents if i["severity"] == "high") + sum(1 for c in cowrie if c["severity"] == "high") + sum(1 for s in suricata if s["severity"] == "high")
    medium_count = sum(1 for i in incidents if i["severity"] == "medium") + sum(1 for s in suricata if s["severity"] == "medium")

    stages = Counter(i["attack_stage"] for i in incidents)
    signatures = Counter(s["signature"] for s in suricata)
    users = Counter(c.get("username") or "unknown" for c in failed)
    passwords = Counter(c.get("password") or "empty" for c in failed)

    attackers = defaultdict(lambda: {
        "score": 0, "incidents": 0, "alerts": 0, "failed": 0, "success": 0,
        "commands": 0, "flag": "", "country": "", "city": "", "lat": 0, "lon": 0
    })

    for i in incidents:
        a = attackers[i["src_ip"]]
        a["score"] += i["score"]
        a["incidents"] += 1
        a.update({k: i[k] for k in ["flag", "country", "city", "lat", "lon"]})

    for s in suricata:
        a = attackers[s["src_ip"]]
        a["alerts"] += 1
        a["score"] += 2 if s["severity"] == "medium" else 5
        a.update({k: s[k] for k in ["flag", "country", "city", "lat", "lon"]})

    for c in cowrie:
        a = attackers[c["src_ip"]]
        if c["eventid"] == "cowrie.login.failed":
            a["failed"] += 1
            a["score"] += 3
        elif c["eventid"] == "cowrie.login.success":
            a["success"] += 1
            a["score"] += 8
        elif c["eventid"] == "cowrie.command.input":
            a["commands"] += 1
            a["score"] += 6 if c["severity"] == "high" else 14
        a.update({k: c[k] for k in ["flag", "country", "city", "lat", "lon"]})

    top_attackers = sorted(
        [{"ip": ip, **v} for ip, v in attackers.items()],
        key=lambda x: x["score"],
        reverse=True
    )[:10]

    activity = []

    for s in suricata[-150:]:
        activity.append({
            "timestamp": s["timestamp"],
            "type": "suricata",
            "src_ip": s["src_ip"],
            "title": "Suricata Alert",
            "detail": s["signature"],
            "severity": s["severity"],
            "flag": s["flag"],
            "search": f"{s['src_ip']} {s['signature']} {s.get('dest_port')} {s.get('proto')}",
        })

    for c in cowrie[-200:]:
        title = "Cowrie Event"
        detail = c["eventid"]
        if c["eventid"] == "cowrie.login.failed":
            title = "Bruteforce Attempt"
            detail = f"{c.get('username')} / {c.get('password')}"
        elif c["eventid"] == "cowrie.login.success":
            title = "Successful Login"
            detail = f"user={c.get('username')}"
        elif c["eventid"] == "cowrie.command.input":
            title = "Command Executed"
            detail = c.get("command") or "command"

        activity.append({
            "timestamp": c["timestamp"],
            "type": "cowrie",
            "src_ip": c["src_ip"],
            "title": title,
            "detail": detail,
            "severity": c["severity"],
            "flag": c["flag"],
            "search": f"{c['src_ip']} {c['eventid']} {c.get('username')} {c.get('password')} {c.get('command')}",
        })

    activity = sorted(activity, key=lambda x: x["timestamp"])[-260:]

    map_points = []
    for a in top_attackers:
        sev = "medium"
        if a["commands"] > 0:
            sev = "critical"
        elif a["failed"] >= 5 or a["success"] > 0:
            sev = "high"
        map_points.append({
            "src_ip": a["ip"],
            "flag": a["flag"],
            "country": a["country"],
            "city": a["city"],
            "lat": a["lat"],
            "lon": a["lon"],
            "severity": sev,
            "score": a["score"],
            "failed": a["failed"],
            "success": a["success"],
            "commands": a["commands"],
        })
    
    demo_points = [
    {
        "src_ip": "185.220.101.12",
        "flag": "🇩🇪",
        "country": "Germany",
        "city": "Tor Exit Node",
        "lat": 52.52,
        "lon": 13.405,
        "severity": "critical",
        "score": 95,
        "failed": 24,
        "success": 1,
        "commands": 8,
    },
    {
        "src_ip": "45.155.205.233",
        "flag": "🇳🇱",
        "country": "Netherlands",
        "city": "Scanner Botnet",
        "lat": 52.3676,
        "lon": 4.9041,
        "severity": "high",
        "score": 61,
        "failed": 18,
        "success": 0,
        "commands": 2,
    },
    {
        "src_ip": "103.152.220.44",
        "flag": "🇸🇬",
        "country": "Singapore",
        "city": "Credential Stuffing",
        "lat": 1.3521,
        "lon": 103.8198,
        "severity": "high",
        "score": 54,
        "failed": 31,
        "success": 0,
        "commands": 0,
    },
    {
        "src_ip": "196.251.80.77",
        "flag": "🇲🇦",
        "country": "Morocco",
        "city": "Recon Source",
        "lat": 33.5731,
        "lon": -7.5898,
        "severity": "medium",
        "score": 29,
        "failed": 6,
        "success": 0,
        "commands": 0,
    },
    {
        "src_ip": "201.48.90.11",
        "flag": "🇧🇷",
        "country": "Brazil",
        "city": "Suspicious SSH Probe",
        "lat": -23.5505,
        "lon": -46.6333,
        "severity": "medium",
        "score": 22,
        "failed": 4,
        "success": 0,
        "commands": 0,
    },
]

    map_points.extend(demo_points)

    top_commands = Counter(c["command"] for c in commands if c["command"]).most_common(8)
    #if time.time() % 10 < 2:
        #auto_block(top_attackers)
    
    sys = get_system_info()





    return {
        "updated_at": utc_now(),
        "system": sys,
        "stats": {
            "services": sys,
            "total": len(incidents),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "blocked": len(blocked),
            "failed": len(failed),
            "success": len(success),
            "commands": len(commands),
            "suricata": len(suricata),
            "cowrie": len(cowrie),
            "stages": dict(stages),
            "top_attackers": top_attackers,
            "top_users": users.most_common(6),
            "top_passwords": passwords.most_common(6),
            "top_signatures": signatures.most_common(8),
            "top_commands": top_commands,
        },
        "activity": activity,
        "incidents": incidents,
        "suricata": suricata,
        "cowrie": cowrie,
        "map_points": map_points,
    }

LAST_BLOCK = {}

def auto_block(attackers):
    now = time.time()

    for a in attackers:
        ip = a["ip"]

        if ip in WHITELIST:
            continue

        # ⛔ cooldown 30s
        if ip in LAST_BLOCK and now - LAST_BLOCK[ip] < 30:
            continue

        if (
            a["commands"] > 0 or
            a["failed"] >= 6 or
            a["success"] > 0 or
            a["score"] > 25
        ):
            r = subprocess.run(
                ["sudo", "-n", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            if r.returncode != 0:
                subprocess.run(
                    ["sudo", "-n", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                )
                LAST_BLOCK[ip] = now
        ip = a["ip"]

        if ip in WHITELIST:
            continue

        # règles simples mais efficaces
        if (
            a["commands"] > 0 or
            a["failed"] >= 6 or
            a["success"] > 0 or
            a["score"] > 25
        ):
            subprocess.run(
                ["sudo", "-n", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # si pas déjà bloqué → on bloque
            r = subprocess.run(
                ["sudo", "-n", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            if r.returncode != 0:
                subprocess.run(
                    ["sudo", "-n", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                )

@app.route("/")
def index():
    return render_template_string(TEMPLATE)




@app.route("/api/dashboard")
def api():
    now = time.time()
    if CACHE["data"] and now - CACHE["ts"] < CACHE_TTL:
        return jsonify(CACHE["data"])

    data = build_dashboard()
    CACHE["data"] = data
    CACHE["ts"] = now
    return jsonify(data)


TEMPLATE = r"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>SOC Command Center</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

<style>
:root{--cyan:#38bdf8;--red:#ef4444;--orange:#fb923c;--yellow:#facc15;--green:#22c55e}
body{background:radial-gradient(circle at top right,rgba(79,70,229,.20),transparent 28%),#020617;color:#e5e7eb;font-family:Inter,system-ui,sans-serif}
.glass{background:linear-gradient(180deg,rgba(15,23,42,.96),rgba(2,6,23,.94));border:1px solid rgba(148,163,184,.16);box-shadow:0 18px 55px rgba(0,0,0,.34)}
.nav{color:#94a3b8;transition:.18s}
.nav:hover{background:rgba(15,23,42,.9);color:white}
.nav.active{background:linear-gradient(90deg,#0284c7,#4f46e5);color:white;box-shadow:0 0 30px rgba(79,70,229,.42)}
.page{display:none}.page.active{display:block}
.sidebar.collapsed{width:88px}.sidebar.collapsed .label,.sidebar.collapsed .brand-text,.sidebar.collapsed .status-box,.sidebar.collapsed .profile-box{display:none}
.main.collapsed{margin-left:88px}
#map,#map_full{height:430px;border-radius:22px;background:#000}
#map_full{height:700px}
.leaflet-control-attribution{display:none}
.badge{border:1px solid rgba(255,255,255,.16);border-radius:8px;padding:4px 9px;font-size:11px;font-weight:800}
.red{color:var(--red)}.orange{color:var(--orange)}.yellow{color:var(--yellow)}.green{color:var(--green)}.cyan{color:var(--cyan)}
.spark{height:34px}
.attack-dot {
  width: 16px;
  height: 16px;
  border-radius: 999px;
  background: #ef4444;
  box-shadow: 0 0 18px #ef4444;
  animation: pulseAttack 1.4s infinite;
}

@keyframes pulseAttack {
  0% { transform: scale(.8); opacity: .7; }
  50% { transform: scale(1.45); opacity: 1; }
  100% { transform: scale(.8); opacity: .7; }
}

.leaflet-interactive.attack-line {
  stroke-dasharray: 8;
  animation: dashMove 1.2s linear infinite;
}

@keyframes dashMove {
  to { stroke-dashoffset: -40; }
}
</style>
</head>

<body>
<div id="sidebar" class="sidebar fixed left-0 top-0 h-screen w-72 bg-black/60 border-r border-slate-800 p-5 z-20 transition-all">
  <div class="flex items-center gap-3 mb-8">
    <button onclick="toggleSidebar()" class="bg-slate-900 border border-slate-800 px-3 py-2 rounded-xl">☰</button>
    <div class="brand-text">
      <h1 class="text-2xl font-black">SOC<span class="cyan">COMMAND</span></h1>
      <p class="text-xs text-slate-500">Raspberry SOC Node <span class="green">● LIVE</span></p>
    </div>
  </div>

  <nav class="space-y-3">
    <button class="nav active w-full text-left rounded-xl px-4 py-3 font-bold" onclick="showPage('overview',this)">▦ <span class="label">OVERVIEW</span></button>
    <button class="nav w-full text-left rounded-xl px-4 py-3 font-bold" onclick="showPage('mapPage',this)">◎ <span class="label">ATTACK MAP</span></button>
    <button class="nav w-full text-left rounded-xl px-4 py-3 font-bold" onclick="showPage('killPage',this)">⛓ <span class="label">KILL CHAIN</span></button>
    <button class="nav w-full text-left rounded-xl px-4 py-3 font-bold" onclick="showPage('brutePage',this)">⚔ <span class="label">BRUTEFORCE</span></button>
    <button class="nav w-full text-left rounded-xl px-4 py-3 font-bold" onclick="showPage('eventsPage',this)">▤ <span class="label">EVENTS</span></button>
    <button class="nav w-full text-left rounded-xl px-4 py-3 font-bold" onclick="showPage('wazuhPage',this)">W <span class="label">WAZUH</span></button>
  </nav>

  <div class="status-box absolute bottom-24 left-5 right-5 glass rounded-2xl p-4">
    <h3 class="font-bold text-sm mb-3">SYSTEM STATUS</h3>
    <div class="flex gap-4 items-center">
      <div class="w-20 h-20 rounded-full border-8 border-green-500 grid place-items-center font-black">98%</div>
      <div class="text-xs space-y-1 text-slate-400">
        <p>Suricata <span class="green ml-5">● Online</span></p>
        <p>Cowrie <span class="green ml-8">● Online</span></p>
        <p>Correlator <span class="green ml-3">● Online</span></p>
        <p>Wazuh <span class="yellow ml-8">● Ready</span></p>
      </div>
    </div>
  </div>

  <div class="profile-box absolute bottom-6 left-5 right-5 glass rounded-2xl p-4 flex items-center gap-3">
    <div class="w-11 h-11 bg-blue-900 rounded-full grid place-items-center font-black">DA</div>
    <div><p class="font-bold">dark@SOC</p><p class="text-xs text-slate-500">Administrator</p></div>
  </div>
</div>

<main id="main" class="main ml-72 w-auto p-6 transition-all">
<header class="flex justify-between items-start mb-6">
  <div>
    <h2 class="text-5xl font-black">SOC Overview</h2>
    <p class="text-slate-400 mt-1">Real-time monitoring, honeypot intelligence and response</p>
  </div>
  <div class="flex items-center gap-4">
    <input id="globalSearch" oninput="renderAll()" class="glass rounded-2xl px-5 py-4 text-slate-200 w-96 outline-none" placeholder="Search IP, user, password, command, signature...">
    <button onclick="clearSearch()" class="glass rounded-2xl px-4 py-4">Clear</button>
    <div class="glass rounded-2xl px-4 py-4 text-red-400">🔔 <span id="notif" class="badge bg-red-600 text-white">0</span></div>
    <div class="glass rounded-2xl px-5 py-3 text-right"><p class="text-xs text-slate-500">SOC Time</p><p class="cyan font-black" id="clock">--:--:--</p></div>
  </div>
</header>

<section id="overview" class="page active">
  <div class="grid grid-cols-4 gap-4 mb-4">
    <div class="glass rounded-2xl p-5"><p class="cyan font-bold">TOTAL</p><h3 id="total" class="text-5xl font-black mt-2">0</h3><p class="green text-xs">correlated incidents</p><canvas class="spark" id="sparkTotal"></canvas></div>
    <div class="glass rounded-2xl p-5"><p class="red font-bold">CRITICAL</p><h3 id="critical" class="text-5xl font-black mt-2">0</h3><p class="red text-xs">dangerous commands</p><canvas class="spark" id="sparkCritical"></canvas></div>
    <div class="glass rounded-2xl p-5"><p class="orange font-bold">HIGH</p><h3 id="high" class="text-5xl font-black mt-2">0</h3><p class="orange text-xs">bruteforce / successful login</p><canvas class="spark" id="sparkHigh"></canvas></div>
    <div class="glass rounded-2xl p-5"><p class="cyan font-bold">BLOCKED</p><h3 id="blocked" class="text-5xl font-black mt-2">0</h3><p class="cyan text-xs">iptables response</p><canvas class="spark" id="sparkBlocked"></canvas></div>
  </div>

  <div class="grid grid-cols-3 gap-4 mb-4">
    <div class="glass rounded-2xl p-4 col-span-2">
      <div class="flex justify-between mb-2"><div><h3 class="font-black">ATTACK MAP</h3><p class="text-xs text-slate-400">Live network and honeypot sources</p></div><select id="severityFilter" onchange="renderAll()" class="bg-slate-900 rounded-xl px-3"><option value="">All severity</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></div>
      <div id="map"></div>
    </div>
    <div class="glass rounded-2xl p-4">
      <h3 class="font-black">LIVE INCIDENT FEED</h3><p class="text-xs text-slate-400 mb-3">Real-time alerts and events</p>
      <div id="feed" class="space-y-2"></div>
    </div>
  </div>

  <div class="grid grid-cols-4 gap-4">
    <div class="glass rounded-2xl p-4"><h3 class="font-black">ATTACK STAGES</h3><canvas id="stageChart"></canvas></div>
    <div class="glass rounded-2xl p-4"><h3 class="font-black">TOP ATTACKERS</h3><div id="attackers" class="space-y-3 mt-3"></div></div>
    <div class="glass rounded-2xl p-4"><h3 class="font-black">BRUTEFORCE OVERVIEW</h3><canvas id="cowrieChart"></canvas><div id="bruteMini" class="grid grid-cols-3 gap-2 text-center text-xs mt-2"></div></div>
    <div class="glass rounded-2xl p-4"><h3 class="font-black">MOST USED COMMANDS</h3><div id="commandsBox" class="space-y-2 mt-3 text-sm"></div></div>
  </div>

  <div class="glass rounded-2xl p-4 mt-4">
  <h3 class="font-black mb-3">SYSTEM INFORMATION</h3>

  <div class="grid grid-cols-6 gap-4 text-sm">
    <div>
      <p class="text-slate-500">Hostname</p>
      <p id="sysHostname" class="font-bold cyan">-</p>
    </div>

    <div>
      <p class="text-slate-500">IP</p>
      <p id="sysIp" class="font-bold">-</p>
    </div>

    <div>
      <p class="text-slate-500">Uptime</p>
      <p id="sysUptime" class="font-bold green">-</p>
    </div>

    <div>
      <p class="text-slate-500">CPU</p>
      <p id="sysCpu" class="font-bold orange">-</p>
    </div>

    <div>
      <p class="text-slate-500">Memory</p>
      <p id="sysMemory" class="font-bold yellow">-</p>
    </div>

    <div>
      <p class="text-slate-500">Disk</p>
      <p id="sysDisk" class="font-bold red">-</p>
    </div>
  </div>
</div>
</section>

<section id="mapPage" class="page"><h2 class="text-4xl font-black mb-5">Attack Map</h2><div class="glass rounded-2xl p-5"><div id="map_full"></div></div></section>
<section id="killPage" class="page"><h2 class="text-4xl font-black mb-5">Kill Chain</h2><div id="killCards" class="grid grid-cols-5 gap-4"></div></section>
<section id="brutePage" class="page"><h2 class="text-4xl font-black mb-5">Bruteforce Intelligence</h2><div class="grid grid-cols-3 gap-4"><div class="glass rounded-2xl p-5"><h3 class="font-black mb-3">Top Users</h3><div id="topUsers" class="space-y-2"></div></div><div class="glass rounded-2xl p-5"><h3 class="font-black mb-3">Top Passwords</h3><div id="topPasswords" class="space-y-2"></div></div><div class="glass rounded-2xl p-5"><h3 class="font-black mb-3">Top Signatures</h3><div id="sigs" class="space-y-2"></div></div></div></section>
<section id="eventsPage" class="page"><h2 class="text-4xl font-black mb-5">Events</h2><div class="glass rounded-2xl p-5"><div id="allEvents" class="space-y-2"></div></div></section>
<section id="wazuhPage" class="page"><h2 class="text-4xl font-black mb-5">Wazuh Integration</h2><div class="glass rounded-2xl p-6"><pre class="bg-black rounded-xl p-4 text-cyan-300">/home/dark/soc-node/logs/incidents.json</pre></div></section>
</main>

<script>
let DATA=null,map,mapFull,markers=[],markersFull=[],stageChart,cowrieChart,sparks={};

function toggleSidebar(){sidebar.classList.toggle('collapsed');main.classList.toggle('collapsed');setTimeout(()=>{map.invalidateSize();mapFull.invalidateSize()},250)}
function showPage(id,btn){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.getElementById(id).classList.add('active');document.querySelectorAll('.nav').forEach(n=>n.classList.remove('active'));btn.classList.add('active');setTimeout(()=>{map.invalidateSize();mapFull.invalidateSize()},250)}
function q(){return globalSearch.value.toLowerCase().trim()}
function clearSearch(){globalSearch.value='';renderAll()}
function sevColor(s){return s==='critical'?'#ef4444':s==='high'?'#fb923c':s==='medium'?'#facc15':'#22c55e'}
function badge(s){return `<span class="badge" style="color:${sevColor(s)};border-color:${sevColor(s)}">${String(s).toUpperCase()}</span>`}
function filter(items){let x=q(),sev=severityFilter?severityFilter.value:'';return items.filter(i=>(!x||JSON.stringify(i).toLowerCase().includes(x))&&(!sev||i.severity===sev))}
function row(pair){return `<div class="flex justify-between bg-slate-900/80 rounded-lg px-3 py-2"><span class="font-mono">${pair[0]}</span><span class="cyan font-black">${pair[1]}</span></div>`}

function init(){
 map=L.map('map',{zoomControl:true}).setView([25,10],2);mapFull=L.map('map_full',{zoomControl:true}).setView([25,10],2);
 L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(mapFull);
 stageChart=new Chart(document.getElementById('stageChart'),{type:'doughnut',data:{labels:['Recon','Intrusion','Brute','Exploit','Post'],datasets:[{data:[0,0,0,0,0],backgroundColor:['#38bdf8','#a855f7','#facc15','#fb923c','#ef4444']}]},options:{plugins:{legend:{labels:{color:'#e5e7eb'}}}}});
 cowrieChart=new Chart(document.getElementById('cowrieChart'),{type:'line',data:{labels:['Failed','Success','Commands'],datasets:[{data:[0,0,0],borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.18)',fill:true,tension:.35}]},options:{plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#94a3b8'}},y:{ticks:{color:'#94a3b8'}}}}});
 ['sparkTotal','sparkCritical','sparkHigh','sparkBlocked'].forEach(id=>sparks[id]=new Chart(document.getElementById(id),{type:'line',data:{labels:[1,2,3,4,5,6,7],datasets:[{data:[1,3,2,5,4,7,6],borderColor:'#38bdf8',pointRadius:0,tension:.4}]},options:{plugins:{legend:{display:false}},scales:{x:{display:false},y:{display:false}}}}));
}

function animatedMarker(point) {
  return L.divIcon({
    className: '',
    html: `<div class="attack-dot" style="background:${sevColor(point.severity)}; box-shadow:0 0 22px ${sevColor(point.severity)}"></div>`,
    iconSize: [16, 16],
    iconAnchor: [8, 8]
  });
}

function renderMaps(points) {
  markers.forEach(m => map.removeLayer(m));
  markersFull.forEach(m => mapFull.removeLayer(m));
  markers = [];
  markersFull = [];

  const filtered = filter(points);

const center = [48.8566, 2.3522];
  filtered.forEach(i => {
    if (!i.lat || !i.lon) return;

    const color = sevColor(i.severity);
    const target = [i.lat, i.lon];

    const popup = `
      <b>${i.flag} ${i.src_ip}</b><br>
      ${i.city}, ${i.country}<br>
      Severity: ${i.severity}<br>
      Failed: ${i.failed || 0}<br>
      Commands: ${i.commands || 0}
    `;

    const line1 = L.polyline([target, center], {
      color,
      weight: 2,
      opacity: 0.75,
      className: 'attack-line'
    }).addTo(map);

    const line2 = L.polyline([target, center], {
      color,
      weight: 2,
      opacity: 0.75,
      className: 'attack-line'
    }).addTo(mapFull);

    const marker1 = L.marker(target, { icon: animatedMarker(i) }).addTo(map);
    marker1.bindPopup(popup);

    const marker2 = L.marker(target, { icon: animatedMarker(i) }).addTo(mapFull);
    marker2.bindPopup(popup);

    markers.push(line1, marker1);
    markersFull.push(line2, marker2);
  });

  const socIcon = L.divIcon({
    className: '',
    html: `<div class="attack-dot" style="background:#38bdf8; box-shadow:0 0 25px #38bdf8"></div>`,
    iconSize: [18, 18],
    iconAnchor: [9, 9]
  });

  const soc1 = L.marker(center, { icon: socIcon }).addTo(map).bindPopup("<b>Raspberry SOC Node</b>");
  const soc2 = L.marker(center, { icon: socIcon }).addTo(mapFull).bindPopup("<b>Raspberry SOC Node</b>");

  markers.push(soc1);
  markersFull.push(soc2);
  if (filtered.length > 2) {
    map.setView([25, 10], 2);
    mapFull.setView([25, 10], 2);
}
}

function renderAll(){
 if(!DATA)return;let s=DATA.stats,act=filter(DATA.activity).slice().reverse();
 total.innerText=s.total;critical.innerText=s.critical;high.innerText=s.high;blocked.innerText=s.blocked;notif.innerText=s.critical+s.high;
 stageChart.data.datasets[0].data=[s.stages.reconnaissance||0,s.stages.intrusion_attempt||0,s.failed||0,s.stages.exploitation||0,s.stages.post_exploitation||0];stageChart.update();
 cowrieChart.data.datasets[0].data=[s.failed,s.success,s.commands];cowrieChart.update();

 feed.innerHTML=act.slice(0,7).map(i=>`<div class="flex justify-between items-center bg-slate-900/80 rounded-lg px-3 py-2 text-sm"><div>${i.flag} <span class="font-mono">${i.src_ip}</span><br><span class="text-slate-400">${i.title} • ${i.detail}</span></div>${badge(i.severity)} ${i.blocked ? '<span class="text-red-400 ml-2">[BLOCKED]</span>' : ''}</div>`).join('');
 attackers.innerHTML = s.top_attackers.slice(0,5).map((a,i)=>`
<div class="bg-slate-900/80 rounded-xl p-3 text-xs space-y-2">
  <div class="flex items-center gap-2">
    <span class="red font-bold">${i+1}</span>
    <span>${a.flag}</span>
    <span class="font-mono flex-1 truncate">${a.ip}</span>
    <span class="red font-black">${a.score}</span>
  </div>

  <div class="grid grid-cols-2 gap-2">
    <button onclick="blockIP('${a.ip}')" class="bg-red-600 hover:bg-red-500 px-2 py-1 rounded-lg font-bold">
      BLOCK
    </button>
    <button onclick="unblockIP('${a.ip}')" class="bg-green-600 hover:bg-green-500 px-2 py-1 rounded-lg font-bold">
      UNBLOCK
    </button>
  </div>
</div>
`).join('');
 bruteMini.innerHTML=`<div><b>${s.failed}</b><br>Failed</div><div><b>${s.success}</b><br>Success</div><div><b>${s.commands}</b><br>Commands</div>`;
 commandsBox.innerHTML=s.top_commands.map(row).join('');
 topUsers.innerHTML=s.top_users.map(row).join('');topPasswords.innerHTML=s.top_passwords.map(row).join('');sigs.innerHTML=s.top_signatures.map(row).join('');
 killCards.innerHTML=[['Recon',s.stages.reconnaissance||0],['Intrusion',s.stages.intrusion_attempt||0],['Bruteforce',s.failed],['Exploit',s.stages.exploitation||0],['Post',s.stages.post_exploitation||0]].map(x=>`<div class="glass rounded-2xl p-6"><p class="text-slate-400">${x[0]}</p><h3 class="text-6xl font-black mt-3">${x[1]}</h3></div>`).join('');
 allEvents.innerHTML=act.slice(0,120).map(i=>`<div class="flex justify-between bg-slate-900/80 rounded-lg px-3 py-3"><span>${i.flag} <span class="font-mono">${i.src_ip}</span> — ${i.title} • ${i.detail}</span>${badge(i.severity)}</div>`).join('');
 renderMaps(DATA.map_points);

 if (DATA.system) {
  sysHostname.innerText = DATA.system.hostname;
  sysIp.innerText = DATA.system.ip;
  sysUptime.innerText = DATA.system.uptime;
  sysCpu.innerText = DATA.system.cpu + "%";
  sysMemory.innerText = DATA.system.memory;
  sysDisk.innerText = DATA.system.disk;
}
}

async function load(){let r=await fetch('/api/dashboard');DATA=await r.json();renderAll()}
setInterval(()=>clock.innerText=new Date().toLocaleTimeString(),1000);
init();load();setInterval(load,8000);

async function blockIP(ip){
  await fetch('/api/block/'+ip,{method:'POST'})
  load()
}

async function unblockIP(ip){
  await fetch('/api/unblock/'+ip,{method:'POST'})
  load()
}
</script>
</body>
</html>
"""


@app.route("/api/block/<ip>", methods=["POST"])
def block_ip(ip):
    if ip in WHITELIST:
        return jsonify({"error": "whitelisted"}), 403

    try:
        subprocess.run(["sudo", "-n", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        return jsonify({"status": "blocked", "ip": ip})
    except:
        return jsonify({"error": "failed"}), 500


@app.route("/api/unblock/<ip>", methods=["POST"])
def unblock_ip(ip):
    try:
        subprocess.run(["sudo", "-n", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        return jsonify({"status": "unblocked", "ip": ip})
    except:
        return jsonify({"error": "failed"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)