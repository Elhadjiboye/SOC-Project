#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
import ipaddress


# ==============================
# CONFIGURATION
# ==============================

CONFIG = {
    "suricata_log": "/var/log/suricata/eve.json",
    "cowrie_log": "/home/dark/soc-node/cowrie-full/var/log/cowrie/cowrie.json",
    "incident_log": "/home/dark/soc-node/logs/incidents.json",

    # En entreprise: mettre False au debut, puis activer apres validation
    "auto_block": True,

    # Seuils
    "block_threshold": 25,
    "incident_threshold": 10,
    "critical_threshold": 30,

    # Sessions
    "session_timeout": 300,

    # Anti-spam
    "dedup_seconds": 60,
    "incident_cooldown": 60,

    # Whitelist: ajoute ton Mac ici si tu veux tester sans te bloquer
    "whitelist": {
        "192.168.1.1",
        #"192.168.1.18",
	"127.0.0.1",
    },

    # Commandes suspectes Cowrie
    "suspicious_commands": [
        "wget", "curl", "chmod", "chown", "bash", "sh",
        "nc", "netcat", "python", "python3", "perl",
        "busybox", "tftp", "ftp", "scp", "ssh",
        "rm -", "crontab", "systemctl", "service"
    ],
}


# ==============================
# GLOBAL STATE
# ==============================

attackers = {}
blocked_ips = set()
dedup_cache = {}
last_incident_time = {}
lock = threading.Lock()


# ==============================
# UTILITIES
# ==============================

def now():
    return datetime.now(timezone.utc)


def timestamp():
    return now().isoformat()


def ensure_paths():
    Path(CONFIG["incident_log"]).parent.mkdir(parents=True, exist_ok=True)
    Path(CONFIG["incident_log"]).touch(exist_ok=True)


def is_whitelisted(ip):
    return ip in CONFIG["whitelist"]


def normalize_command(cmd):
    return " ".join((cmd or "").strip().split()).lower()


def is_suspicious_command(cmd):
    normalized = normalize_command(cmd)
    return any(keyword in normalized for keyword in CONFIG["suspicious_commands"])


def is_duplicate(key):
    current = time.time()
    old = dedup_cache.get(key)

    if old and current - old < CONFIG["dedup_seconds"]:
        return True

    dedup_cache[key] = current
    return False


def cleanup_dedup_cache():
    current = time.time()
    expired = [
        key for key, ts_value in dedup_cache.items()
        if current - ts_value > CONFIG["dedup_seconds"]
    ]

    for key in expired:
        del dedup_cache[key]


def ensure_attacker(ip):
    if ip not in attackers:
        attackers[ip] = {
            "first_seen": now(),
            "last_seen": now(),

            "score": 0,
            "stage": "unknown",
            "severity": "low",

            "suricata_alerts": 0,
            "suricata_signatures": set(),

            "scan": 0,
            "ssh_network_events": 0,

            "failed": 0,
            "success": 0,

            "commands": 0,
            "suspicious_commands": 0,
            "command_samples": [],

            "sessions": set(),
            "blocked": False,
        }

    return attackers[ip]


# ==============================
# SCORING
# ==============================

def add_score(attacker, points):
    attacker["score"] += points
    attacker["severity"] = get_severity(attacker["score"])


def get_severity(score):
    if score >= CONFIG["critical_threshold"]:
        return "critical"
    if score >= CONFIG["block_threshold"]:
        return "high"
    if score >= CONFIG["incident_threshold"]:
        return "medium"
    return "low"


def determine_stage(a):
    if a["commands"] > 0:
        return "post_exploitation"

    if a["success"] > 0:
        return "exploitation"

    if a["failed"] >= 3:
        return "bruteforce"

    if a["failed"] > 0:
        return "intrusion_attempt"

    if a["scan"] > 0 or a["ssh_network_events"] > 0:
        return "reconnaissance"

    return "unknown"

def determine_attack_chain(a):
    if (
        a["ssh_network_events"] > 0
        and a["success"] > 0
        and a["suspicious_commands"] > 0
    ):
        return "ssh_intrusion_to_post_exploitation"

    if a["failed"] >= 5 and a["success"] == 0:
        return "ssh_bruteforce_attempt"

    if a["success"] > 0 and a["commands"] == 0:
        return "ssh_login_without_commands"

    if a["commands"] > 0 and a["suspicious_commands"] == 0:
        return "interactive_shell_activity"

    if a["scan"] > 0 or a["ssh_network_events"] > 0:
        return "ssh_reconnaissance"

    return "unknown"


def update_stage(attacker):
    attacker["stage"] = determine_stage(attacker)
    attacker["severity"] = get_severity(attacker["score"])


# ==============================
# BLOCKING
# ==============================

def run_cmd(cmd):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def iptables_rule_exists(ip):
    result = run_cmd(["sudo", "-n", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    return result.returncode == 0


def block_ip(ip):
    if is_whitelisted(ip):
        print(f"[SAFE] IP whitelist, blocage ignoré: {ip}")
        return False

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"[ERROR] IP invalide: {ip}")
        return False

    if ip.startswith("192.168.1."):
        print(f"[SAFE] Local IP ignorée: {ip}")
        return False

    if ip in blocked_ips or iptables_rule_exists(ip):
        blocked_ips.add(ip)
        attackers[ip]["blocked"] = True
        return True

    result = run_cmd(["sudo", "-n", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])

    if result.returncode == 0:
        blocked_ips.add(ip)
        attackers[ip]["blocked"] = True
        print(f"[BLOCK] IP bloquée: {ip}")
        return True

    print(f"[ERROR] Blocage impossible pour {ip}: {result.stderr.strip()}")
    return False


def should_block(attacker):
    if attacker["score"] < CONFIG["block_threshold"]:
        return False

    # On bloque seulement si on a un comportement vraiment utile.
    if attacker["stage"] in {"bruteforce", "post_exploitation"}:
        return True

    if attacker["suspicious_commands"] > 0:
        return True

    return False


# ==============================
# INCIDENT LOGGING
# ==============================

def build_incident(ip, data, reason):
    return {
        "timestamp": timestamp(),
        "attack_chain": determine_attack_chain(data),
        "mitre": map_mitre(data),
        "sensor": "raspberry-soc-node",
        "src_ip": ip,
        "attack_stage": data["stage"],
        "severity": data["severity"],
        "score": data["score"],
        "reason": reason,
        "timeline_seconds": int((data["last_seen"] - data["first_seen"]).total_seconds()),
        "activity": {
            "suricata_alerts": data["suricata_alerts"],
            "suricata_signatures": sorted(list(data["suricata_signatures"])),
            "scan_events": data["scan"],
            "ssh_network_events": data["ssh_network_events"],
            "failed_logins": data["failed"],
            "successful_logins": data["success"],
            "commands": data["commands"],
            "suspicious_commands": data["suspicious_commands"],
            "command_samples": data["command_samples"][-10:],
            "sessions": sorted(list(data["sessions"])),
        },
        "response": {
            "auto_block": CONFIG["auto_block"],
            "blocked": data["blocked"] or ip in blocked_ips,
            "method": "iptables" if data["blocked"] or ip in blocked_ips else None,
        },
    }


def map_mitre(data):
    techniques = []

    if data["failed"] > 0:
        techniques.append("T1110 - Brute Force")

    if data["success"] > 0:
        techniques.append("T1078 - Valid Accounts")

    if data["commands"] > 0:
        techniques.append("T1059 - Command Execution")

    if data["suspicious_commands"] > 0:
        techniques.append("T1105 - Ingress Tool Transfer")

    return techniques

def log_incident(ip, reason):
    current = time.time()
    last = last_incident_time.get(ip, 0)

    bypass_cooldown_reasons = {
        "cowrie_suspicious_command",
        "cowrie_login_success",
        "automatic_block_applied",
    }

    if reason not in bypass_cooldown_reasons:
        if current - last < CONFIG["incident_cooldown"]:
            return

    last_incident_time[ip] = current

    data = attackers[ip]
    incident = build_incident(ip, data, reason)

    with open(CONFIG["incident_log"], "a", encoding="utf-8") as f:
        f.write(json.dumps(incident, ensure_ascii=False) + "\n")

    print("\n=== INCIDENT SOC ===")
    print(json.dumps(incident, indent=2, ensure_ascii=False))


# ==============================
# EVALUATION
# ==============================

def evaluate(ip, reason):
    if ip not in attackers:
        return

    data = attackers[ip]
    update_stage(data)

    if data["score"] >= CONFIG["incident_threshold"]:
        log_incident(ip, reason)

    if CONFIG["auto_block"] and should_block(data):
        if block_ip(ip):
            log_incident(ip, "automatic_block_applied")


# ==============================
# SURICATA HANDLER
# ==============================

def handle_suricata(line):
    try:
        event = json.loads(line)
        if not isinstance(event, dict):
            return
    except json.JSONDecodeError:
        return

    if event.get("event_type") != "alert":
        return

    ip = event.get("src_ip")
    if not ip or is_whitelisted(ip):
        return

    signature = event.get("alert", {}).get("signature", "")
    if "ICMPv4 unknown code" in signature:
        return
    dest_port = event.get("dest_port")
    flow_id = event.get("flow_id", "")

    dedup_key = f"suricata:{ip}:{signature}:{dest_port}:{flow_id}"
    if is_duplicate(dedup_key):
        return

    with lock:
        attacker = ensure_attacker(ip)
        attacker["last_seen"] = now()
        attacker["suricata_alerts"] += 1
        attacker["suricata_signatures"].add(signature)

        add_score(attacker, 1)

        sig_upper = signature.upper()

        if "SCAN" in sig_upper or "SYN" in sig_upper or "NMAP" in sig_upper:
            attacker["scan"] += 1
            add_score(attacker, 2)

        if dest_port in {22, 2222} or "SSH" in sig_upper or "COWRIE" in sig_upper:
            attacker["ssh_network_events"] += 1
            add_score(attacker, 1)

        update_stage(attacker)

    print(f"[SURICATA] {ip} -> port {dest_port} | {signature}")
    evaluate(ip, "suricata_alert")


# ==============================
# COWRIE HANDLER
# ==============================

def handle_cowrie(line):
    try:
        event = json.loads(line)
        if not isinstance(event, dict):
            return
    except json.JSONDecodeError:
        return  

    ip = event.get("src_ip")
    if not ip or is_whitelisted(ip):
        return

    eventid = event.get("eventid", "")
    session = event.get("session")

    if eventid not in {
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.command.input",
    }:
        return

    command = normalize_command(event.get("input", ""))
    dedup_key = f"cowrie:{ip}:{eventid}:{session}:{command}:{event.get('timestamp')}"
    if is_duplicate(dedup_key):
        return

    reason = "cowrie_activity"

    with lock:
        attacker = ensure_attacker(ip)
        attacker["last_seen"] = now()

        if session:
            attacker["sessions"].add(session)

        if eventid == "cowrie.login.failed":
            attacker["failed"] += 1
            add_score(attacker, 3)
            username = event.get("username", "?")
            print(f"[COWRIE] FAIL {ip} user={username}")
            reason = "cowrie_login_failed"

        elif eventid == "cowrie.login.success":
            attacker["success"] += 1
            add_score(attacker, 8)
            username = event.get("username", "?")
            print(f"[COWRIE] SUCCESS {ip} user={username}")
            reason = "cowrie_login_success"

        elif eventid == "cowrie.command.input":
            attacker["commands"] += 1
            attacker["command_samples"].append(command)
            add_score(attacker, 5)

            if is_suspicious_command(command):
                attacker["suspicious_commands"] += 1
                add_score(attacker, 12)
                reason = "cowrie_suspicious_command"
                print(f"[COWRIE] SUSPICIOUS CMD {ip}: {command}")
            else:
                reason = "cowrie_command"
                print(f"[COWRIE] CMD {ip}: {command}")

        update_stage(attacker)

    evaluate(ip, reason)


# ==============================
# FILE TAILER
# ==============================

def wait_for_file(path):
    while not Path(path).exists():
        print(f"[WAIT] Fichier introuvable: {path}")
        time.sleep(2)


def tail_file(path, handler):
    wait_for_file(path)

    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.2)
                continue

            handler(line)


# ==============================
# CLEANUP
# ==============================

def cleanup():
    while True:
        time.sleep(60)
        cleanup_dedup_cache()
        current = now()

        with lock:
            for ip in list(attackers.keys()):
                age = (current - attackers[ip]["last_seen"]).total_seconds()

                if age > CONFIG["session_timeout"]:
                    del attackers[ip]


# ==============================
# MAIN
# ==============================

def main():
    ensure_paths()

    print("=== SOC CORRELATOR ENTERPRISE+ ===")
    print(f"Suricata log : {CONFIG['suricata_log']}")
    print(f"Cowrie log   : {CONFIG['cowrie_log']}")
    print(f"Incident log : {CONFIG['incident_log']}")
    print(f"Auto-block   : {CONFIG['auto_block']}")
    print(f"Threshold    : {CONFIG['block_threshold']}")
    print("Ctrl+C pour arrêter\n")

    threading.Thread(target=cleanup, daemon=True).start()

    t_suricata = threading.Thread(
        target=tail_file,
        args=(CONFIG["suricata_log"], handle_suricata),
        daemon=True,
    )

    t_cowrie = threading.Thread(
        target=tail_file,
        args=(CONFIG["cowrie_log"], handle_cowrie),
        daemon=True,
    )

    t_suricata.start()
    t_cowrie.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[STOP] Correlator arrêté.")


if __name__ == "__main__":
    main()
