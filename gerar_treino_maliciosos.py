import pandas as pd
import random
import os
from datetime import datetime, timedelta
from ipaddress import IPv4Address

# === Função para gerar IPs privados ===
def gerar_ips_privados(qtd):
    ranges = [
        (167772160, 184549375),
        (2886729728, 2887778303),
        (3232235520, 3232301055)
    ]
    return [str(IPv4Address(random.randint(*random.choice(ranges)))) for _ in range(qtd)]

# === Geração de log ===
def gerar_log(timestamp, ip_origem, ip_destino, tipo_ataque=False):
    return {
        "timestamp": timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "evento": random.choice(["Firewall Rule", "Alert", "Connection Attempt"]),
        "ação": random.choice(["Allowed", "Blocked", "Denied", "Dropped"]),
        "usuario": random.choice([
            "ataque@botnet.local", "exploit@malware.org", "scan@rogue.dev",
            "root@compromised.dev", "usuario@pmg.local", "admin@pmg.local", " ", "", None
        ]),
        "cod1": round(random.uniform(10, 300), 2),
        "descricao_rede": random.choice([
            "TRÁFEGO SUSPEITO", "ATAQUE AUTOMATIZADO", "VARREDURA DE PORTAS",
            "DDoS DETECTADO", "TENTATIVA DE EXPLOIT", "COMUNICAÇÃO EXTERNA",
            "ACESSO INTERNET REDE DE ACESSO", "VPN CORPORATIVA", "TRÁFEGO INTERNO"
        ]),
        "cod2": random.randint(50, 300),
        "nat_policy": random.choice(["Default SNAT IPv4", "Ataque NAT", "Bypass", "Double NAT", "Sem NAT", "SNAT Temporário"]),
        "porta_saida": f"Port{random.randint(1, 40)}.{random.randint(1, 99)}",
        "porta_entrada": f"Port{random.randint(1, 60)}",
        "ip_origem": ip_origem,
        "ip_destino": ip_destino,
        "porta_origem": random.randint(1, 65535),
        "porta_destino": float(random.choice([80, 443, 22, 53, 25, 110, 3306, 3389, 5900, random.randint(1, 65535)])),
        "protocolo": random.choice(["TCP", "UDP", "ICMP", "ESP", "GRE", "IGMP"]),
        "flag": random.randint(0, 1),
        "label": 1 if tipo_ataque else 0
    }

# === Geração dos logs ===
base_time = datetime(2025, 3, 6, 6, 0, 0)
timestamp_atual = base_time

ips_ddos = gerar_ips_privados(300)
ips_portscan = gerar_ips_privados(100)
ips_normais = gerar_ips_privados(500)
destinos_gerais = gerar_ips_privados(500)

logs = []

# Sessões de DDoS
for ip in random.sample(ips_ddos, 50):
    for _ in range(random.randint(10, 50)):
        timestamp_atual += timedelta(seconds=random.randint(10, 30))
        logs.append(gerar_log(timestamp_atual, ip, random.choice(destinos_gerais), tipo_ataque=True))

# Sessões de Port Scan
for ip in random.sample(ips_portscan, 20):
    destinos_portscan = random.sample(destinos_gerais, 10)
    for dst in destinos_portscan:
        timestamp_atual += timedelta(seconds=random.randint(10, 100))
        logs.append(gerar_log(timestamp_atual, ip, dst, tipo_ataque=True))

# === Exportar CSV ===
os.makedirs("database_treinamento/logs", exist_ok=True)
df = pd.DataFrame(logs)
df.to_csv("database_treinamento/logs/logs_maliciosos12.csv", index=False)
print("📁 CSV gerado com sucesso: logs_maliciosos11.csv")
