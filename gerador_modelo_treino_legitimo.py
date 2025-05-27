import pandas as pd
import random
from datetime import datetime, timedelta
from ipaddress import IPv4Address

# === Função para gerar IPs privados ===
def gerar_ips_privados(qtd):
    ranges = [
        (167772160, 184549375),      # 10.0.0.0/8
        (2886729728, 2887778303),    # 172.16.0.0/12
        (3232235520, 3232301055)     # 192.168.0.0/16
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
ips_ddos = gerar_ips_privados(300)          # IPs maliciosos
ips_portscan = gerar_ips_privados(100)
ips_normais = gerar_ips_privados(500)       # IPs legítimos
destinos_gerais = gerar_ips_privados(500)

logs = []
blocos = 10
eventos_por_bloco = 1000

for bloco in range(blocos):
    offset = timedelta(minutes=bloco * random.randint(10, 30))
    
    # Sessões de DDoS
    for ip in random.sample(ips_ddos, 50):
        for _ in range(random.randint(10, 50)):
            timestamp = base_time + offset + timedelta(seconds=random.uniform(0, 60))
            logs.append(gerar_log(timestamp, ip, random.choice(destinos_gerais), tipo_ataque=True))
    
    # Sessões de Port Scan
    for ip in random.sample(ips_portscan, 20):
        destinos_portscan = random.sample(destinos_gerais, 10)
        for dst in destinos_portscan:
            timestamp = base_time + offset + timedelta(seconds=random.uniform(0, 60))
            logs.append(gerar_log(timestamp, ip, dst, tipo_ataque=True))

    # Sessões normais
    for ip in random.sample(ips_normais, 100):
        for _ in range(random.randint(5, 15)):
            timestamp = base_time + offset + timedelta(seconds=random.uniform(0, 60))
            logs.append(gerar_log(timestamp, ip, random.choice(destinos_gerais), tipo_ataque=False))

# === Exportar CSV ===
df = pd.DataFrame(logs)
df.to_csv("logs_maliciosos7.csv", index=False)
print("📁 CSV gerado com sucesso: logs_maliciosos7.csv")
