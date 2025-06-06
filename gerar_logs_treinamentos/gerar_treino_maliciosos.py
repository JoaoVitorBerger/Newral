import pandas as pd
import random
import os
from datetime import datetime, timedelta
from ipaddress import IPv4Address

# === Função para gerar IPs privados ===
def gerar_ips_privados(qtd):
    ranges = [
        (167772160, 184549375),      # 10.0.0.0 – 10.255.255.255
        (2886729728, 2887778303),    # 172.16.0.0 – 172.31.255.255
        (3232235520, 3232301055)     # 192.168.0.0 – 192.168.255.255
    ]
    return [str(IPv4Address(random.randint(*random.choice(ranges)))) for _ in range(qtd)]

# === Geração de log ===
def gerar_log(timestamp, ip_origem, ip_destino, tipo_ataque):
    return {
        "timestamp": timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "evento": random.choice(["Firewall Rule", "Alert", "Connection Attempt"]),
        "ação": random.choice(["Blocked", "Denied", "Dropped"]),
        "usuario": random.choice([
            "ataque@botnet.local", "exploit@malware.org", "scan@rogue.dev",
            "root@compromised.dev"
        ]),
        "cod1": round(random.uniform(100, 500), 2),
        "descricao_rede": random.choice([
            "TRÁFEGO SUSPEITO", "ATAQUE AUTOMATIZADO", "VARREDURA DE PORTAS",
            "DDoS DETECTADO", "TENTATIVA DE EXPLOIT"
        ]),
        "cod2": random.randint(100, 500),
        "nat_policy": random.choice(["Ataque NAT", "Double NAT", "SNAT Temporário"]),
        "porta_saida": f"Port{random.randint(1, 48)}.{random.randint(1, 99)}",
        "porta_entrada": f"Port{random.randint(1, 60)}",
        "ip_origem": ip_origem,
        "ip_destino": ip_destino,
        "porta_origem": random.randint(1024, 65535),
        "porta_destino": float(random.choice([80, 443, 22, 53, 25, 3306, 3389, random.randint(1, 65535)])),
        "protocolo": random.choice(["TCP", "UDP", "ICMP"]),
        "flag": random.randint(0, 1),
        "label": 1
    }

# === Geração dos logs maliciosos ===
base_time = datetime(2025, 6, 5, 6, 0, 0)
timestamp_atual = base_time

logs = []
destinos_gerais = gerar_ips_privados(6000)

# Sessões DDoS: Cada IP único ataca repetidamente o mesmo destino
for ip_origem in gerar_ips_privados(3000):  # 250 IPs diferentes
    ip_destino = random.choice(destinos_gerais)
    for _ in range(random.randint(10, 25)):
        timestamp_atual += timedelta(seconds=random.randint(1, 3))
        logs.append(gerar_log(timestamp_atual, ip_origem, ip_destino, tipo_ataque="ddos"))

# Sessões Port Scan: Cada IP único escaneia vários destinos
for ip_origem in gerar_ips_privados(3000):  # 150 IPs diferentes
    destinos = random.sample(destinos_gerais, random.randint(5, 20))
    for ip_destino in destinos:
        timestamp_atual += timedelta(seconds=random.randint(5, 20))
        logs.append(gerar_log(timestamp_atual, ip_origem, ip_destino, tipo_ataque="portscan"))

# Sessões mistas com IPs exclusivos
for ip_origem in gerar_ips_privados(3000):  # 100 IPs diferentes
    for _ in range(random.randint(10, 20)):
        ip_destino = random.choice(destinos_gerais)
        timestamp_atual += timedelta(seconds=random.randint(2, 15))
        logs.append(gerar_log(timestamp_atual, ip_origem, ip_destino, tipo_ataque="misto"))

# === Exportar CSV ===
os.makedirs("database_treinamento/logs", exist_ok=True)
timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
nome_arquivo = f"logs_maliciosos_{timestamp_str}.csv"
df = pd.DataFrame(logs)
df.to_csv(f"database_treinamento/logs/{nome_arquivo}", index=False)
print(f"📁 CSV gerado com sucesso: {nome_arquivo}")
