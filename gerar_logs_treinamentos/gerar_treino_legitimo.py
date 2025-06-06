import pandas as pd
import random
import os
from datetime import datetime, timedelta
from ipaddress import IPv4Address

# === Geração de IPs internos de alta diversidade ===
def gerar_ips_privados(qtd):
    ranges = [
        (167772160, 184549375),      # 10.0.0.0/8
        (2886729728, 2887778303),    # 172.16.0.0/12
        (3232235520, 3232301055)     # 192.168.0.0/16
    ]
    return [str(IPv4Address(random.randint(*random.choice(ranges)))) for _ in range(qtd)]

# === Geração de logs legítimos ===
def gerar_log_legitimo(timestamp, ip_origem, ip_destino, porta_origem, porta_destino):
    return {
        "timestamp": timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "evento": random.choice(["Firewall Rule", "Session Log", "Allowed Access"]),
        "ação": random.choices(["Allowed", "Accepted"], weights=[0.95, 0.05])[0],
        "usuario": random.choice([
            "usuario@pmg.local", "admin@pmg.local", "scanner@iot.local",
            "guest@pmg.local", "vazio@pmg.local"
        ]),
        "cod1": round(random.uniform(10, 250), 2),
        "descricao_rede": random.choice([
            "ACESSO INTERNET REDE DE ACESSO", "TRÁFEGO INTERNO", "VPN CORPORATIVA",
            "ACESSO À REDE WI-FI", "REDE CONVIDADO", "REDE EDUCACIONAL"
        ]),
        "cod2": random.randint(50, 300),
        "nat_policy": random.choice([
            "Default SNAT IPv4", "Custom SNAT", "SNAT Alternativo", "Redirecionamento SNAT"
        ]),
        "porta_saida": f"Port{random.randint(1, 50)}.{random.randint(1, 99)}",
        "porta_entrada": f"Port{random.randint(1, 50)}",
        "ip_origem": ip_origem,
        "ip_destino": ip_destino,
        "porta_origem": porta_origem,
        "porta_destino": float(random.choice([
            porta_destino, 80, 443, 22, 25, 110, 143, 8080, 8443, 3306, 3389
        ])),
        "protocolo": random.choice(["TCP", "UDP", "ICMP"]),
        "flag": random.randint(0, 1),
    }

# === Parâmetros de simulação ===
base_time = datetime(2025, 3, 6, 6, 0, 0)
timestamp_atual = base_time

ips_simulados = gerar_ips_privados(2000)
ips_destino_legitimos = gerar_ips_privados(500)

logs_legitimos = []

total_eventos = 10000

for _ in range(total_eventos):
    incremento = timedelta(seconds=random.randint(10, 30))
    timestamp_atual += incremento
    log = gerar_log_legitimo(
        timestamp_atual,
        random.choice(ips_simulados),
        random.choice(ips_destino_legitimos),
        random.randint(1024, 65535),
        random.randint(1024, 49151)
    )
    logs_legitimos.append(log)

# === Exporta para CSV ===
os.makedirs("database_treinamento/logs", exist_ok=True)
df_legitimo = pd.DataFrame(logs_legitimos)
df_legitimo.to_csv("database_treinamento/logs/logs_legitimos12.csv", index=False)
print("📁 Arquivo logs_legitimos7.csv gerado com sucesso.")
