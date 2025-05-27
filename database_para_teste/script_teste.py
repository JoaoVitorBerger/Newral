import pandas as pd
import random
from datetime import datetime, timedelta
from ipaddress import IPv4Address

# === Função para IPs privados altamente diversos ===
def gerar_ips_privados(qtd):
    ranges = [
        (167772160, 184549375),      # 10.0.0.0/8
        (2886729728, 2887778303),    # 172.16.0.0/12
        (3232235520, 3232301055)     # 192.168.0.0/16
    ]
    return [str(IPv4Address(random.randint(*random.choice(ranges)))) for _ in range(qtd)]

# === Geração de log ===
def gerar_log_para_csv(timestamp, ip_origem, ip_destino, porta_origem, porta_destino, tipo_ataque):
    return {
        "timestamp": timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "evento": "Firewall Rule",
        "ação": random.choice(["Allowed", "Denied"]),
        "usuario": random.choice([
            "admin@pmg.local", "scanner@iot.local", "guest@public.net", "anon@vpn.org", "root@cloud", "", "exploit@rogue.net"
        ]),
        "cod1": round(random.uniform(30, 200), 2),
        "descricao_rede": random.choice([
            "ACESSO INTERNET REDE DE ACESSO", "TRÁFEGO INTERNO", "VPN CORPORATIVA", "REDE PÚBLICA", "TRÁFEGO SUSPEITO"
        ]),
        "cod2": random.randint(50, 300),
        "nat_policy": random.choice([
            "Default SNAT IPv4", "Custom SNAT", "SNAT Alternativo", "Ataque NAT", "Sem NAT"
        ]),
        "porta_saida": f"Port{random.randint(1, 15)}.{random.randint(1, 40)}",
        "porta_entrada": f"Port{random.randint(1, 25)}",
        "ip_origem": ip_origem,
        "ip_destino": ip_destino,
        "porta_origem": porta_origem,
        "porta_destino": float(porta_destino),
        "protocolo": random.choice(["TCP", "UDP", "ICMP", "ESP", "GRE"]),
        "flag": random.randint(0, 1),
        "label": 1 if tipo_ataque else 0
    }

# === Parâmetros base ===
data_base = datetime(2025, 3, 6, 7, 0, 0)
ips_simulados = gerar_ips_privados(2000)
logs_teste = []

# === Geração de 10.000 eventos ao longo de até 12 horas ===
for i in range(10000):
    dispersao_segundos = random.randint(0, 43200)  # até 12 horas
    jitter = timedelta(milliseconds=random.randint(-300, 700))
    timestamp = data_base + timedelta(seconds=dispersao_segundos) + jitter

    tipo_evento = random.choices(
        population=["normal", "ddos", "portscan"],
        weights=[0.80, 0.15, 0.05],
        k=1
    )[0]

    if tipo_evento == "ddos":
        log = gerar_log_para_csv(
            timestamp,
            random.choice(ips_simulados),
            "10.10.10.25",
            random.randint(1024, 65535),
            random.choice([80, 443, 22, 53, 123]),
            True
        )
    elif tipo_evento == "portscan":
        log = gerar_log_para_csv(
            timestamp,
            random.choice(["192.168.1.54", "172.20.5.88", "10.0.0.9"]),
            random.choice(ips_simulados),
            random.randint(30000, 60000),
            random.randint(1, 1024),
            True
        )
    else:
        log = gerar_log_para_csv(
            timestamp,
            random.choice(ips_simulados),
            random.choice(["192.168.1.1", "10.1.1.1", "172.16.0.1"]),
            random.randint(1024, 65535),
            random.choice([80, 443, 8080, 8443, 53, 3389, 3306, random.randint(1025, 49151)]),
            False
        )

    logs_teste.append(log)

# === Exportar CSV ===
df_teste_modelo = pd.DataFrame(logs_teste)
df_teste_modelo.to_csv("logs_simulados1.csv", index=False)

print("✅ CSV gerado com máxima aleatoriedade: logs_simulados_extremos.csv")
