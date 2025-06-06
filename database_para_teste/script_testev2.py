import pandas as pd
import random
from datetime import datetime, timedelta
from ipaddress import IPv4Address

def gerar_ips_privados(qtd):
    ranges = [
        (167772160, 184549375),      # 10.0.0.0/8
        (2886729728, 2887778303),    # 172.16.0.0/12
        (3232235520, 3232301055)     # 192.168.0.0/16
    ]
    return [str(IPv4Address(random.randint(*random.choice(ranges)))) for _ in range(qtd)]

def gerar_log_extremo(timestamp, ip_origem, ip_destino, porta_origem, porta_destino, tipo_ataque):
    protocolo_especial = random.choice(["GRE", "ESP", "IGMP", "ICMP", "HOPOPT", "UDPLite"])
    usuario_fake = random.choice([
        "honeypot@decoy.net", "script@auto.local", "root@fake.dmz", "", None
    ])
    descricao = random.choice([
        "TRÁFEGO SUSPEITO", "VARREDURA INTENSA", "RECONHECIMENTO HOST", 
        "FLOODING ICMP", "TENTATIVA SSH", "TRÁFEGO NORMAL"
    ])
    return {
        "timestamp": timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "evento": random.choice(["Firewall Rule", "Syslog", "Alert", "Session Start"]),
        "ação": random.choice(["Allowed", "Denied", "Dropped"]),  # até ataque permitido
        "usuario": usuario_fake,
        "cod1": random.choice([0.0, round(random.uniform(10, 300), 2), 999.9]),  # variações extremas
        "descricao_rede": descricao,
        "cod2": random.choice([0, 255, 500]),  # cod2 mal definido
        "nat_policy": random.choice(["Ataque NAT", "Default SNAT IPv4", "Double NAT", "None"]),
        "porta_saida": f"Port{random.randint(1, 99)}.{random.randint(1, 99)}",
        "porta_entrada": f"Port{random.randint(1, 99)}",
        "ip_origem": ip_origem,
        "ip_destino": ip_destino,
        "porta_origem": random.choice([porta_origem, random.randint(0, 1023)]),  # portas reservadas
        "porta_destino": float(random.choice([porta_destino, 0, 65535])),
        "protocolo": protocolo_especial,
        "flag": random.randint(0, 1),
        "label": 1 if tipo_ataque else 0
    }

# Simulação extrema
base_time = datetime(2025, 3, 6, 5, 0, 0)
ips_simulados = gerar_ips_privados(3000)
ips_destino = gerar_ips_privados(1000)
logs_extremos = []

for _ in range(12000):  # aumenta volume
    dispersao = timedelta(seconds=random.randint(0, 43200))  # até 12h
    jitter = timedelta(milliseconds=random.randint(-1000, 1500))
    timestamp = base_time + dispersao + jitter

    tipo = random.choices(["ddos", "portscan", "normal", "inverso"], weights=[0.4, 0.2, 0.3, 0.1])[0]
    if tipo == "ddos":
        log = gerar_log_extremo(timestamp, random.choice(ips_simulados), "10.10.10.25", random.randint(30000, 60000), 80, True)
    elif tipo == "portscan":
        log = gerar_log_extremo(timestamp, "192.168.1.54", random.choice(ips_destino), random.randint(1000, 50000), random.randint(1, 1024), True)
    elif tipo == "inverso":  # comportamento normal rotulado como ataque
        log = gerar_log_extremo(timestamp, random.choice(ips_simulados), random.choice(ips_destino), random.randint(1024, 65535), 443, True)
    else:
        log = gerar_log_extremo(timestamp, random.choice(ips_simulados), random.choice(ips_destino), random.randint(1024, 65535), 443, False)

    logs_extremos.append(log)

# Exporta CSV
df_extremo = pd.DataFrame(logs_extremos)
df_extremo.to_csv("simulacao_trefego_para_avaliacao_agressivo.csv", index=False)
print("📁 Dataset extremo de avaliação gerado: logs_extremos_avaliacao.csv")




# Variações imprevisíveis de horários (incluindo picos e lacunas de tráfego).
# IPs duplicados com comportamentos conflitantes (normal e ataque).
# Porta de origem como número de sistema ou reservada.
# Protocolos obscuros ou raramente usados.
# Ação "Allowed" em eventos de ataque (falso positivo proposital).
# Usuários simulados de honeypots ou serviços automatizados.
# Campos intencionalmente inconsistentes (ex: cod1 = 0.0 ou valores muito altos).