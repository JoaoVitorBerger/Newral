import pandas as pd
import random
from datetime import datetime, timedelta
from ipaddress import IPv4Address

# === Funções auxiliares ===
def gerar_ips_privados(qtd):
    return [str(IPv4Address(f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}")) for _ in range(qtd)]

def gerar_log_para_csv(timestamp, ip_origem, ip_destino, porta_origem, porta_destino, tipo_ataque):
    return {
        "timestamp": timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "evento": "Firewall Rule",
        "ação": "Allowed",
        "usuario": "teste@pmg.local" if tipo_ataque else None,
        "cod1": round(random.uniform(70, 130), 1),
        "descricao_rede": "ACESSO INTERNET REDE DE ACESSO",
        "cod2": random.randint(100, 200),
        "nat_policy": "Default SNAT IPv4",
        "porta_saida": f"Port{random.randint(1, 10)}.{random.randint(1, 30)}",
        "porta_entrada": f"Port{random.randint(1, 20)}",
        "ip_origem": ip_origem,
        "ip_destino": ip_destino,
        "porta_origem": porta_origem,
        "porta_destino": float(porta_destino),
        "protocolo": "TCP",
        "flag": 1,
        "label": 1 if tipo_ataque else 0
    }

# === Gerar logs ===
hora_aleatoria = random.randint(14, 17)
minuto_aleatorio = random.randint(0, 59)
data_base = datetime(2025, 3, 6, hora_aleatoria, minuto_aleatorio, 0)

ips_simulados = gerar_ips_privados(1000)
logs_teste = []
intervalo = timedelta(seconds=60) / 10000  # 10.000 eventos em 1 minuto

for i in range(10000):
    timestamp = data_base + (i * intervalo)

    tipo_evento = random.choices(
        population=["normal", "ddos", "portscan"],
        weights=[0.85, 0.10, 0.05],
        k=1
    )[0]

    if tipo_evento == "ddos":
        log = gerar_log_para_csv(timestamp, random.choice(ips_simulados), "10.10.10.25", random.randint(50000, 60000), 80, True)
    elif tipo_evento == "portscan":
        log = gerar_log_para_csv(timestamp, "192.168.1.54", "192.168.1.20", random.randint(50000, 60000), random.randint(20, 1024), True)
    else:
        log = gerar_log_para_csv(timestamp, random.choice(ips_simulados), "192.168.1.1", random.randint(1024, 50000), 443, False)

    logs_teste.append(log)

# === Salvar CSV ===
df_teste_modelo = pd.DataFrame(logs_teste)
df_teste_modelo.to_csv("logs_simulados.csv", index=False)

print(f"CSV gerado com sucesso: logs_simulados.csv | Início: {data_base.strftime('%H:%M:%S')}")
