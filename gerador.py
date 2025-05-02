import pandas as pd
import random
from datetime import datetime, timedelta
import csv

random.seed(42)
base_time = datetime(2025, 3, 7, 2, 0, 0)

users = [
    "roberto.lima@pmg.local", "ana.santos@pmg.local",
    "maria.oliveira@pmg.local", "joana.pereira@pmg.local", ""
]
protocols = ["TCP", "UDP"]
services = ["Default SNAT IPv4", "SSH", "HTTP", "OpenVPN", "HTTPS"]
identificadores = list(range(50, 120))
descricoes = ["LDAP Aberto", "Acesso externo", "Serviço desconhecido"]
classificacoes = [1]

colunas = [
    "Tempo", "Tipo de Regra", "Ação", "Usuário", "Código",
    "Descrição Recurso", "Identificador", "SNAT",
    "Porta Interna", "Porta Externa",
    "IP de Origem", "IP de Destino",
    "Porta de Origem", "Porta de Destino",
    "Protocolo", "Prioridade", "Descrição", "Extra1", "Classificação"
]

logs = []

# 1. Tráfego normal
for i in range(1500):
    log = [
        (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
        "Firewall Rule",
        "Allowed",
        random.choice(users),
        100 + i % 50,
        "ACESSO INTERNET REDE DE ACESSO",
        random.choice(identificadores),
        random.choice(services),
        f"Port{random.randint(1, 10)}.{random.randint(1, 30)}",
        f"Port{random.randint(1, 10)}.{random.randint(1, 30)}",
        f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        random.randint(54000, 55000),
        random.choice([80, 8080, 443]),
        random.choice(protocols),
        random.choice([1, 2]),
        random.choice(descricoes),
        "",
        random.choice(classificacoes)
    ]
    logs.append(log)

# 2. Ataque DDoS (mesmo destino, origens variadas)
ddos_target = "192.168.100.100"
ddos_atacante= "185.167.225.100"
for i in range(1500, 1550):
    log = [
        (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
        "Firewall Rule",
        "Allowed",
        "",  # sem usuário
        200 + i % 50,
        "ACESSO INTERNET REDE DE ACESSO",
        random.choice(identificadores),
        "HTTP",
        "Port4.22",
        "Port5.30",
        ddos_atacante,  # origem aleatória
        ddos_target,
        random.randint(54000, 55000),
        80,
        "TCP",
        1,
        "Ataque DDoS detectado",
        "",
        1
    ]
    logs.append(log)

# 3. Ataque Port Scan (mesmo IP origem escaneando muitas portas do mesmo destino)
portscan_source = "10.10.10.10"
portscan_target = "172.16.0.1"
for port in range(20, 1020):  # 1000 portas
    log = [
        (base_time + timedelta(seconds=2000 + port)).strftime("%Y-%m-%d %H:%M:%S"),
        "Firewall Rule",
        "Allowed",
        "joana.pereira@pmg.local",
        250 + port % 50,
        "ACESSO INTERNET REDE DE ACESSO",
        random.choice(identificadores),
        "SSH",
        "Port2.3",
        "Port3.1",
        portscan_source,
        portscan_target,
        random.randint(50000, 51000),
        port,
        "TCP",
        2,
        "Port Scan detectado",
        "",
        1
    ]
    logs.append(log)

# Ordenar por tempo
logs.sort(key=lambda x: x[0])

# Exportar para CSV
with open("D:\\RandomForest\\Newral\\database_para_teste\\logs_maliciosos_padronizados.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(colunas)
    writer.writerows(logs)

print("Arquivo 'logs_maliciosos_padronizados.csv' gerado com sucesso.")
