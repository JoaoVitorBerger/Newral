import csv
import random
from datetime import datetime, timedelta

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

colunas = [
    "Tempo", "Tipo de Regra", "Ação", "Usuário", "Código",
    "Descrição Recurso", "Identificador", "SNAT",
    "Porta Interna", "Porta Externa",
    "IP de Origem", "IP de Destino",
    "Porta de Origem", "Porta de Destino",
    "Protocolo", "Prioridade", "Descrição", "Extra1", "Classificacao"
]

logs = []

# 1. Ataque DDoS — IPs de origem variados atacando mesmo destino em alta frequência
ddos_target = "192.168.100.100"
for i in range(500):
    log = [
        (base_time + timedelta(seconds=i // 50)).strftime("%Y-%m-%d %H:%M:%S"),
        "Firewall Rule",
        "Allowed",
        "",  # sem usuário
        200 + i % 50,
        "ACESSO INTERNET REDE DE ACESSO",
        random.choice(identificadores),
        random.choice(services),
        f"Port{random.randint(1, 10)}.{random.randint(1, 30)}",
        f"Port{random.randint(1, 10)}.{random.randint(1, 30)}",
        f"185.167.225.{random.randint(1, 254)}",
        ddos_target,
        random.randint(54000, 55000),
        80,
        "TCP",
        1,
        "Ataque DDoS detectado",
        "",
        1  # 1 = DDoS
    ]
    logs.append(log)

# 2. Ataque Port Scan — mesmo IP escaneando várias portas de um destino
portscan_source = "10.10.10.10"
portscan_target = "172.16.0.1"
for port in range(20, 1020):  # 1000 portas
    log = [
        (base_time + timedelta(seconds=2000 + port)).strftime("%Y-%m-%d %H:%M:%S"),
        "Firewall Rule",
        "Allowed",
        random.choice(users),
        250 + port % 50,
        "ACESSO INTERNET REDE DE ACESSO",
        random.choice(identificadores),
        random.choice(services),
        f"Port{random.randint(1, 10)}.{random.randint(1, 30)}",
        f"Port{random.randint(1, 10)}.{random.randint(1, 30)}",
        portscan_source,
        portscan_target,
        random.randint(50000, 51000),
        port,
        "TCP",
        2,
        "Port Scan detectado",
        "",
        2  # 2 = Port Scan
    ]
    logs.append(log)

# Exportar para CSV
caminho = "D:\\RandomForest\\Newral\\database_treinamento\\trafego_malicioso_padronizado.csv"
with open(caminho, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(colunas)
    writer.writerows(logs)

print(f"Arquivo '{caminho}' gerado com sucesso.")
