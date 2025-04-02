import pandas as pd
import requests
from collections import defaultdict
from datetime import datetime
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import re
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

BLACKLIST_URL = "https://github.com/dolutech/blacklist-dolutech/blob/main/Black-list-semanal-dolutech.txt"
BLACKLIST_FILE = "Black-list-semanal-dolutech.txt"

# Função para baixar a blacklist
def baixar_blacklist():
    response = requests.get(BLACKLIST_URL)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        ips = soup.find_all('span', class_='pl-c1')
        ips_extraidos = [ip.get_text() for ip in ips[:900]]
        if ips_extraidos:
            with open(BLACKLIST_FILE, 'w') as file:
                for ip in ips_extraidos:
                    file.write(ip + "\n")
            return ips_extraidos
    return []

# Função para carregar a blacklist
def carregar_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        baixar_blacklist()
        return carregar_blacklist()

# Função para criar features avançadas
def criar_features_avancadas(df):
    # Converter timestamp para datetime
    df['datetime'] = pd.to_datetime(df['timestamp'])
    
    # Feature de horário noturno (00h-6h)
    df['noturno'] = df['datetime'].dt.hour.apply(lambda x: 1 if x < 6 else 0)
    
    # Portas privilegiadas (SSH, RDP, etc.)
    df['porta_privilegiada'] = df['porta_destino'].apply(
        lambda x: 1 if x in [22, 3389, 3306, 1433, 445, 8080] else 0)
    
    # IP está na blacklist
    blacklist = carregar_blacklist()
    df['na_blacklist'] = df['ip'].apply(lambda x: 1 if x in blacklist else 0)
    
    # Taxa de acessos por minuto
    df['acessos_por_minuto'] = df.groupby('ip')['ip'].transform('count') / 5  # Janela de 5 minutos
    
    # Diversidade de portas acessadas
    df['diversidade_portas'] = df.groupby('ip')['porta_destino'].transform('nunique')
    
    return df

# Função para processar o CSV e extrair features
def process_csv(file_path, limit=900):
    df = pd.read_csv(file_path, header=None, delimiter=",", engine="python", on_bad_lines="skip")
    blacklist = carregar_blacklist()
    dados = []
    acessos_por_usuario = defaultdict(lambda: defaultdict(int))
    acessos_sem_usuario = defaultdict(int)
    ips_conversando = defaultdict(set)
    velocidade_requisicoes = defaultdict(list)

    for _, row in df.iterrows():
        if row[2] == "Allowed":
            ip_destino = row[11]
            usuario = row[3] if not pd.isna(row[3]) and row[3] != "" else None
            timestamp = row[0]
            porta_origem = row[12]
            porta_destino = row[13]

            if isinstance(ip_destino, str) and re.match(r'\d+\.\d+\.\d+\.\d+', ip_destino):
                ausencia_usuario = 1 if usuario is None else 0

                if usuario:
                    acessos_por_usuario[usuario][ip_destino] += 1
                else:
                    acessos_sem_usuario[ip_destino] += 1

                ips_conversando[ip_destino].add(usuario) if usuario else None

                try:
                    timestamp_dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    velocidade_requisicoes[ip_destino].append(timestamp_dt)
                except ValueError:
                    print(f"Formato de timestamp inválido: {timestamp}")

                dados.append({
                    "ip": ip_destino,
                    "ausencia_usuario": ausencia_usuario,
                    "frequencia_acesso": acessos_por_usuario[usuario][ip_destino] if usuario else acessos_sem_usuario[ip_destino],
                    "ips_conversando": len(ips_conversando[ip_destino]),
                    "timestamp": timestamp,
                    "porta_origem": porta_origem,
                    "porta_destino": porta_destino
                })
                if len(dados) >= limit:
                    break

    df_dados = pd.DataFrame(dados)
    df_dados['ausencia_usuario'] = df_dados.groupby('ip')['ausencia_usuario'].transform('mean')

    def calcular_media_intervalo_temporal(timestamps):
        if len(timestamps) < 2:
            return 0
        timestamps.sort()
        intervalos = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps) - 1)]
        return sum(intervalos) / len(intervalos)

    df_dados['media_intervalo_temporal'] = df_dados['ip'].apply(lambda ip: calcular_media_intervalo_temporal(velocidade_requisicoes[ip]))
    
    # Aplicar features avançadas
    df_dados = criar_features_avancadas(df_dados)
    
    return df_dados

# Processar dados
file_path = 'Log_Viewer.csv'
dados_csv = process_csv(file_path)
dados_maliciosos = process_csv("logs_maliciosos.csv")

# Adicionar rótulos
dados_csv['rotulo'] = 0
dados_maliciosos['rotulo'] = 1

# Combinar dados
dados_completos = pd.concat([dados_csv, dados_maliciosos], ignore_index=True)

# Codificar portas
encoder = LabelEncoder()
dados_completos['porta_destino'] = encoder.fit_transform(dados_completos['porta_destino'])
dados_completos['porta_origem'] = encoder.fit_transform(dados_completos['porta_origem'])

# Features selecionadas
colunas_features = [
    'ausencia_usuario',
    'frequencia_acesso',
    'ips_conversando',
    'media_intervalo_temporal',
    'porta_destino',
    'noturno',
    'porta_privilegiada',
    'na_blacklist',
    'acessos_por_minuto',
    'diversidade_portas'
]

# Normalização
scaler = MinMaxScaler()
dados_completos[colunas_features] = scaler.fit_transform(dados_completos[colunas_features])

# Dividir dados
X = dados_completos[colunas_features]
y = dados_completos['rotulo']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Modelo otimizado
modelo = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    class_weight={0:1, 1:3},
    min_samples_leaf=2,
    max_features='sqrt',
    random_state=42
)
modelo.fit(X_train, y_train)


# ADICIONE ESTA SEÇÃO PARA GERAR O RELATÓRIO DE IPS SUSPEITOS:
def gerar_relatorio_suspeitos(modelo, dados, colunas_features, threshold=0.7):
    # Fazer previsões e pegar probabilidades
    probas = modelo.predict_proba(dados[colunas_features])[:,1]
    dados['probabilidade_malicioso'] = probas
    
    # Filtrar IPs suspeitos
    ips_suspeitos = dados[dados['probabilidade_malicioso'] >= threshold].copy()
    
    # Função para explicar as decisões
    def explicar_decisao(row):
        reasons = []
        if row['na_blacklist'] > 0.5:
            reasons.append("IP na blacklist conhecida")
        if row['porta_privilegiada'] > 0.5:
            reasons.append(f"Acesso a porta privilegiada ({row['porta_destino']})")
        if row['noturno'] > 0.5:
            reasons.append("Atividade noturna (00h-6h)")
        if row['ausencia_usuario'] > 0.8:
            reasons.append("Alta taxa de acessos sem autenticação")
        if row['acessos_por_minuto'] > np.percentile(dados['acessos_por_minuto'], 70):
            reasons.append(f"Taxa anormal de acessos ({row['acessos_por_minuto']:.1f}/min)")
        if row['diversidade_portas'] > np.percentile(dados['diversidade_portas'], 70):
            reasons.append(f"Varredura de portas ({int(row['diversidade_portas'])} portas distintas)")
        return "; ".join(reasons) if reasons else "Padrão genérico suspeito"
    
    # Adicionar coluna de razões
    ips_suspeitos['razao_suspeita'] = ips_suspeitos.apply(explicar_decisao, axis=1)
    
    # Ordenar por probabilidade
    ips_suspeitos = ips_suspeitos.sort_values('probabilidade_malicioso', ascending=False)
    
    # Selecionar colunas relevantes para o relatório
    cols_relatorio = ['ip', 'probabilidade_malicioso', 'razao_suspeita'] + colunas_features
    return ips_suspeitos[cols_relatorio]

# Configurações para exibição completa no pandas
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

# Gerar relatório completo
relatorio_suspeitos = gerar_relatorio_suspeitos(modelo, dados_csv, colunas_features)

# Função para exibir todos os IPs formatados
def exibir_todos_ips(relatorio):
    print("\n" + "="*100)
    print("RELATÓRIO COMPLETO DE IPS SUSPEITOS".center(100))
    print("="*100)
    
    if relatorio.empty:
        print("\nNenhum IP suspeito encontrado!")
        return
    
    print(f"\nTotal de IPs suspeitos detectados: {len(relatorio)}")
    print("\nDetalhamento completo:")
    
    # Exibir cada IP com suas informações
    for idx, linha in relatorio.iterrows():
        print("\n" + "-"*100)
        print(f"IP: {linha['ip']}")
        print(f"Probabilidade: {linha['probabilidade_malicioso']:.2%}")
        print(f"Razões: {linha['razao_suspeita']}")
        
        print("\nCaracterísticas detalhadas:")
        print(f"- Ausência usuário: {linha['ausencia_usuario']:.2f}")
        print(f"- Frequência acesso: {linha['frequencia_acesso']:.2f}")
        print(f"- IPs conversando: {linha['ips_conversando']:.2f}")
        print(f"- Intervalo temporal: {linha['media_intervalo_temporal']:.2f}")
        print(f"- Porta destino: {linha['porta_destino']}")
        print(f"- Horário noturno: {'Sim' if linha['noturno'] > 0.5 else 'Não'}")
        print(f"- Porta privilegiada: {'Sim' if linha['porta_privilegiada'] > 0.5 else 'Não'}")
        print(f"- Na blacklist: {'Sim' if linha['na_blacklist'] > 0.5 else 'Não'}")
        print(f"- Acessos/min: {linha['acessos_por_minuto']:.2f}")
        print(f"- Diversidade portas: {linha['diversidade_portas']}")

# Exibir todos os IPs
exibir_todos_ips(relatorio_suspeitos)

# Salvar em CSV (opcional)
relatorio_suspeitos.to_csv('ips_suspeitos_completo.csv', index=False)
print("\nRelatório completo salvo em 'ips_suspeitos_completo.csv'")