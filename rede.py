import pandas as pd
import requests
from bs4 import BeautifulSoup
import numpy as np
import ipaddress
from sklearn.utils import resample
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.metrics import roc_curve, auc
import matplotlib.pyplot as plt

BLACKLIST_URL = "https://github.com/dolutech/blacklist-dolutech/blob/main/Black-list-semanal-dolutech.txt"
BLACKLIST_FILE = "Black-list-semanal-dolutech.txt"

# Função para baixar a blacklist
def baixar_blacklist():
    response = requests.get(BLACKLIST_URL)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        ips = soup.find_all('span', class_='pl-c1')
        ips_extraidos = [ip.get_text() for ip in ips]
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

def ip_to_int(ip):
    """Converte um endereço IP para um número inteiro."""
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0  # Se não for um IP válido, retorna 0

def protocolo_para_int(protocolo):
    """Mapeia protocolos para valores numéricos."""
    protocolos = {"TCP": 6, "UDP": 17, "ICMP": 1}
    return protocolos.get(protocolo.upper(), -1)  # Retorna -1 se não estiver na lista

def preparar_dados(caminho_arquivo):
    """Processa os dados do arquivo CSV e retorna um DataFrame formatado."""
    colunas = [
        "Tempo", "Tipo de Regra", "Ação", "Usuário", "Código",
        "Descrição", "Prioridade", "SNAT", "Porta Interna", "Porta Externa",
        "IP de Origem", "IP de Destino", "Porta de Origem", "Porta de Destino",
        "Protocolo", "Bytes Transferidos"
    ]    # Tentar carregar os dados
    try:
        df = pd.read_csv(caminho_arquivo, header=None, names=colunas, delimiter=",", engine="python")
    except:
        df = pd.read_csv(caminho_arquivo, header=None, names=colunas, delimiter=";", engine="python")
    
    # Converte a coluna de tempo para timestamp UNIX
    df["Tempo"] = pd.to_datetime(df["Tempo"], errors="coerce").astype(np.int64) // 10**9      # Adiciona colunas de tempo (Ano, Mês, Dia, Hora, Minuto, Segundo)
    df["Hora"] = pd.to_datetime(df["Tempo"], unit="s").dt.hour
    df["Minuto"] = pd.to_datetime(df["Tempo"], unit="s").dt.minute
    df["Segundo"] = pd.to_datetime(df["Tempo"], unit="s").dt.second    # Mapeia se o usuário existe (1 se existir, 0 se for vazio)
    df["Tempo_Segundos"] = df["Hora"] * 3600 + df["Minuto"] * 60 + df["Segundo"]
    df["Usuário"] = df["Usuário"].apply(lambda x: 1 if isinstance(x, str) and x.strip() else 0)    # Converte IPs para inteiros
    df["IP de Origem"] = df["IP de Origem"].apply(ip_to_int)
    df["IP de Destino"] = df["IP de Destino"].apply(ip_to_int)    # Converte protocolos para valores numéricos
    df["Protocolo"] = df["Protocolo"].apply(protocolo_para_int)    # Converte portas para inteiros
    df["Porta de Origem"] = pd.to_numeric(df["Porta de Origem"], errors="coerce").fillna(0).astype(int)
    df["Porta de Destino"] = pd.to_numeric(df["Porta de Destino"], errors="coerce").fillna(0).astype(int)    # Seleciona as colunas relevantes
    colunas_finais = ["Tempo","Hora", "Minuto", "Segundo","Tempo_Segundos",
                      "Usuário", "IP de Origem", "IP de Destino", "Protocolo",
                      "Porta de Origem", "Porta de Destino"]
  
    df_final = df[colunas_finais]
    return df_final

def extrair_features_adicionais(df, blacklist_set=None):
    df["Tempo"] = pd.to_datetime(df["Tempo"])
    # Ordena o DataFrame por IP de Origem e Tempo
    df_sorted = df.sort_values(by=["IP de Origem", "Tempo"])
    grupos = df_sorted.groupby("IP de Origem")
    
    # Número total de conexões por IP de Origem
    qtd_conexoes = grupos.size().rename("Qtd_Conexoes")
    
    # Número de IPs de Destino únicos
    diversidade_ip_destino = grupos["IP de Destino"].nunique().rename("Diversidade_IP_Destino")
    
    # Tempo total de atividade (diferença entre última e primeira requisição)
    tempo_total = grupos["Tempo_Segundos"].agg(lambda x: x.max() - x.min()).rename("Tempo_Total_das_requisicoes")

    # Taxa de requisições por segundo
    taxa = (qtd_conexoes / tempo_total.replace(0, np.nan)).fillna(0).rename("Requisicoes_por_Segundo")

    qtd_portas_solicitadas = grupos["Porta de Destino"].count().rename("Qtd_Portas_Solicitadas")
    # Combina as features em um DataFrame
    df_features = pd.concat([qtd_conexoes, diversidade_ip_destino, tempo_total, taxa, qtd_portas_solicitadas], axis=1).reset_index()
    
    # Converter os IPs de Origem para inteiro para comparação
    df_features["IP de Origem Num"] = df_features["IP de Origem"].apply(lambda ip: ip_to_int(ip) if isinstance(ip, str) else ip)
    
    # Adiciona a coluna de Blacklist: 1 se o IP de Origem está na blacklist, 0 caso contrário
    if blacklist_set is not None:
        df_features["Blacklist"] = df_features["IP de Origem Num"].apply(lambda ip: 1 if str(ip) in blacklist_set or ip in [ip_to_int(item) for item in blacklist_set] else 0)
    else:
        df_features["Blacklist"] = 0
    
    return df_features

def formatar_log_csv(entrada_csv: str, saida_csv: str):
    colunas = [
        "Tempo", "Tipo de Regra", "Ação", "Usuário", "Código",
        "Descrição", "Prioridade", "SNAT", "Porta Interna", "Porta Externa",
        "IP de Origem", "IP de Destino", "Porta de Origem", "Porta de Destino",
        "Protocolo", "Bytes Transferidos"
    ]

    linhas_processadas = []
    
    with open(entrada_csv, "r", encoding="utf-8") as file:
        for linha in file:
            linha = linha.strip()
            campos = linha.split(",")

            # Pula linhas com valores como '0,1,2,...' ou cabeçalho duplicado
            if campos == colunas:
                continue
            if all(c.isdigit() for c in campos[:len(colunas)]):
                continue

            if len(campos) >= len(colunas):
                campos = campos[:len(colunas)]
                linhas_processadas.append(campos)
    
    df = pd.DataFrame(linhas_processadas, columns=colunas)
    df.to_csv(saida_csv, index=False, header=False, columns=colunas, encoding="utf-8")
    print(f"Arquivo salvo como: {saida_csv}")
    

formatar_nao_classificados  =  formatar_log_csv("Log_Viewer.csv", "Nao_avaliado.csv")
formatar_classificados  =  formatar_log_csv("logs_maliciosos.csv", "Malicioso.csv")

nao_classificados = preparar_dados("Nao_avaliado.csv")
classificados = preparar_dados("Malicioso.csv")

print("Total após preparação:", len(nao_classificados))
print("Nulos por coluna:")
print(nao_classificados.isnull().sum())

def classificar_comportamento(row):
    if row["Requisicoes_por_Segundo"] <= 0.013 and row["Diversidade_IP_Destino"] > 10:
        return "DDos" # DDoS
    elif (row["Requisicoes_por_Segundo"] <= 0.013  and (row["Qtd_Portas_Solicitadas"] > 10 or row["Qtd_Conexoes"]>20)):
        return "Port Scan"  # Port Scan
    elif row["Blacklist"] == 1:
        return 3  # Outro comportamento anômalo
    else:
        return 0  # Normal


blacklist = carregar_blacklist()
nao_classificados_features = extrair_features_adicionais(nao_classificados, blacklist)
classificados_features = extrair_features_adicionais(classificados, blacklist)

print(classificados_features.__len__())
# Adiciona coluna de classe
nao_classificados_features["Classe"] = 0  # Não malicioso
classificados_features["Classe"] = 1      # Malicioso

# Junta os dois datasets
df = pd.concat([nao_classificados_features, classificados_features], ignore_index=True)

# Separa por classe
classe_0 = df[df["Classe"] == 0]
classe_1 = df[df["Classe"] == 1]
# Verifica qual classe está em menor quantidade
if len(classe_0) > len(classe_1):
    classe_minoria = classe_1
    classe_majoria = classe_0
else:
    classe_minoria = classe_0
    classe_majoria = classe_1
# Faz oversampling da minoria para igualar a maioria
classe_minoria_upsampled = resample(
    classe_minoria,
    replace=True,
    n_samples=len(classe_majoria),
    random_state=42
)

def int_to_ip(ip_int):
    try:
        return str(ipaddress.IPv4Address(int(ip_int)))
    except:
        return None

print(classe_majoria[:10])
print(classe_minoria_upsampled[:10])
# Junta os dois de novo, agora balanceados
df_balanceado = pd.concat([classe_majoria, classe_minoria_upsampled], ignore_index=True)
# Embaralha os dados (opcional, mas recomendado)
# df_balanceado = df_balanceado.sample(frac=1, random_state=42).reset_index(drop=True)
# Agora seus dados estão prontos para o modelo
X = df_balanceado.drop("Classe", axis=1)
y = df_balanceado["Classe"]

# Divide os dados em treino e teste
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

print("Valores para teste",X_test)
# Cria e treina o modelo
modelo = RandomForestClassifier(n_estimators=5, max_depth=3)
modelo.fit(X_train, y_train)
# Faz previsões
y_pred = modelo.predict(X_test)

# Junta os dados de teste com os resultados das previsões
df_resultado = X_test.copy()
df_resultado["Classe_Real"] = y_test.values
df_resultado["Classe_Prevista"] = y_pred

# Apenas registros 
ips_maliciosos = df_resultado
ips_maliciosos['IP de Origem'] = ips_maliciosos['IP de Origem'].apply(int_to_ip)
ips_maliciosos["Comportamento"] = ips_maliciosos.apply(classificar_comportamento, axis=1)
ips_maliciosos.to_csv("ips_maliciosos.csv", index=False, sep=";", encoding="utf-8")
# Avaliação
print(classification_report(y_test, y_pred))


y_proba = modelo.predict_proba(X_test)[:, 1]
fpr, tpr, _ = roc_curve(y_test, y_proba)
roc_auc = auc(fpr, tpr)

plt.figure()
plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {roc_auc:.2f})")
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel("FPR")
plt.ylabel("TPR")
plt.title("Curva ROC")
plt.legend(loc="lower right")
plt.grid()
plt.show()