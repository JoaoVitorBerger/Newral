import pandas as pd
import requests
from bs4 import BeautifulSoup
import numpy as np
import ipaddress
from sklearn.utils import resample
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report,confusion_matrix, ConfusionMatrixDisplay,roc_curve, auc
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree
import joblib
from joblib import dump,load
import seaborn as sns
import streamlit as st

BLACKLIST_URL = "https://github.com/dolutech/blacklist-dolutech/blob/main/Black-list-semanal-dolutech.txt"
BLACKLIST_FILE = "D:\\RandomForest\\Newral\\database_treinamento\\Black-list-semanal-dolutech.txt"

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

# Conversão de IP para inteiro
def ip_to_int(ip):
    try:
        parts = list(map(int, ip.strip().split('.')))
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    except:
        return 0

# Conversão de protocolo
def protocolo_para_int(protocolo):
    protocolos = protocolos = {
    "HOPOPT": 0,
    "ICMP": 1,
    "IGMP": 2,
    "GGP": 3,
    "IPv4": 4,
    "ST": 5,
    "TCP": 6,
    "CBT": 7,
    "EGP": 8,
    "IGP": 9,
    "BBN-RCC-MON": 10,
    "NVP-II": 11,
    "PUP": 12,
    "ARGUS": 13,
    "EMCON": 14,
    "XNET": 15,
    "CHAOS": 16,
    "UDP": 17,
    "MUX": 18,
    "DCN-MEAS": 19,
    "HMP": 20,
    "PRM": 21,
    "XNS-IDP": 22,
    "TRUNK-1": 23,
    "TRUNK-2": 24,
    "LEAF-1": 25,
    "LEAF-2": 26,
    "RDP": 27,
    "IRTP": 28,
    "ISO-TP4": 29,
    "NETBLT": 30,
    "MFE-NSP": 31,
    "MERIT-INP": 32,
    "DCCP": 33,
    "3PC": 34,
    "IDPR": 35,
    "XTP": 36,
    "DDP": 37,
    "IDPR-CMTP": 38,
    "TP++": 39,
    "IL": 40,
    "IPv6": 41,
    "SDRP": 42,
    "IPv6-Route": 43,
    "IPv6-Frag": 44,
    "IDRP": 45,
    "RSVP": 46,
    "GRE": 47,
    "DSR": 48,
    "BNA": 49,
    "ESP": 50,
    "AH": 51,
    "I-NLSP": 52,
    "SWIPE": 53,
    "NARP": 54,
    "MOBILE": 55,
    "TLSP": 56,
    "SKIP": 57,
    "ICMPv6": 58,
    "IPv6-NoNxt": 59,
    "IPv6-Opts": 60,
    "VRRP": 112,
    "L2TP": 115,
    "SCTP": 132,
    "UDPLite": 136
}
    return protocolos.get(str(protocolo).upper(), 0)

# Processamento inicial do CSV
def preparar_dados(caminho_arquivo):
    colunas = [
        "Tempo", "Tipo de Regra", "Ação", "Usuário", "Código",
        "Descrição", "Prioridade", "SNAT",
        "IP de Origem", "IP de Destino", "Porta de Origem", "Porta de Destino",
        "Protocolo", "Bytes Transferidos"
    ]

    try:
        df = pd.read_csv(caminho_arquivo, header=None, delimiter=",", engine="python")
    except:
        df = pd.read_csv(caminho_arquivo, header=None, delimiter=";", engine="python")
    # print(f"📥 preparar_dados: {len(df)} linhas após leitura inicial")
    # Ignora colunas de índice 8 e 9 (Porta Interna e Externa) e qualquer coluna extra
    df = df.iloc[:, [0,1,2,3,4,5,6,7,10,11,12,13,14,15]]
    df.columns = colunas

    df["Tempo"] = pd.to_datetime(df["Tempo"], errors="coerce")
    df["Timestamp"] = df["Tempo"].astype("int64") // 10**9
    
    df["Hora"] = df["Tempo"].dt.hour
    df["Minuto"] = df["Tempo"].dt.minute
    df["Segundo"] = df["Tempo"].dt.second
    df["Tempo_Segundos"] = df["Hora"] * 3600 + df["Minuto"] * 60 + df["Segundo"]
    df["Usuário"] = df["Usuário"].apply(lambda x: 1 if isinstance(x, str) and x.strip() else 0)
    df["IP de Origem"] = df["IP de Origem"].apply(ip_to_int)
    df["IP de Destino"] = df["IP de Destino"].apply(ip_to_int)
    df["Protocolo"] = df["Protocolo"].apply(protocolo_para_int)
    df["Porta de Origem"] = pd.to_numeric(df["Porta de Origem"], errors="coerce").fillna(0).astype(int)
    df["Porta de Destino"] = pd.to_numeric(df["Porta de Destino"], errors="coerce").fillna(0).astype(int)

    colunas_finais = ["Tempo_Segundos",
                      "Usuário", "IP de Origem", "IP de Destino", "Protocolo",
                      "Porta de Origem", "Porta de Destino"]
    # print(f"📊 valores selecionados: {len(df)} linhas após formatação")
    print(df[colunas_finais].head())
    return df[colunas_finais]

def extrair_features_adicionais(df, blacklist_set=None):
    print(f"📊 Entrada dataframe \n", df.head(), len(df))

    df_sorted = df.sort_values(by=["IP de Origem", "Tempo_Segundos"])
    grupos = df_sorted.groupby("IP de Origem")


    # Calcula estatísticas por IP de Origem
    qtd_conexoes = grupos.size().rename("Qtd_Conexoes")
    diversidade_ip_destino = grupos["IP de Destino"].nunique().rename("Diversidade_IP_Destino")
    tempo_total = df.groupby("IP de Origem")["Tempo_Segundos"].agg(lambda x: x.max() - x.min())
    print("valores de tempo total \n",tempo_total.head())
    qtd_portas_solicitadas = grupos["Porta de Destino"].count().rename("Qtd_Portas_Solicitadas")

    # Calcula a taxa de requisições por segundo (evita divisão por zero)
    taxa_requisicoes = (
        (qtd_conexoes / tempo_total.replace(0, pd.NA))
        .fillna(0)
        .astype(float)
        .rename("Requisicoes_por_Segundo")
    )

    # Junta tudo em um único DataFrame
    df_features = pd.concat([
        qtd_conexoes,
        tempo_total,
        diversidade_ip_destino,
        taxa_requisicoes,
        qtd_portas_solicitadas
    ], axis=1).reset_index()

    # Coluna de IP numérico
    df_features["IP de Origem Num"] = df_features["IP de Origem"]

    # Verifica se o IP está na blacklist
    if blacklist_set is not None:
        blacklist_ints = set(ip_to_int(ip) for ip in blacklist_set)
        df_features["Blacklist"] = df_features["IP de Origem Num"].apply(lambda ip: 1 if ip in blacklist_ints else 0)
    else:
        df_features["Blacklist"] = 0

    print(f"📊 Saída dataframe \n", df_features.head(), len(df_features))
    return df_features


def formatar_log_csv(entrada_csv: str, saida_csv: str):
    colunas = [
        "Tempo", "Tipo de Regra", "Ação", "Usuário", "Código",
        "Descrição", "Prioridade", "SNAT", "Porta Interna", "Porta Externa",
        "IP de Origem", "IP de Destino", "Porta de Origem", "Porta de Destino",
        "Protocolo", "Bytes Transferidos"
    ]

    linhas_processadas = []
    total_linhas_lidas = 0
    linhas_cabecalho_ignoradas = 0
    linhas_dados_invalidos = 0
    linhas_aceitas = 0

    with open(entrada_csv, "r", encoding="utf-8") as file:
        for linha in file:
            total_linhas_lidas += 1
            linha = linha.strip()
            campos = linha.split(",")

            if campos == colunas:
                linhas_cabecalho_ignoradas += 1
                continue
            if all(c.isdigit() for c in campos[:len(colunas)]):
                linhas_dados_invalidos += 1
                continue

            if len(campos) >= len(colunas):
                campos = campos[:len(colunas)]
                linhas_processadas.append(campos)
                linhas_aceitas += 1
            else:
                linhas_dados_invalidos += 1

    df = pd.DataFrame(linhas_processadas, columns=colunas)
    # print(df.head())

    # print("📊 Estatísticas da montagem do dataset:")
    # print(f"🔹 Total de linhas lidas: {total_linhas_lidas}")
    # print(f"🔹 Linhas ignoradas por serem cabeçalho: {linhas_cabecalho_ignoradas}")
    # print(f"🔹 Linhas inválidas (curtas ou numéricas): {linhas_dados_invalidos}")
    # print(f"✅ Linhas válidas processadas: {linhas_aceitas}")
    # print(f"🧹 Total de linhas no DataFrame final: {len(df)}")

    df.to_csv(saida_csv, index=False, header=False, columns=colunas, encoding="utf-8")
    # print(f"📁 Arquivo salvo como: {saida_csv}")

    
def processar_dados_completos(entrada_csv: str, nome: str):
    """
    Pipeline completo:
    1. Formata o CSV bruto.
    2. Prepara os dados básicos.
    3. Extrai features adicionais.
    Retorna o DataFrame final com as features extraídas.
    """

    # Etapa 1: Formata e limpa o CSV bruto
    csv_formatado = nome
    formatar_log_csv(entrada_csv, csv_formatado)
    print(f"📁 CSV formatado: {csv_formatado}")
    # Etapa 2: Prepara os dados
    df_preparado = preparar_dados(csv_formatado)
    print(f"🧹 Total de linhas no DataFrame preparado: {len(df_preparado)}")
    # Etapa 3: Extrai features adicionais
    df_features = extrair_features_adicionais(df_preparado)

    print(f"🧹 Total de linhas no DataFrame final: {len(df_features)}")
    return df_features

def classificar_comportamento(row):
    # Critério de DDoS
    if row["Requisicoes_por_Segundo"] <= 0.013 and row["Diversidade_IP_Destino"] == 1 and row["Qtd_Conexoes"] > 20:
        return "DDos"  # DDoS
    
    # Critério de Port Scan
    elif  row["Qtd_Portas_Solicitadas"] > 10 or row["Qtd_Conexoes"] > 20:
        return "Port Scan"  # Port Scan
    
    # Critério de IP na Blacklist (Outro comportamento anômalo)
    elif row["Blacklist"] == 1:
        return "Outro comportamento anômalo"
    
    # Caso não seja nenhum dos anteriores
    else:
        return "Normal"  # Comportamento normal


def preparar_dados_para_treinamento(df_malicioso, df_nao_malicioso):

    # Define rótulos
    df_nao_malicioso["Classe"] = 0
    df_malicioso["Classe"] = 1

    # Junta os dois datasets
    df = pd.concat([df_nao_malicioso, df_malicioso], ignore_index=True)

    # Separa por classe
    classe_0 = df[df["Classe"] == 0]
    classe_1 = df[df["Classe"] == 1]

    print(f"\n Antes do balanceamento:")
    print(f"Classe 0 (não malicioso): {len(classe_0)} registros")
    print(f"Classe 1 (malicioso): {len(classe_1)} registros")
    # Verifica classe com menor quantidade
    if len(classe_0) > len(classe_1):
        classe_minoria = classe_1
        classe_majoria = classe_0
    else:
        classe_minoria = classe_0
        classe_majoria = classe_1

    # Oversampling da classe minoritária
    classe_minoria_upsampled = resample(
        classe_minoria,
        replace=True,
        n_samples=len(classe_majoria),
        random_state=42
    )

    print(f"\n Após o oversampling:")
    print(f"Classe majoritária: {len(classe_majoria)} registros")
    print(f"Classe minoritária (após upsample): {len(classe_minoria_upsampled)} registros")

    # Verificação de duplicatas
    duplicatas = classe_minoria_upsampled.duplicated().sum()
    print(f"⚠️ Registros duplicados no oversampling: {duplicatas}")

    # Junta de novo, agora balanceado
    df_balanceado = pd.concat([classe_majoria, classe_minoria_upsampled], ignore_index=True)

    # Define colunas de features
    colunas_de_features = [col for col in df_balanceado.columns 
                           if col not in ["Classe", "IP de Origem", "IP de Origem Num"]]

    # Separação X (features) e y (rótulo)
    X = df_balanceado[colunas_de_features]
    y = df_balanceado["Classe"]

    # Dados extras (por exemplo, IPs)
    df_completo = df_balanceado[["IP de Origem", "IP de Origem Num"]]

    return X, y, df_completo

def int_to_ip(ip_int):
    try:
        return str(ipaddress.IPv4Address(int(ip_int)))
    except:
        return None

def treinar_e_avaliar_modelo(X, y, df_completo, int_to_ip, classificar_comportamento, caminho_modelo="D:\\RandomForest\\Newral\\modelo_treinado\\modelo_random_forest.joblib"):
    # Divisão dos dados
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.7, random_state=42)
    dados_extras = df_completo.loc[X_test.index]

    # Treinamento
    modelo = RandomForestClassifier(n_estimators=50, max_features=2, max_depth=6, random_state=42)
    modelo.fit(X_train, y_train)

    # Previsão
    y_pred = modelo.predict(X_test)

    # Resultados
    df_resultado = X_test.copy()
    df_resultado["Classe_Real"] = y_test.values
    df_resultado["Classe_Prevista"] = y_pred
    df_resultado[["IP de Origem", "IP de Origem Num"]] = dados_extras.values
    df_resultado["IP de Origem"] = df_resultado["IP de Origem"].apply(int_to_ip)
    df_resultado["Comportamento"] = df_resultado.apply(classificar_comportamento, axis=1)
    df_resultado.to_csv("D:\\RandomForest\\Newral\\saidas\\ips_maliciosos.csv", index=False, sep=";", encoding="utf-8")

    # Avaliação
    print(classification_report(y_test, y_pred))
    y_proba = modelo.predict_proba(X_test)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    roc_auc = auc(fpr, tpr)

    importances = modelo.feature_importances_
    indices = np.argsort(importances)[::-1]

    plt.figure(figsize=(10, 6))
    plt.title("Importância das Features")
    plt.bar(range(X.shape[1]), importances[indices], align='center')
    plt.xticks(range(X.shape[1]), X.columns[indices], rotation=90)
    plt.tight_layout()
    plt.grid()
    plt.show()

    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=modelo.classes_)
    disp.plot(cmap=plt.cm.Blues)
    plt.title("Matriz de Confusão")
    plt.grid(False)
    plt.show()

    plt.figure(figsize=(20,10))
    plot_tree(modelo.estimators_[1], feature_names=X.columns, class_names=["Classe 0", "Classe 1"], filled=True, rounded=True)
    plt.title("Árvore de decisão 1 da Random Forest")
    plt.show()

    plt.figure()
    plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {roc_auc:.2f})")
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel("FPR")
    plt.ylabel("TPR")
    plt.title("Curva ROC")
    plt.legend(loc="lower right")
    plt.grid()
    plt.show()

    # Salva o modelo treinado
    dump(modelo, caminho_modelo)
    print(f"Modelo salvo em: {caminho_modelo}")

    return modelo


def avaliar_novos_dados(caminho_modelo, dados_features, dados_completos, int_to_ip, classificar_comportamento):
    # Carrega o modelo treinado
    modelo = load(caminho_modelo)
    print(f"Modelo carregado de: {caminho_modelo}")

    # Previsão
    previsoes = modelo.predict(dados_features)
    probabilidades = modelo.predict_proba(dados_features)[:, 1]

    # Monta resultado
    df_resultado = dados_features.copy()
    df_resultado["Classe_Prevista"] = previsoes
    df_resultado["Probabilidade"] = probabilidades
    df_resultado[["IP de Origem", "IP de Origem Num"]] = dados_completos[["IP de Origem", "IP de Origem Num"]].values
    df_resultado["IP de Origem"] = df_resultado["IP de Origem"].apply(int_to_ip)
    df_resultado["Comportamento"] = df_resultado.apply(classificar_comportamento, axis=1)

    # Exporta resultado
    df_resultado.to_csv("D:\\RandomForest\\Newral\\saidas\\avaliacao_novos_dados.csv", index=False, sep=";", encoding="utf-8")
    print("Resultados salvos em: avaliacao_novos_dados.csv")

    return df_resultado

def preparar_dados_para_avaliacao(df_novos_dados):
    # Rotula todos os dados como não maliciosos (classe 0)
    df_novos_dados["Classe"] = 0

    # Define colunas de features (removendo colunas que não devem ser usadas)
    colunas_de_features = [col for col in df_novos_dados.columns 
                           if col not in ["Classe", "IP de Origem", "IP de Origem Num"]]

    # Separa features e rótulo (rótulo é opcional aqui, mas mantido para consistência)
    X = df_novos_dados[colunas_de_features]
    # y = df_novos_dados["Classe"]

    # Guarda colunas extras (IP etc)
    df_completo = df_novos_dados[["IP de Origem", "IP de Origem Num"]].copy()

    return X, y, df_completo

blacklist = carregar_blacklist()

classificados_features = processar_dados_completos(
    "database_treinamento\\logs\\logs_maliciosos11.csv",
    "D:\\RandomForest\\Newral\\database_treinamento\\Valores_Maliciosos.csv"
)

nao_classificados_features = processar_dados_completos(
    "database_treinamento\\logs\\logs_legitimos11.csv",
    "D:\\RandomForest\\Newral\\database_treinamento\\Valores_Nao_Avaliados.csv"
)
print(len(classificados_features))
print(len(nao_classificados_features))


X, y, df_completo = preparar_dados_para_treinamento(classificados_features, nao_classificados_features)

print("valor de x",X.head())             # Número de registros (linhas) em X
print(len(y))             # Número de rótulos
print(len(df_completo))

modelo = treinar_e_avaliar_modelo(X, y, df_completo, int_to_ip, classificar_comportamento)

modelo_carregado = joblib.load("D:\\RandomForest\\Newral\\modelo_treinado\\modelo_random_forest.joblib")

def avaliar_logs_suspeitos(arquivo_csv):
    st.title("Avaliação de Novos Logs Suspeitos")

    # Processa os dados
    try:
        novos_classificados = processar_dados_completos(
            arquivo_csv,
            "D:\\RandomForest\\Newral\\saidas\\avaliacao_nova_base_dados.csv"
        )
        st.success("[✔] Dados processados com sucesso.")
    except Exception as e:
        st.error(f"[✖] Erro ao processar os dados: {e}")
        return None

    # Prepara os dados
    try:
        X_novo, y_novo, df_novo_completo = preparar_dados_para_avaliacao(novos_classificados)
        print(X_novo.head())
        st.success("[✔] Dados preparados para avaliação.")
    except Exception as e:
        st.error(f"[✖] Erro ao preparar os dados: {e}")
        return None

   # Avaliação com modelo
    try:
        modelo = load("D:\\RandomForest\\Newral\\modelo_treinado\\modelo_random_forest.joblib")
        y_pred = modelo.predict(X_novo)
        y_proba = modelo.predict_proba(X_novo)[:, 1]

        df_resultado = X_novo.copy()
        df_resultado["Classe_Prevista"] = y_pred
        df_resultado[["IP de Origem", "IP de Origem Num"]] = df_novo_completo.values
        df_resultado["IP de Origem"] = df_resultado["IP de Origem"].apply(int_to_ip)
        df_resultado["Comportamento"] = df_resultado.apply(classificar_comportamento, axis=1)

        # Salva os resultados
        df_resultado.to_csv("D:\\RandomForest\\Newral\\saidas\\avaliacao_detalhada.csv", index=False, sep=";", encoding="utf-8")

        # Informações básicas dos dados classificados
        st.subheader("Resumo da Classificação")
        st.write(df_resultado["Classe_Prevista"].value_counts().rename({0: "Não Malicioso", 1: "Malicioso"}))

        # Tabela de resultados
        st.subheader("Tabela com Classificações")
        st.dataframe(df_resultado)

        st.success("[✔] Avaliação concluída com sucesso.")
        return df_resultado

    except Exception as e:
        st.error(f"[✖] Erro durante a avaliação: {e}")
        return None


resultado = avaliar_logs_suspeitos("D:\\RandomForest\\Newral\\database_para_teste\\logs_extremos_avaliacao.csv")
