import pandas as pd
import re
import requests
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from tensorflow import keras
from tensorflow.keras import layers

# URL da Blacklist e caminho para salvar localmente
BLACKLIST_URL = "https://github.com/dolutech/blacklist-dolutech/blob/main/Black-list-semanal-dolutech.txt"
BLACKLIST_FILE = "Black-list-semanal-dolutech.txt"


# Função para baixar a blacklist
################# 4 Parte do código ###################
def baixar_blacklist():
    response = requests.get(BLACKLIST_URL)
    if response.status_code == 200:
        with open(BLACKLIST_FILE, "w") as f:
            f.write(response.text)
        print("✅ Blacklist baixada com sucesso!")
    else:
        print("❌ Erro ao baixar a blacklist.")
########################################################

# Função para carregar a blacklist
################# 2 Parte do código ###################
def carregar_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print("⚠️ Blacklist não encontrada. Baixando agora...")
        baixar_blacklist()
        return carregar_blacklist()
########################################################

# Função para extrair os IPs do CSV
################# 3 Parte do código ###################
def process_csv(file_path, limit=10):
    df = pd.read_csv(file_path, header=None, delimiter=",", engine="python", on_bad_lines="skip")
    ips = []
    for _, row in df.iterrows():
        if row[2] == "Allowed":
            ip_destino = row[11]
            if isinstance(ip_destino, str) and re.match(r'\d+\.\d+\.\d+\.\d+', ip_destino):
                ips.append(ip_destino)
                if len(ips) >= limit:
                    return ips
    return ips
########################################################


# Carregar blacklist e CSV
######################## 1 Parte do código ##################
blacklist_ips = carregar_blacklist()
file_path = 'D:\\Database\\Log_Viewer.csv'
csv_ips = process_csv(file_path)

##############################################

# # Criar vetorizador
tokenizer = HashingVectorizer(n_features=16, alternate_sign=False)
print(tokenizer)
def vetorizar_ips(ip_list):
    return np.array(tokenizer.transform(ip_list).toarray())

# # Vetorizar dados
blacklist_vetorizada = vetorizar_ips(list(blacklist_ips))
csv_vetorizado = vetorizar_ips(csv_ips)

# # Criar rótulos
# y_blacklist = np.ones(len(blacklist_vetorizada))
# y_csv = np.zeros(len(csv_vetorizado))

# # Dados finais para treinamento
# X = np.vstack((blacklist_vetorizada, csv_vetorizado))
# print(X)
# y = np.concatenate((y_blacklist, y_csv))
# print(y)

# # Criar a rede neural
# model = keras.Sequential([
#     layers.Dense(32, activation='relu', input_shape=(16,)),
#     layers.Dense(16, activation='relu'),
#     layers.Dense(1, activation='sigmoid')
# ])

# # Compilar o modelo
# model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# # Treinar o modelo
# model.fit(X, y, epochs=10, batch_size=16, validation_split=0.2)

# # Testar com um IP novo
# print(csv_vetorizado)
# predicao = model.predict(csv_vetorizado)
# print(f'🧐 Probabilidade de ser malicioso: {predicao[0][0]:.4f}')
