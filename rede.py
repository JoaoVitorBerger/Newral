import pandas as pd
import re
import requests
import numpy as np
import random
from sklearn.feature_extraction.text import HashingVectorizer
from tensorflow import keras
from tensorflow.keras import layers
from bs4 import BeautifulSoup

# URL da Blacklist e caminho para salvar localmente
BLACKLIST_URL = "https://github.com/dolutech/blacklist-dolutech/blob/main/Black-list-semanal-dolutech.txt"
BLACKLIST_FILE = "Black-list-semanal-dolutech.txt"

# Função para baixar a blacklist
def baixar_blacklist():
    response = requests.get(BLACKLIST_URL)
    if response.status_code == 200:
        # Usar BeautifulSoup para processar o HTML da página
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Encontrar todos os <span> com a classe "pl-c1" (onde estão os IPs)
        ips = soup.find_all('span', class_='pl-c1')

        # Extrair os IPs dos elementos encontrados
        ips_extraidos = [ip.get_text() for ip in ips[:100]]
        
        if ips_extraidos:
            # Salvar os IPs em um arquivo
            with open('Black-list-semanal-dolutech.txt', 'w') as file:
                for ip in ips_extraidos:
                    file.write(ip + "\n")
            
            print(f"{len(ips_extraidos)} IPs encontrados e salvos no arquivo.")
            return ips_extraidos
        else:
            print("Nenhum IP encontrado na blacklist.")
            return []
    else:
        print("Erro ao acessar a URL.")
        return []

# Função para carregar a blacklist
def carregar_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print("⚠️ Blacklist não encontrada. Baixando agora...")
        baixar_blacklist()
        return carregar_blacklist()

# Função para extrair os IPs do CSV
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

# Carregar blacklist e CSV
blacklist_ips = carregar_blacklist()
file_path = 'D:\\Database\\Log_Viewer.csv'
csv_ips = process_csv(file_path)


# Balanceamento dos dados (seleciona o mesmo número de IPs da blacklist e do CSV)
min_amostras = min(len(blacklist_ips), len(csv_ips))
blacklist_ips_balanceada = random.sample(list(blacklist_ips), min_amostras)
csv_ips_balanceado = csv_ips[:min_amostras]

print("Blacklists balanceados: ", blacklist_ips_balanceada)
print("CSV balanceado: ", csv_ips_balanceado)

# Criar vetorizador
tokenizer = HashingVectorizer(n_features=16, alternate_sign=False)

def vetorizar_ips(ip_list):
    return np.array(tokenizer.transform(ip_list).toarray())

# Vetorizar dados balanceados
blacklist_vetorizada = vetorizar_ips(blacklist_ips_balanceada)
csv_vetorizado = vetorizar_ips(csv_ips_balanceado)

# Criar rótulos balanceados
y_blacklist = np.ones(len(blacklist_vetorizada))  # 1 para IPs maliciosos
y_csv = np.zeros(len(csv_vetorizado))  # 0 para IPs legítimos

# Dados finais para treinamento
X = np.vstack((blacklist_vetorizada, csv_vetorizado))
y = np.concatenate((y_blacklist, y_csv))

# Criar a rede neural
model = keras.Sequential([
     layers.Dense(32, activation='relu', input_shape=(16,)),
     layers.Dense(16, activation='relu'),
     layers.Dense(1, activation='sigmoid')
])

# Compilar o modelo
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Treinar o modelo
model.fit(X, y, epochs=100, batch_size=16, validation_split=0.2)

# Testar com um IP novo
predicao = model.predict(csv_vetorizado)
limiar = 0.8  # Definir um limiar de 80%

print("\n🚨 IPs considerados maliciosos:")
for ip, prob in zip(csv_ips_balanceado, predicao.flatten()):
    if prob > limiar:
        print(f"⚠️ {ip} - Probabilidade: {prob:.2f}")