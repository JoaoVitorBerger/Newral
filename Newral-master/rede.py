import pandas as pd
import re
import requests
import numpy as np
import random
from sklearn.feature_extraction.text import HashingVectorizer
from tensorflow import keras
from tensorflow.keras import layers, regularizers
import tensorflow as tf
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
from keras.callbacks import ReduceLROnPlateau, EarlyStopping

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
            with open(BLACKLIST_FILE, 'w') as file:
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
def process_csv(file_path, limit=64):
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
file_path = 'D:\\Log_Viewer.csv'  # Substitua pelo caminho do seu arquivo CSV
csv_ips = process_csv(file_path)

# Balanceamento dos dados (seleciona o mesmo número de IPs da blacklist e do CSV)
min_amostras = min(len(blacklist_ips), len(csv_ips))
blacklist_ips_balanceada = list(blacklist_ips)[:min_amostras]
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
    layers.Dense(16, activation='relu', kernel_regularizer=regularizers.l2(0.01), input_shape=(16,)),  # Aumentado para 32 neurônios
    layers.Dropout(0.3),
    layers.Dense(8, activation='relu', kernel_regularizer=regularizers.l2(0.01)),  # Adicionada uma camada oculta extra
    layers.Dense(1, activation='sigmoid')
])

learning_rate = 0.007  # Teste valores entre 0.0001 e 0.001
optimizer = keras.optimizers.Adam(learning_rate=learning_rate)
model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=['accuracy'])

# Callbacks
reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=1e-6)
early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)

# Treinar o modelo
history = model.fit(X, y, epochs=100, batch_size=16, validation_split=0.2, callbacks=[reduce_lr, early_stopping])

# Plotar a curva de aprendizado
def plot_learning_curve(history):
    plt.figure(figsize=(12, 6))

    # Curva de perda
    plt.subplot(1, 2, 1)
    plt.plot(history.history['loss'], label='Perda de Treinamento')
    plt.plot(history.history['val_loss'], label='Perda de Validação')
    plt.title('Curva de Perda')
    plt.xlabel('Épocas')
    plt.ylabel('Perda')
    plt.legend()

    # Curva de acurácia
    plt.subplot(1, 2, 2)
    plt.plot(history.history['accuracy'], label='Acurácia de Treinamento')
    plt.plot(history.history['val_accuracy'], label='Acurácia de Validação')
    plt.title('Curva de Acurácia')
    plt.xlabel('Épocas')
    plt.ylabel('Acurácia')
    plt.legend()

    plt.tight_layout()
    plt.show()

# Plotar a curva de aprendizado
plot_learning_curve(history)

# Testar com um IP novo
predicao = model.predict(csv_vetorizado)
limiar = 0.8  # Definir um limiar de 80%

print("\n🚨 IPs considerados maliciosos:")
for ip, prob in zip(csv_ips_balanceado, predicao.flatten()):
    if prob > limiar:
        # Calcula a porcentagem de ser malicioso
        porcentagem = prob * 100
        print(f"⚠️ {ip} - Probabilidade: {porcentagem:.2f}%")
