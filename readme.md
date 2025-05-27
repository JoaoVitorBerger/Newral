# Detecção de Tráfego Malicioso com Random Forest

Este projeto utiliza técnicas de machine learning para identificar tráfego malicioso em redes de computadores. O objetivo é classificar conexões como legítimas ou maliciosas com base em logs de firewall, usando o algoritmo Random Forest. O script `rede.py` é responsável por grande parte do processamento, validação e análise dos dados.

## 📚 Bibliotecas utilizadas

- **pandas**: Utilizada para carregar e manipular os arquivos CSV contendo os logs de tráfego. Permite operações eficientes em tabelas de dados.
- **numpy**: Usada para manipulação de arrays e vetores numéricos, além de conversões de data e hora para timestamps UNIX.
- **requests**: Responsável por baixar a blacklist semanal de IPs maliciosos diretamente de um repositório público (Dolutech).
- **beautifulsoup4 (bs4)**: Usada em conjunto com `requests` para extrair IPs do conteúdo HTML da blacklist.
- **ipaddress**: Converte endereços IP de string para inteiros, facilitando a entrada do modelo.
- **scikit-learn (sklearn)**:
  - `ensemble.RandomForestClassifier`: Algoritmo principal para treinar o modelo de classificação.
  - `model_selection.train_test_split`: Divide o conjunto de dados em treino e teste.
  - `metrics`: Fornece métricas como matriz de confusão, curva ROC e relatório de classificação.
  - `tree.plot_tree`: Visualização da estrutura interna das árvores da floresta.
- **matplotlib.pyplot**: Geração de gráficos como curva ROC e árvore de decisão.
- **seaborn**: Criação de gráficos mais refinados e mapas de calor (heatmaps).
- **joblib**: Utilizada para salvar e carregar o modelo Random Forest treinado.
- **streamlit**: Biblioteca voltada para construção de dashboards e interfaces web simples (ainda em fase inicial no projeto).

## ⚙️ Funcionamento do Script `rede.py`

### 1. Carregamento e Tratamento de Dados

- O script espera um arquivo CSV contendo logs de firewall.
- A função `preparar_dados()` trata os dados brutos, transformando colunas como IPs, portas e protocolo em formatos numéricos.
- As colunas de tempo são convertidas para timestamp UNIX, e extraídas variáveis como hora, minuto e segundo.

### 2. Download e Leitura de Blacklist

- O sistema baixa automaticamente uma lista de IPs maliciosos do repositório da Dolutech.
- A lista é armazenada localmente e reutilizada caso já esteja presente.
- Os IPs de origem e destino nos logs são comparados com a blacklist para identificação de tráfego suspeito.

### 3. Conversões e Feature Engineering

- Protocolo (TCP, UDP, ICMP) é mapeado para um número (6, 17, 1).
- IPs são convertidos para inteiros para facilitar o uso em modelos de ML.

### 4. Treinamento e Avaliação (em outras partes do projeto)

- Os dados tratados podem ser passados para um classificador Random Forest, como visto nos outros scripts do projeto.
- O modelo gera relatórios de avaliação e pode ser exportado com `joblib`.

### 5. Saídas Geradas

- `ips_maliciosos.csv`: lista de IPs classificados como suspeitos.
- `avaliacao_detalhada.csv`: desempenho do modelo em um conjunto de teste.
- `modelo_random_forest.joblib`: arquivo com o modelo treinado pronto para ser reutilizado.

---

## 💡 Considerações Finais

O `rede.py` é um componente essencial do projeto Newral, sendo o ponto de integração entre blacklist, logs reais e aprendizado de máquina. A modularidade do código permite sua adaptação para outras fontes de dados e modelos de classificação.

Para saber mais sobre o funcionamento dos outros scripts e a estrutura completa do projeto, consulte também os arquivos:
- `gerador_modelo_treino_legitimo.py`
- `script_teste.py`
- Diretórios `database_treinamento/`, `saidas/` e `modelo_treinado/`

---


