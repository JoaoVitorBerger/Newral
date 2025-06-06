# 🚀 Predição de Tráfego Malicioso com Random Forest

**Resumo:** Este projeto tem como objetivo detectar comportamentos maliciosos em registros de tráfego de firewall por meio de aprendizado de máquina. Utilizando o algoritmo Random Forest, o sistema classifica sessões de rede como maliciosas ou não, com base em logs simulados que incluem ataques como DDoS e Port Scan.

---

## 🎯 Objetivo

O projeto busca aplicar os conceitos de aprendizado de máquina e segurança da informação para automatizar a detecção de tráfego suspeito em redes computacionais. A solução se baseia na análise de logs gerados artificialmente e tratados por um pipeline completo de extração de características. A proposta está diretamente relacionada aos temas de Inteligência Artificial, Redes de Computadores e Segurança, explorando também a aplicação prática de classificadores supervisionados.

---

## 👨‍💻 Tecnologias Utilizadas

- Python 3.12
- Streamlit (Interface)
- Pandas / Scikit-learn (Machine Learning)
- IPAddress / Datetime (Manipulação de logs)
- Matplotlib (Visualização)
- Joblib (Persistência de modelo)

---

## 🗂️ Estrutura do Projeto

```
📦 RANDOMFOREST
├── 📁 .venv
├── 📁 Anotacoes
│   ├── Anotacoes.txt
│   └── Relatorio.txt
├── 📁 Arvores
│   ├── Arvore1.png
│   ├── Arvore2.txt
│   └── Porque_devemos_definir_uma_profundidade.png
├── 📁 database_para_teste
│   ├── Classificados.csv
│   ├── logs_simulados_avaliacao.csv
│   ├── logs_simulados.csv
│   ├── script_teste.py
│   └── script_testev2.py
├── 📁 logs
│   ├── Block-list-semanal-dolutech.txt
│   ├── Logs_View.csv
│   ├── OrganizandoDatasetMaliciosos.csv
│   └── OrganizandoDatasetLegitimos.csv
├── 📁 gerar_logs_treinamento
│   ├── gerar_treino_legitimos.py
│   └── gerar_treino_maliciosos.py
├── 📁 modelo_treinado
│   └── modelo_random_forest.joblib
├── 📁 saidas
│   └── informacoes_sobre_features_treinamento.joblib
├── .gitignore
├── README.md
└── requirements.txt
```

---

## ⚙️ Como Executar

### ✅ Rodando Localmente

1. Clone o repositório:

```bash
git clone https://github.com/seu-usuario/random-forest-firewall.git
cd random-forest-firewall
```

2. Crie e ative o ambiente virtual:

```bash
python -m venv venv
venv\Scripts\activate  # Windows
# ou source venv/bin/activate no Linux/macOS
```

3. Instale as dependências:

```bash
pip install -r requirements.txt
```

4. Execute a aplicação no Streamlit:

```bash
streamlit run rede.py
```

---

## 📸 Demonstrações

- ✅ Tela de Avaliação de Novos Logs
- 📊 Classificação entre tráfego malicioso e não malicioso
- 📁 Geração de logs sintéticos para treinamento
- 🧠 Pipeline com Random Forest em ação

---

## 👥 Equipe

| Nome | GitHub |
|------|--------|
| João Vitor Berger | [@joaovitor][(https://github.com/JoaoVitorBerger) |
| Gustavo Gomes Guimarães | [@gustavoguimaraes](https://github.com/gustavoguimaraes) |
| Gabriel Souza Gava | [@gabrielgava](https://github.com/gabrielgava) |

---

## 🧠 Disciplinas Envolvidas

- Segurança da Informação
- Inteligência Artificial
- Aprendizado de Máquina
- Estrutura de Dados
- Redes de Computadores

---

## 🏫 Informações Acadêmicas

- Universidade: **Universidade Braz Cubas**
- Curso: **Ciência da Computação**
- Semestre: **7º Semestre**
- Período: **Noite**
- Professora orientadora: **Dra. Andréa Ono Sakai**
- Evento: **Mostra de Tecnologia — 1º Semestre de 2025**
- Local: **Laboratório 12**
- Datas: **05 e 06 de junho de 2025**

---

## 📄 Licença

MIT License — sinta-se à vontade para utilizar, estudar e adaptar este projeto para fins educacionais.
