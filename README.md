# Newral - Projeto Rede Neural

Este é um projeto de rede neural para detecção de anomalias, com foco em ataques como **DDos** e **Port Scan**. Abaixo estão as bibliotecas utilizadas e um resumo do fluxo de processamento dos dados.

## Bibliotecas utilizadas

- **sklearn**: Biblioteca relacionada ao aprendizado de máquina em Python. Estamos utilizando o `resample` para definir um balanço entre dados maliciosos e não classificados, evitando o overfitting (memorização excessiva dos dados de treino).
- **ensemble**: Disponibiliza modelos de classificação e detecção de anomalias.
- **model_selection**: Utilizada para dividir os dados entre treino e teste.
- **metrics**: Usada para avaliar a precisão e o erro do modelo. A `ROC CURVE` foi adicionada para mostrar a taxa de verdadeiros positivos e a AUC (Área Sob a Curva), que é um parâmetro de avaliação que varia de 0 a 1.
- **matplotlib**: Utilizada para plotar a curva ROC e visualizar os resultados das predições do modelo.
- **ipaddress**: Converte endereços IP em formato string para valores numéricos.
- **BeautifulSoup**: Facilita a extração de dados de arquivos HTML.
- **requests**: Realiza requisições HTTP.
- **pandas**: Manipula os dados contidos em planilhas, organizando os valores de entrada.
- **numpy**: Manipula matrizes multidimensionais.

## Instalação

Para executar o projeto, instale as bibliotecas necessárias utilizando o seguinte comando:

```bash
pip install pandas requests beautifulsoup4 numpy scikit-learn matplotlib
Fluxo do Projeto
Processamento Inicial de Dados

Os arquivos logs_maliciosos.csv e Log_Viewer contêm os dados a serem processados. Inicialmente, temos um arquivo CSV sem formatação. A função formatar_log_csv separa os dados por features (ou características) utilizadas para predição. Isso gera dois arquivos: Malicioso.csv e Nao_avaliado.csv, que contêm os dados formatados.

Seleção de Features

A função preparar_dados seleciona as features mais importantes para a detecção de ataques, como DDos e Port Scan. Estamos focando nas features que mais indicam esses tipos de atividades.

Extração de Features Adicionais

A função extrair_features_adicionais adiciona mais características aos dados, como:

Rótulos de atividades de IPs.

Análise de requisições anormais, como múltiplas requisições para diferentes endereços em um curto período.

Com essas novas características, podemos criar um padrão de comportamento para cada IP e identificar se ele é malicioso.

Rotulagem dos Dados

Após a extração das features, os dados são rotulados com a coluna Classe:

1 para valores maliciosos (como DDos ou Port Scan).

0 para dados não classificados.

Balanceamento de Dados

O resample é utilizado para balancear os dados, garantindo que o número de entradas seja igual para ambos os casos (malicioso e não classificado), prevenindo o overfitting.

Embaralhamento e Preparação para o Modelo

Após o balanceamento, os dados são agrupados e embaralhados para garantir uma distribuição aleatória e evitar viés.

Treinamento do Modelo

Os dados são inseridos no modelo de classificação, e o treinamento é feito utilizando 20% dos dados para teste.

Pré-processamento e Pós-processamento

Após o treinamento, os dados são testados e os valores de rótulos são comparados entre o pré-processamento e o pós-processamento para verificar a precisão do modelo.

Classificação do Comportamento

Os registros maliciosos são classificados pela função classificar_comportamento, que avalia em qual predição os dados caem:

1 para Port Scan.

2 para DDos.

0 para nenhuma anomalia.

Avaliação de Desempenho

O desempenho do modelo é avaliado e a curva ROC é plotada. Quanto mais a curva se aproximar de 1, maior será a precisão do modelo. O último registro foi de 98% de precisão.

Armazenamento dos Resultados

Todos os valores identificados como maliciosos são salvos em um arquivo chamado ips_maliciosos.txt.

Considerações Finais
Este projeto utiliza técnicas de aprendizado de máquina e redes neurais para detectar comportamentos anômalos em redes, como ataques de DDos e Port Scan. Com uma precisão de 98%, o modelo tem mostrado resultados promissores para identificar e classificar esses ataques de forma eficaz.

