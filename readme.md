# Newral
Projeto Rede Neural

Bibliotecas utilizadas no projeto

### skelarn - biblioteca relacionada ao aprendizado de máquina em python, nela estou utilizando o resample para definir um balanço entre os dados maliciosos e não classificados, essa ação evita que o modelo entre em overfitting, ou seja, memorize os dados de treino e não consiga generalizar bem para dados não classificados.

### ensemble - responsável por disponibilizar os modelos de classificação e detecção de anômalias.

### model_selection - utilizado para dividar os valores entre treino e teste.

### metrics - utilizado para classificar a precisão e o erro do modelo, adicionei a ROC CURVE, responsável por mostrar a taxa dos verdadeiros positivos e a AUC área under de curve, no caso ele cria um parâmetro de avaliação do modelo que varia entre 0 e 1.

### matplotlib - Utilizada para plotar os valores dentro da curva ROC, trazendo resultados sobre as predições do modelo.

### ipadress - utilizado para converter valores ips que estão em formato string em valores numéricos.

### BeautifulSoup - utilizado para transformar o html em um arquivo de dados, facilitando a extração de valores desejados.

### requests - utilizado para realizar requisições https.

### pandas - utilizado para o manuseio dos dados dispostos nas planilha, afim de organizar os valores de entrada.

### numpy - utilizado para a manipulação de matrizes multidimensionais.

Execute utilizando o comando CTRL + "' e instale as seguintes bibliotecas

## pip install pandas requests beautifulsoup4 numpy scikit-learn matplotlib

1. Nos arquivos logs_maliciosos.csv e Log_Viewer, estão os dados que serão processados pela rede, de início temos um arquivo CSV sem formatação e extruturação de colunas. Na função  # formatar_log_csv separamos os dados por features, ou características que utilizaremos para a predição. Os dois arquivos passam por essa função gerando dois arquivos, Malicioso.csv e Nao_avaliado.csv Esses são nosso dados formatados e prontos para as próximas etapas.

2. Na função preparar_dados, temos a seleção das features mais importantes que desejamos utilizar, no caso para os ataques de DDos e Port Scan, estou selecionando as que mais levantam suspeitas quanto a essas atividades.

3. Os dados seguem para a função extrair_features_adicionais, essas features irão auxiliar na criação de um comportamento para cada IP, como um rótulo de atividades, buscando por requisições anormais para vários endereços, quantidades de solicitações por segundo e diversidade de endereços de destino. Ao identificarmos todas as características que aquele dado trouxe consigo para essa função, criamos um comportamento para o dado e posteriormente utilizaremos um rótulo para informar ao algoritmo, que aquele padrão de comportamento, deve ser considerados como malicioso.

4. Feito isso, podemos rotular os dados criando um index chamado "Classe" que recebe 1 para valores maliciosos e 0 para não classificados.

5. Após a rotulagem dos dados, temos o resample, como citado anteriormente, ele realiza o balanço dos dados para que não ocorra overfitting trazendo uma mesma quantidade de dados de entrada para os dois casos.

6. Feito isso, os dados são agrupados em uma pilha e embaralhados.

7. Inserimos os valores no modelo de classificação e treinamos o modelo com 20% dos dados fornecidos.

8. Feito isso copiamos os valores que foram gerados no teste e verificamos o valor do rótulo, valor pré-processamento com o pós processamento.

9. Separamos os registros maliciosos e chamamos a função classificar comportamento, ela será responsável por avaliar em qual predição o valor caiu no índice Classe_Prevista, seja 1 para Port Scan, 2 para DDos e 0 para nenhuma anomalia.

10. Depois avaliamos o desempenho do modelo e plotamos a curva ROC, quanto mais o valor se aproximar de 1, maior é a precisão do algoritmo, meu útlimo registro foi de 98% de precisão. Todos os valores identificados como malicioso, são salvos em um txt chamado ips_maliciosos.txt