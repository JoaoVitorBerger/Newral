HashingVectorizer da biblioteca  sklearn.feature_extraction.text

Utilizado para transformar textos em vetores númericos, já que a rede não consegue trabalhar com strings.

tokenizer = HashingVectorizer(n_features=16 alternate_sign=False)

No caso aqui estamos criando um conversor de strings e valores vetoriais, em que cada valor será transformado em 16 valores diferentes. Exemplo o ip 172.22.88.41, pode ser convertido em 16 valores vetoriais com tamanhos variados.


def vetorizar_ips(ip_list):
    return np.array(tokenizer.transform(ip_list).toarray())

    Aqui estamos utilizando a biblioteca do Python, chamada Numpy para converter o valor que o vetorizador criou em um array tridimensional, chamado de tensor, essa biblioteca ajuda a trabalhar com esse tipo de dimensão de array.

# # Vetorizar dados
blacklist_vetorizada = vetorizar_ips(list(blacklist_ips))
csv_vetorizado = vetorizar_ips(csv_ips)

    Aqui estamos criando tensores para ambos os dados, tanto as blacklists como os dados do csv

# # Criar rótulos
 y_blacklist = np.ones(len(blacklist_vetorizada))
 y_csv = np.zeros(len(csv_vetorizado))

    Aqui estamos criando rótulos para as nossas respectivas listas, em que os valores ones serão classificados como maliciosos e os valores zeros, como ainda não definidos ou não classificados.

# # Dados finais para treinamento
 X = np.vstack((blacklist_vetorizada, csv_vetorizado))
 y = np.concatenate((y_blacklist, y_csv))

    Aqui estamos empilhando todos os valores das blacklists e do csv_vetorizado para criar um único array, realizamos o mesmo processo para a classificação dos IPs. A rede neural necessita de uma entrada uniforme para seu treinamento, mesmo as informações entre seguros e inseguros, a rede consegue se lembrar, por meio da etiqueta daquele ip, se ele é malicioso ou ainda não definido

# # Criar a rede neural
 model = keras.Sequential([
     layers.Dense(32, activation='relu', input_shape=(16,)),
     layers.Dense(16, activation='relu'),
     layers.Dense(1, activation='sigmoid')
 ])

    Aqui estamos criando a rede e suas camadas, vou explicar um pouco melhor. Na linha layers.Dense(32, activation='relu', input_shape=(16,)),
     Nesta etapa ocorre uma multiplicação de matriz e adição de vetor, chamada de multiplicação de pesos. Ela constitui de multiplicar os valores de entrada, no caso nosso IP vetorizado, por matrizes de pesos com valores aleatórios e quando feita a multiplicação desses valores, o resultado de cada camada de neurônio é somado com um valor do vetor de viés. Isso é feito para que a rede não enfrente uma linearidade quanto ao fornecimento de seus resultado. Isso significa que com a adição de um viés para a tratativa dos dados, os resultados e processamento serão distribuidos por todos os neurônios evitando que alguns neurônios fiquem inutilizados.

     Após feito isso, os valores resultantes da soma do valor do neurônio com o vetor de viés passam por uma função ReLu (Rectified Linear Unit) que é uma função de ativação que avalia entre um valor e 0. Caso o valor seja negativo, o resultado gerado é 0, essa função retira todos os valores negativos da rede retornando um array, apenas com valores positivos. Ao chegar na ultima camada, iremos aplicar uma função sigmoidal, que avalia se um valor está entre 0 e 1, quando os valores são dispostos pela rede para essa ultima camada, o neurônio deve avaliar se os resultados gerados estão próximos dos parâmetros desejados
     
     Z = ReLU(Z) = [max(0,0.8), max(0,0.3), max(0,0.15), max(0,1.6)]

     Aplicando o sigmoide para a categorização entre 0 e 1

     Z^1=[1/1+e^-0.8, 1/1+e^-0.3, 1/1+e^-0.15, 1/1+e^-1.6]

     Os valores que devem ser esperados são
     Y = [0.6899, 0.5744, 0.5374, 0.8320]

    Após estes passo, é utilizado um thresold para determinar a classe 0 ou 1

    Após esta classificação a rede executa uma função de perda chamada Binary Cross-Entropy que analisa o quão distante a rede ficou do valor esperado em cada neurônio

    Sua fórmula é definida como L = -(Y.LOG(Y^) + (1-Y) .LOG(1-Y^))
    Onde:
        L é a perda
        Y é o valor real(rótulo)
        Y^ é a previsão da rede ou a saída da rede.

    Seguindo os exemplos anteriores ficaria dessa maneira

    Para 0.6899 e y = 1

    L1 = -(1.log(0.6899) + (1-1).log(1-0.6899))
    L1 = -log(0.6899) =/ 0.7599

    esse processo segue para todos os valores retornados pela função sigmoide.

    Após a realização dessa etapa entramos na camada de ajuste dos pesos da rede utilizando o Backpropagation que seria a taxa de variação da função de perda L(loss) em relação aos pesos W(weigth), ou indicativo de como os pesos devem ser ajustados para aproximar o valor de classificação do valor desejado.Para cada valor que foi gerado anteriormente, utilizaremos a seguinte função
    L/w = (Y^ - Y) . X

    Onde:
        Y^ é a previsão da rede(resultado da sigmoide)
        Y é o valor real
        x é o valor de entrada correspondente ao peso w

    No caso para os valores de exemplo
    y^ = 0.7, y1=1, x1=0.8

    gradiente de perda
    --------------  = (0.7 - 1) . 0.8 = (-0.3) . 0.8 = -0.24
    pesos da rede

    Após a realização dos cálculos, realizamos a atualização do gradiente

    w= w - n .(L/W)

    Onde n é a taxa de aprendizado e (L/W) é a taxa de variação já calculada.