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

    Aqui estamos empilhando todos os valores das blacklists e do csv_vetorizado para criar um único array, realizamos o mesmo processo para a classificação dos IPs. A rede neural necessita de uma entradas uniforme para seu treinamento, mesmo as informações entre seguros e inseguros, a rede consegue se lembrar, por meio da etiqueta daquele ip, se ele é malicioso ou ainda não definido

# # Criar a rede neural
 model = keras.Sequential([
     layers.Dense(32, activation='relu', input_shape=(16,)),
     layers.Dense(16, activation='relu'),
     layers.Dense(1, activation='sigmoid')
 ])

    Aqui estamos criando a rede e suas camadas, vou explicar um pouco melhor. Na linha layers.Dense(32, activation='relu', input_shape=(16,)),
    estamos criando uma camada de 32 neurônios, esses neurônios processam a informação, no caso multiplicam seus respectivos pesos pelo pelo valor de entrada fornecido. Ele espera no parâmetro input_shape um valor de aproximadamente 16 digitos, ou seja, a string ou valor de ip deve conter um tamanho de 16 digitos.
