HashingVectorizer da biblioteca  sklearn.feature_extraction.text
Utilizado para transformar textos em vetores númericos, já que a rede não consegue trabalhar com strings

tokenizer = HashingVectorizer(n_features=16 alternate_sign=False)
No caso aqui estamos criando um conversor de strings e valores vetoriais, em que cada valor será transformado em 16 valores diferentes. Exemplo o ip 172.22.88.41, pode ser convertido em 16 valores vetoriais com tamanhos variados

print(tokenizer)
def vetorizar_ips(ip_list):
    return np.array(tokenizer.transform(ip_list).toarray())
    Aqui estamos utilizando a biblioteca do Python, chamada Numpy para converter o valor que o vetorizador criou em um array tridimensional, chamado de tensor, essa biblioteca ajuda a trabalhar com esse tipo de dimensão de array.

# # Vetorizar dados
blacklist_vetorizada = vetorizar_ips(list(blacklist_ips))