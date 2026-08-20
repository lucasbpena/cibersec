import secrets
import os
import pathlib
import base64

def gerar_chave(tamanho: int) -> bytes:
	"""Gera uma chave criptograficamente segura com tamanho bytes."""
	if isinstance(tamanho, int) != True or tamanho <= 0:
		print("Forneça tamanho da chave como inteiro positivo!")
		return None

	return secrets.token_bytes(tamanho)


def xor_bytes(dados: bytes, chave: bytes) -> bytes:
	"""Calcula o XOR enre sequencias de mesmo comprimento"""

	if isinstance(dados, bytes) != True or isinstance(chave, bytes) != True or len(dados) != len(chave):
		print("Dados ou chave não são bytes ou tem tamanhos diferentes.")
		return None

	return bytes(a ^ b for a, b in zip(dados, chave))


def cifrar(mensagem: bytes, chave: bytes) -> bytes:
	"""Cifra mensagens usando OTP"""
	if isinstance(mensagem, bytes) != True or isinstance(chave, bytes) != True or len(mensagem) != len(chave):
		print("Mensagem ou chave não são bytes ou tem tamanhos diferentes.")
		return None

	return xor_bytes(mensagem, chave)

def decifrar(cifrado: bytes, chave: bytes) -> bytes:
	"""Decifra um texto cifrado usando OTP"""
	if isinstance(cifrado, bytes) != True or isinstance(chave, bytes) != True or len(cifrado) != len(chave):
			print("Mensagem cifrada ou chave não são bytes ou tem tamanhos diferentes.")
			return None
	
	return xor_bytes(cifrado, chave)
	


if __name__ == "__main__":
	# Ler arquivo de mensagens de teste
	with open("mensagens_teste.txt", 'r') as r:
		lines = r.readlines()
		# Limpar new line e whitespace de todas as linhas
		for n, l in enumerate(lines):
			lines[n] = l.rstrip()

	#print(lines)
	
	print("PARTE A")
	# Mensagem de teste ascii
	m_ascii = lines[2].encode("utf-8")
	k_ascii = gerar_chave(len(m_ascii))
	cifrado_ascii = cifrar(m_ascii, k_ascii)
	decifrado_ascii = decifrar(cifrado_ascii, k_ascii)
	print("\nMensagem teste ASCII")
	print(f"\tm: {m_ascii.hex()}\n\tk: {k_ascii.hex()}\n\tc: {cifrado_ascii.hex()}")
	print(f"Preservação da mensagem: {m_ascii == decifrado_ascii}")

	# Mensagem de teste UTF-8
	m_utf8 = lines[3].encode("utf-8")
	k_utf8 = gerar_chave(len(m_utf8))
	cifrado_utf8 = cifrar(m_utf8, k_utf8)
	decifrado_utf8 = decifrar(cifrado_utf8, k_utf8)
	print("\nMensagem teste UTF-8")
	print(f"\tm: {m_utf8.hex()}\n\tk: {k_utf8.hex()}\n\tc: {cifrado_utf8.hex()}")
	print(f"Preservação da mensagem: {m_utf8 == decifrado_utf8}")
	
	# Mensagem de teste binária
	m_bin = b"110111000011010"
	k_bin = gerar_chave(len(m_bin))
	cifrado_bin = cifrar(m_bin, k_bin)
	decifrado_bin = decifrar(cifrado_bin, k_bin)
	print("\nMensagem teste binária")
	print(f"\tm: {m_bin.hex()}\n\tk: {k_bin.hex()}\n\tc: {cifrado_bin.hex()}")
	print(f"Preservação da mensagem: {m_bin == decifrado_bin}")

	print("\nPARTE B")
	# Ler arquivo sintético fornecido
	nome_original = "registros_rede_sinteticos.csv"
	with open(nome_original, "rb") as r:
		fileContent = r.read()

	k_file = gerar_chave(len(fileContent))
	c_file = cifrar(fileContent, k_file)
	d_file = decifrar(c_file, k_file)

	# Salvar chave em arquivo separado (apenas durante o experimento)
	with open("chave_file.bin", "wb") as w:
		w.write(k_file)
	# Salvar somente os bytes cifrados
	with open("arquivo.cifrado", "wb") as w:
		w.write(c_file)
	# Salvar o resultado da decifração
	with open("arquivo.recuperado", "wb") as w:
		w.write(d_file)

	# Tamanho dos três arquivos
	tam_original = pathlib.Path(nome_original).stat().st_size
	tam_cifrado = pathlib.Path("arquivo.cifrado").stat().st_size
	tam_recuperado = pathlib.Path("arquivo.recuperado").stat().st_size
	print(f"\tTamanho original:   {tam_original} bytes")
	print(f"\tTamanho cifrado:    {tam_cifrado} bytes")
	print(f"\tTamanho recuperado: {tam_recuperado} bytes")

	# Comparação byte a byte entre original e recuperado
	iguais = fileContent == d_file
	print(f"Igualdade confirmada (original == recuperado): {iguais}")

	# Remover a cópia local da chave do diretório de entrega
	os.remove("chave_file.bin")
	print("Chave removida do diretório de entrega.")

	print("\nPARTE C")
	# Obter mensagens teste do material
	m_a = lines[4].encode("utf-8")
	m_b = lines[5].encode("utf-8")

	# gerar chave única para ambas mensagens
	k_reuso = gerar_chave(len(m_a))
	c_a = cifrar(m_a, k_reuso)
	c_b = cifrar(m_b, k_reuso)  

	# Veriricar XOR
	xor_cifrados = xor_bytes(c_a, c_b)
	xor_mensagens = xor_bytes(m_a, m_b)
	print(f"\tm1: {m_a.hex()}\n\tm2: {m_b.hex()}")
	print(f"\tc1: {c_a.hex()}\n\tc2: {c_b.hex()}")
	print(f"\tc1 XOR c2: {xor_cifrados.hex()}")
	print(f"\tm1 XOR m2: {xor_mensagens.hex()}")
	print(f"Vazamento confirmado (c1 XOR c2 == m1 XOR m2): {xor_cifrados == xor_mensagens}")

	# Com o texto claro de uma mensagem conhecido (known-plaintext), a outra é
	# recuperada sem nunca conhecer a chave k_reuso
	m_b_recuperada = xor_bytes(xor_cifrados, m_a)
	print(f"\tm2 recuperada via ataque de reuso: {m_b_recuperada}")
	print(f"m2 recuperada == m2 original: {m_b_recuperada == m_b}")

