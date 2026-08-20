# Relatório — Laboratório L1: One-Time Pad de Shannon

**Disciplina:** Cibersegurança — 2026.2
**Autor:** lucas.bernardesp205@gmail.com
**Data:** 18/08/2026
**Implementação:** `otp.py`

## 1. Objetivo

Implementar e validar experimentalmente as propriedades da cifra de Vernam
(One-Time Pad — OTP) sobre dados sintéticos: (A) cifração/decifração de
mensagens de texto em diferentes codificações e de uma mensagem binária;
(B) cifração de um arquivo completo, com verificação de integridade
byte a byte e manuseio correto da chave; (C) demonstração controlada da
quebra de sigilo causada pelo reuso de chave (ataque de "two-time pad").

## 2. Implementação

A cifra foi implementada como um XOR byte a byte entre a mensagem e uma
chave de mesmo comprimento, gerada com `secrets.token_bytes` (gerador
criptograficamente seguro):

- `gerar_chave(tamanho)` — gera `tamanho` bytes aleatórios.
- `xor_bytes(dados, chave)` — calcula o XOR entre duas sequências de bytes
  de mesmo comprimento, com validação de tipo e tamanho.
- `cifrar(mensagem, chave)` / `decifrar(cifrado, chave)` — invólucros
  semânticos sobre `xor_bytes`; como o OTP é uma involução (`X ⊕ K ⊕ K = X`),
  cifrar e decifrar são a mesma operação.

Todas as leituras/escritas de arquivo binário usam os modos `"rb"`/`"wb"`,
conforme recomendado no `README.txt` do pacote.

## 3. Parte A — Mensagens de teste (ASCII, UTF-8 e binário)

Cada mensagem foi codificada em bytes, cifrada com uma chave nova e
independente do mesmo comprimento, e decifrada em seguida. O critério de
sucesso é `mensagem_original == mensagem_decifrada`.

| Mensagem | Origem | Bytes | Preservação confirmada |
|---|---|---|---|
| ASCII | `mensagens_teste.txt` (linha "ASCII: …") | 68 | ✅ True |
| UTF-8 | `mensagens_teste.txt` (linha "UTF8: …", com acentuação) | 84 | ✅ True |
| Binária | literal `b"110111000011010"` | 15 | ✅ True |

Nos três casos a mensagem recuperada foi idêntica à original. O caso UTF-8
confirma que a cifra opera sobre a *sequência de bytes* resultante da
codificação (não sobre caracteres), portanto é agnóstica à presença de
acentuação ou de pontos de código multibyte.

## 4. Parte B — Cifração de arquivo completo

Arquivo de entrada: `registros_rede_sinteticos.csv` (registros fictícios de
rede). Fluxo:

1. Leitura integral em modo binário (`"rb"`).
2. Geração de uma chave aleatória do mesmo tamanho do arquivo.
3. Cifração e gravação de **apenas os bytes cifrados** em `arquivo.cifrado`.
4. Decifração e gravação do resultado em `arquivo.recuperado`.
5. Gravação da chave em um arquivo separado, `chave_file.bin`, existente
   somente durante o experimento.

### Resultados

| Arquivo | Tamanho (bytes) |
|---|---|
| Original (`registros_rede_sinteticos.csv`) | 897 |
| Cifrado (`arquivo.cifrado`) | 897 |
| Recuperado (`arquivo.recuperado`) | 897 |

Os três arquivos têm o mesmo tamanho, como esperado do OTP (o XOR não
altera o comprimento dos dados).

**Comparação byte a byte** (`fileContent == d_file` em Python, que compara
os `bytes` posição a posição): **igualdade confirmada — `True`**.

Como verificação independente, os resumos SHA-256 do original e do
recuperado foram calculados e coincidem:

```
0b9ff7ac7c9d17b4541755f377b013a11dcf0d5bcb3a10536631a62ab6bfef53  registros_rede_sinteticos.csv
0b9ff7ac7c9d17b4541755f377b013a11dcf0d5bcb3a10536631a62ab6bfef53  arquivo.recuperado
```

(idêntico ao hash de referência publicado em `SHA256SUMS.txt`). O hash do
arquivo cifrado, por sua vez, é completamente diferente:

```
c7bd5d64c599ee5e15a03651508a31a3b829d2c9f454181600454c800e484833  arquivo.cifrado
```

Ao final do experimento, `chave_file.bin` foi removida do diretório com
`os.remove()`, de forma que **nenhuma cópia da chave permanece na entrega**
— apenas o texto cifrado e o texto recuperado.

## 5. Parte C — Reuso de chave (ataque de "two-time pad")

Para demonstrar por que a segurança do OTP depende do uso de uma chave
*por mensagem, uma única vez*, cifraram-se deliberadamente duas mensagens
de mesmo comprimento (M1 e M2, 61 bytes cada) com a **mesma chave**
`k_reuso`.

### 5.1 Vazamento estrutural

Como `C1 = M1 ⊕ K` e `C2 = M2 ⊕ K`:

```
C1 ⊕ C2 = (M1 ⊕ K) ⊕ (M2 ⊕ K) = M1 ⊕ M2
```

A chave se cancela algebricamente. O experimento confirmou isso
diretamente: `c1 XOR c2` e `m1 XOR m2` produziram exatamente os mesmos
bytes — **vazamento confirmado (`True`)** — sem que a chave `k_reuso`
tenha sido usada nesse cálculo.

### 5.2 Exploração (ataque de texto conhecido)

Assumindo que o atacante conhece o conteúdo de M1 (cenário plausível:
formato previsível, cabeçalho fixo, mensagem interceptada por outro meio),
a segunda mensagem é recuperada por completo, sem jamais obter a chave:

```
M2 = (C1 ⊕ C2) ⊕ M1
```

Resultado obtido: `M2 recuperada == M2 original` → **True**. O texto
recuperado (`M2: SEMINAR NA SALA 3013 AS TREZE HORAS. LEVE O SEU
NOTEBOOK.`) é idêntico ao original.

## 6. Discussão de segurança

**Reuso de chave (Parte C).** A prova de sigilo perfeito de Shannon para o
OTP assume que a chave é aleatória, do mesmo tamanho da mensagem e **usada
uma única vez**. Ao reutilizá-la em duas mensagens, essa terceira condição
é violada e o sistema deixa de ser incondicionalmente seguro: o XOR dos
dois textos cifrados equivale ao XOR dos dois textos claros,
independentemente do tamanho da chave ou da qualidade do gerador aleatório
usado para criá-la. Basta uma pista sobre uma das mensagens (idioma,
formato, texto conhecido) para recuperar a outra integralmente — como
demonstrado na Parte C. É por isso que o esquema se chama *one-time* pad:
a garantia matemática só vale para uso único.

**Guarda conjunta de chave e cifrado (Parte B).** Ainda que a chave nunca
seja reutilizada, ela precisa permanecer secreta e fisicamente/logicamente
separada do texto cifrado. Como `M = C ⊕ K`, quem tiver acesso simultâneo
a ambos recupera a mensagem original com uma operação trivial, sem
qualquer esforço criptoanalítico — o OTP não oferece nenhuma resistência
adicional nesse cenário, pois toda a segurança do esquema reside
inteiramente no sigilo da chave. Por isso a chave foi gravada em arquivo
separado e removida do diretório de entrega ao final do experimento
(Seção 4): armazená-la junto ao `arquivo.cifrado` anularia, na prática,
toda a proteção obtida.

## 7. Conclusão

Os três experimentos confirmaram experimentalmente as propriedades
esperadas do One-Time Pad:

- **Correção:** para mensagens de texto (ASCII/UTF-8), mensagem binária e
  um arquivo completo, decifrar o texto cifrado com a mesma chave sempre
  reproduz exatamente os dados originais (Partes A e B).
- **Sigilo condicionado ao uso correto da chave:** o sigilo perfeito do
  OTP só se sustenta quando a chave é aleatória, do tamanho da mensagem,
  usada uma única vez e mantida separada do texto cifrado. Violar
  qualquer uma dessas condições — reuso de chave (Parte C) ou
  co-localização de chave e cifrado (Parte B) — compromete total ou
  parcialmente a confidencialidade, sem exigir poder computacional para
  o ataque.
