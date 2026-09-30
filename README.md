# Password Security Checker

Ferramenta de linha de comando para análise de senhas, feita em Python 3.10+ e sem dependências externas.

O programa verifica características comuns de segurança, calcula o espaço de busca da senha, estima a entropia e mostra quanto tempo uma tentativa de força bruta poderia levar em diferentes cenários.

Também possui algumas heurísticas para identificar senhas previsíveis e uma lista embutida com senhas frequentemente encontradas em vazamentos.

## Funcionalidades

* Entrada de senha usando `getpass`, sem exibir o conteúdo no terminal.
* Verificação de 9 critérios de segurança.
* Cálculo do tamanho do espaço de busca.
* Estimativa de entropia em bits.
* Estimativa de tempo de quebra por força bruta.
* Detecção de sequências e padrões comuns.
* Verificação contra uma lista das 50 senhas mais comuns.
* Classificação geral da senha.
* Sugestões para melhorar a senha.
* Suporte a senhas muito longas sem depender de números de ponto flutuante para representar o espaço de busca.

## Critérios analisados

A senha é verificada nos seguintes pontos:

1. Possui pelo menos 8 caracteres.
2. Contém letras minúsculas.
3. Contém letras maiúsculas.
4. Contém números.
5. Contém símbolos ou outros caracteres especiais.
6. Não é composta apenas por números.
7. Não é composta apenas por letras.
8. Não possui padrões óbvios, como `abc`, `123`, `aaaa` ou `qwerty`.
9. Não está presente na lista embutida de senhas mais comuns.

Caracteres Unicode também são considerados durante algumas verificações, incluindo acentos e emojis.

## Estimativa de força bruta

O programa calcula o espaço de busca usando:

`S = C^L`

onde:

* `C` é o número de caracteres possíveis no conjunto considerado;
* `L` é o tamanho da senha.

A partir disso, a entropia é estimada por:

`H = L × log2(C)`

A ferramenta também calcula o tempo aproximado necessário para testar todas as combinações em três cenários:

| Cenário                            |         Taxa usada |
| ---------------------------------- | -----------------: |
| Ataque online com rate limiting    |  ~100 tentativas/s |
| Ataque offline em CPU comum        |  ~10⁹ tentativas/s |
| Ataque offline com cluster de GPUs | ~10¹¹ tentativas/s |

Os valores são apenas estimativas teóricas. A velocidade real depende principalmente da aplicação, do algoritmo de hash e do hardware utilizado.

## Exemplo

```text
==============================================================================
        RELATÓRIO DE ANÁLISE E SEGURANÇA DE SENHA
==============================================================================

[+] CHECKLIST
------------------------------------------------------------------------------
 ✅ [APROVADO ] 1. Comprimento mínimo de 8 caracteres - 16 caracteres
 ✅ [APROVADO ] 2. Contém letras minúsculas - Presente
 ✅ [APROVADO ] 3. Contém letras maiúsculas - Presente
 ✅ [APROVADO ] 4. Contém números - Presente
 ✅ [APROVADO ] 5. Contém símbolos/caracteres especiais - Presente
 ✅ [APROVADO ] 6. Não é composta apenas por números - Variada
 ✅ [APROVADO ] 7. Não é composta apenas por letras - Variada
 ✅ [APROVADO ] 8. Não contém sequências óbvias - Nenhum padrão encontrado
 ✅ [APROVADO ] 9. Não está entre as senhas mais comuns - Não encontrada

[+] MÉTRICAS
------------------------------------------------------------------------------
 • Comprimento:       16 caracteres
 • Charset:           95 caracteres
 • Entropia:          105.12 bits
 • Espaço de busca:   ~4.401e+31 combinações

[+] ESTIMATIVA DE FORÇA BRUTA
------------------------------------------------------------------------------
 CENÁRIO                                    | MÉDIA (50%)        | PIOR CASO
------------------------------------------------------------------------------
 Online com limitação                       | > 10^21 anos       | > 10^22 anos
 Offline em CPU                             | > 697 trilhões     | > 1394 trilhões
 Offline com cluster de GPUs                | > 7 trilhões       | > 13 trilhões

[+] CLASSIFICAÇÃO
------------------------------------------------------------------------------
 >>> [ MUITO FORTE ] <<<

[+] SUGESTÃO
------------------------------------------------------------------------------
 Considere usar uma passphrase com várias palavras não relacionadas,
 de preferência geradas aleatoriamente por Diceware ou por um gerenciador
 de senhas.
```

## Instalação

O projeto usa apenas a biblioteca padrão do Python, então não é necessário instalar pacotes com `pip`.

### Requisitos

* Python 3.10 ou superior

[Download do Python](https://www.python.org/downloads/)

### Clonar o repositório

```bash
git clone https://github.com/SEU-USUARIO/password-security-checker.git
cd password-security-checker
```

### Executar normalmente

```bash
python password_checker.py
```

Nesse modo, a senha é digitada sem aparecer no terminal.

## Entropia e espaço de busca

A estimativa utilizada pelo programa parte de um modelo de busca uniforme.

Por exemplo, considerando uma senha de 16 caracteres e um conjunto de 95 caracteres possíveis:

`95^16 ≈ 4.401 × 10^31`

A entropia correspondente é:

`16 × log2(95) ≈ 105.12 bits`

Essa conta representa uma senha realmente aleatória dentro daquele conjunto. Uma senha criada por uma pessoa pode ter uma entropia efetiva muito menor mesmo quando possui muitos caracteres diferentes.

### Referência usada pelo programa

| Entropia   | Classificação |
| ---------- | ------------- |
| < 28 bits  | Muito fraca   |
| 28–44 bits | Fraca         |
| 45–59 bits | Razoável      |
| 60–79 bits | Forte         |
| ≥ 80 bits  | Muito forte   |

Essas faixas são apenas uma referência para a classificação usada pela ferramenta.

## Limitações

O cálculo de força bruta não representa todos os ataques possíveis.

### Ataques de dicionário

Uma senha previsível pode ser encontrada rapidamente mesmo que o espaço de busca teórico pareça grande.

Exemplo:

```text
P@ssw0rd123
```

Esse tipo de senha pode ser testado por listas de palavras, regras de substituição e outros métodos usados por ferramentas como Hashcat e John the Ripper.

Por isso, o programa aplica uma penalidade quando identifica padrões previsíveis.

### Algoritmo de hash

Em ataques offline, o algoritmo usado para armazenar a senha faz uma grande diferença.

Hashes rápidos e antigos, como MD5, SHA-1 e alguns usos de SHA-256, permitem taxas de tentativa muito maiores.

Algoritmos como Argon2id, bcrypt, scrypt e PBKDF2 foram projetados para tornar esse processo mais caro e lento.

### Outros ataques

Força bruta é apenas um dos possíveis métodos para obter uma senha.

Phishing, malware, keyloggers, reutilização de senhas e vazamentos de dados podem comprometer uma conta independentemente da entropia estimada.

## Objetivo do projeto

O projeto foi desenvolvido principalmente com finalidade educacional e para auditorias preventivas.

A ideia é mostrar, de forma simples, como comprimento, variedade de caracteres e previsibilidade afetam a segurança de uma senha.

## Licença

Este projeto está disponível sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE) para mais informações.
