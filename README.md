# CriptografiaRSA
# 🔐 Criptografia RSA (Rivest–Shamir–Adleman)

## 🧭 Assunto Principal
O tema central abordado é a **Criptografia RSA (Rivest–Shamir–Adleman)**, explicando seus **fundamentos matemáticos**, **funcionamento do algoritmo**, **segurança** e **limitações**.

---

## 1. 🧠 Definição e Características do RSA

- O **RSA** é um algoritmo de **criptografia assimétrica** (ou de chave pública) desenvolvido em **1977**.  
- Utiliza **duas chaves diferentes**:
  - **Pública** → compartilhável  
  - **Privada** → secreta  
- É **bidirecional**, podendo ser usado para **criptografia** (confidencialidade) e **assinaturas digitais** (autenticidade).  
- Base de protocolos como **HTTPS**, **SSH** e **TLS**.

---

## 2. 🧩 Fundamentos Matemáticos (O Pilar da Segurança)

- Baseia-se na **dificuldade de fatorar números grandes**, onde `n = p × q`.  
- Utiliza **Aritmética Modular** para operações eficientes.  
- A **Função Totiente de Euler** é:
φ(n) = (p − 1) × (q − 1)
- O **Teorema de Euler** garante o funcionamento correto do algoritmo.  
- O expoente privado `d` é o **inverso modular** de `e`:
e × d ≡ 1 (mod φ(n))
- O cálculo de `d` é feito pelo **Algoritmo Euclidiano Estendido**.

---

## 3. ⚙️ Algoritmo e Fases de Operação

### 🔑 Geração de Chaves
1. Escolher dois primos grandes `p` e `q`.  
2. Calcular `n = p × q`.  
3. Calcular `φ(n) = (p − 1) × (q − 1)`.  
4. Escolher `e` (geralmente `65537`).  
5. Calcular `d` tal que `e × d ≡ 1 (mod φ(n))`.

---

## 4. ⚡ Otimizações de Performance
- **Exponenciação Modular Rápida (Square-and-Multiply):**  
  Reduz a complexidade para `O(log(exp))`.
- **Chinese Remainder Theorem (CRT):**  
  Acelera a descriptografia em até **4x**.
- **Complexidade:**
  - Geração de primos: `O(log⁴ n)`
  - Exponenciação modular: `O(log³ n)`

---

## 5. 🧱 Segurança e Implementação

| Ano  | Tamanho Mínimo | Equivalência Simétrica | Status |
|------|----------------|------------------------|--------|
| 2015 | 2048 bits      | 112 bits               | ✅ Seguro |
| 2025 | 3072 bits      | 128 bits               | ✅ Recomendado |

### 🔐 Contramedidas
- Uso obrigatório de **OAEP (Optimal Asymmetric Encryption Padding)** para evitar ataques de *padding* (ex: Bleichenbacher).  
- Implementações devem ser **tempo constante** (*constant-time*) para mitigar ataques de **canal lateral**.  
- Evitar **expoentes privados pequenos** (`d` pequeno).  
- Implementações educacionais (sem padding, com chaves pequenas) são inseguras.  
  Para produção, utilize bibliotecas como **OpenSSL**, **PyCryptodome** ou **cryptography**.

---

## 6. 🧬 Limitações e Ameaças Futuras
- **Performance:**  
  O RSA é ~**1000x mais lento** que algoritmos simétricos como o **AES**.  
  Usado principalmente para **troca de chaves** e **assinaturas digitais**.
- **Vulnerabilidade Quântica:**  
  O **Algoritmo de Shor (1994)** pode quebrar o RSA em tempo polinomial usando computadores quânticos.
- **Criptografia Pós-Quântica (PQC):**  
  Alternativas seguras incluem algoritmos como:
  - **Kyber** → criptografia
  - **Dilithium** → assinaturas digitais
- **Complexidade de Implementação:**  
  O RSA é fácil de implementar incorretamente, gerando vulnerabilidades (ex: falta de padding, expoente pequeno, primos reutilizados).

---

## 7. 💻 Exemplo Didático [dependencies]
num-bigint = "0.4"
num-traits = "0.2"
rand = "0.8"

Código Rust (main.rs)
use num_bigint::{BigInt, Sign, ToBigInt};
use num_traits::{One, Zero};
use std::ops::Mul;

// Estruturas para as chaves RSA
#[derive(Debug)]
struct ChavePublica {
    n: BigInt, // Módulo público [8]
    e: BigInt, // Expoente público [9]
}

#[derive(Debug)]
struct ChavePrivada {
    n: BigInt, // Módulo (compartilhado com a chave pública)
    d: BigInt, // Expoente privado [9]
}

// =========================================================================
// FUNÇÕES MATEMÁTICAS ESSENCIAIS
// =========================================================================

/// Implementa a Exponenciação Modular Rápida ("Square-and-Multiply") [3, 10].
/// Calcula (base^exp) mod modulo.
/// Complexidade: O(log exp) [3].
fn exponenciacao_modular(base: &BigInt, exp: &BigInt, modulo: &BigInt) -> BigInt {
    let mut resultado = BigInt::one();
    let mut base_mod = base % modulo;
    let mut expoente = exp.clone();

    // Loop "Square-and-Multiply" [10]
    while expoente > BigInt::zero() {
        if &expoente % 2 == BigInt::one() {
            resultado = resultado.mul(&base_mod) % modulo;
        }
        expoente >>= 1; // exp = exp / 2 [10]
        base_mod = base_mod.mul(&base_mod) % modulo; // base = base^2 [10]
    }
    resultado
}

/// Implementa o Algoritmo Euclidiano Estendido [3, 11].
/// Encontra coeficientes (gcd, x, y) tal que a*x + b*y = gcd(a, b) [3].
fn algoritmo_euclidiano_estendido(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        return (b.clone(), BigInt::zero(), BigInt::one());
    }

    let (gcd, x1, y1) = algoritmo_euclidiano_estendido(&(b % a), a);
    let x = y1 - (b / a) * x1.clone();
    let y = x1;

    (gcd, x, y)
}

/// Calcula o inverso modular [11].
/// Encontra d tal que e * d ≡ 1 (mod phi_n) [11].
fn inverso_modular(e: &BigInt, phi_n: &BigInt) -> BigInt {
    let (_, x, _) = algoritmo_euclidiano_estendido(e, phi_n);
    
    // O inverso modular x deve ser ajustado para ser positivo
    let mut resultado = x % phi_n;
    if resultado.sign() == Sign::Minus {
        resultado += phi_n;
    }
    resultado
}

// =========================================================================
// GERAÇÃO DE CHAVES
// =========================================================================

/// [EDUCAÇÃO] Gera o par de chaves RSA.
/// NOTA: Chaves pequenas (p=61, q=53) são usadas para demonstração.
/// Onde p e q seriam primos gerados, idealmente de ~n/2 bits cada [8].
fn gerar_chaves() -> (ChavePublica, ChavePrivada) {
    // Passo 1: Gerar p e q (Primos fictícios)
    let p = BigInt::from(61); 
    let q = BigInt::from(53); 
    
    // Passo 2: Calcular o Módulo n [8]
    let n = &p * &q; 

    // Passo 3: Calcular φ(n) [8, 9]
    let phi_n = (&p - BigInt::one()) * (&q - BigInt::one()); 

    // Passo 4: Escolher Expoente Público e [9]
    let e = BigInt::from(65537); 
    // 65537 é o valor comum (2^16 + 1) [9]

    // Passo 5: Calcular Expoente Privado d [9]
    let gcd = algoritmo_euclidiano_estendido(&e, &phi_n).0;
    if gcd != BigInt::one() {
        panic!("e e phi_n não são coprimos. O algoritmo falhou.");
    }
    let d = inverso_modular(&e, &phi_n);

    // Resultado Final: Par de chaves [9]
    let public_key = ChavePublica { n: n.clone(), e };
    let private_key = ChavePrivada { n, d };

    (public_key, private_key)
}

// =========================================================================
// CRIPTOGRAFIA E DESCRIPTOGRAFIA
// =========================================================================

/// Converte uma string em um vetor de BigInts (um BigInt por byte) [12].
fn string_para_numeros(texto: &str) -> Vec<BigInt> {
    texto.bytes()
        .map(|byte| byte.to_bigint().unwrap())
        .collect()
}

/// Converte um vetor de BigInts de volta para uma string [12].
fn numeros_para_string(numeros: &[BigInt]) -> String {
    numeros.iter()
           .map(|num| {
                // Converte BigInt para byte e depois para char
                let bytes = num.to_bytes_be().1;
                if bytes.is_empty() {
                    '?'
                } else {
                    bytes as char // Assumindo codificação de 1 byte por caractere
                }
           })
           .collect()
}

/// Criptografa a mensagem (m) usando a chave pública.
fn criptografar(mensagem: &BigInt, chave_pub: &ChavePublica) -> BigInt {
    // c = m^e mod n [2]
    exponenciacao_modular(mensagem, &chave_pub.e, &chave_pub.n)
}

/// Descriptografa o texto cifrado (c) usando a chave privada.
fn descriptografar(cifrado: &BigInt, chave_priv: &ChavePrivada) -> BigInt {
    // m = c^d mod n [2]
    exponenciacao_modular(cifrado, &chave_priv.d, &chave_priv.n)
}

// =========================================================================
// DEMONSTRAÇÃO
// =========================================================================

fn main() {
    println!("# Implementação Educacional do Algoritmo RSA em Rust");
    
    // 1. Geração de Chaves
    let (chave_pub, chave_priv) = gerar_chaves();
    
    println!("\n--- 1. Geração de Chaves (p=61, q=53, n=3233) ---");
    println!("Chave Pública (n, e): ({}, {})", chave_pub.n, chave_pub.e);
    println!("Chave Privada (n, d): ({}, {})", chave_priv.n, chave_priv.d);

    // 2. Preparação da Mensagem
    let mensagem_str = "RUST";
    let mensagens_numericas = string_para_numeros(mensagem_str);
    
    println!("\n--- 2. Mensagem Original ---");
    println!("Mensagem String: {}", mensagem_str);
    println!("Mensagem Numérica (por byte): {:?}", mensagens_numericas);

    // 3. Criptografia
    let texto_cifrado: Vec<BigInt> = mensagens_numericas
        .iter()
        .map(|m| {
            // O limite de mensagem é m < n [13]
            if m >= &chave_pub.n {
                panic!("Erro: A mensagem é muito longa para o módulo n.");
            }
            criptografar(m, &chave_pub)
        })
        .collect();

    println!("\n--- 3. Criptografia (C = M^e mod n) ---");
    println!("Texto Cifrado (Numérico): {:?}", texto_cifrado);
    
    // 4. Descriptografia
    let texto_decifrado: Vec<BigInt> = texto_cifrado
        .iter()
        .map(|c| descriptografar(c, &chave_priv))
        .collect();

    let mensagem_recuperada = numeros_para_string(&texto_decifrado);

    println!("\n--- 4. Descriptografia (M = C^d mod n) ---");
    println!("Texto Decifrado (Numérico): {:?}", texto_decifrado);
    println!("Mensagem Recuperada (String): {}", mensagem_recuperada);
    
    // 5. Verificação
    assert_eq!(mensagem_str, mensagem_recuperada);
    println!("\n✅ Sucesso: A mensagem foi criptografada e descriptografada corretamente.");
}
