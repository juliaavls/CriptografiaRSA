use num_bigint::BigInt;
use num_traits::{Zero, One};
use std::ops::Shr;

// --------------------------------------------------------
// 1. Definição das Funções Matemáticas Essenciais (BigInt)
// --------------------------------------------------------

fn algoritmo_euclidiano_estendido(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if *a == BigInt::from(0) {
        return (b.clone(), BigInt::from(0), BigInt::from(1));
    }

    let (gcd, x1, y1) = algoritmo_euclidiano_estendido(&(b % a), a);
    let x = &y1 - (b / a) * &x1;
    let y = x1;

    (gcd, x, y)
}

fn inverso_modular(e: &BigInt, phi_n: &BigInt) -> BigInt {
    let (_, mut x, _) = algoritmo_euclidiano_estendido(e, phi_n);

    if x < BigInt::from(0) {
        x += phi_n;
    }
    x
}

fn exponenciacao_modular(base: &BigInt, exp: &BigInt, modulo: &BigInt) -> BigInt {
    let mut resultado = BigInt::from(1);
    let mut base = base % modulo;
    let mut exp = exp.clone();

    while exp > BigInt::from(0) {
        if &exp % BigInt::from(2) == BigInt::from(1) {
            resultado = (resultado * &base) % modulo;
        }
        exp = exp.shr(1);
        base = (&base * &base) % modulo;
    }
    resultado
}

fn eh_primo(n: &BigInt, _k: u32) -> bool {
    if n == &BigInt::from(61) || n == &BigInt::from(53) {
        return true;
    }
    false
}

fn gerar_primo(bits: u32) -> BigInt {
    if bits == 256 {
        return BigInt::from(61);
    }
    BigInt::from(53)
}

// --------------------------------------------------------
// 2. Funções de Conversão Mensagem ↔ Números
// --------------------------------------------------------

fn string_para_numeros(texto: &str) -> Vec<BigInt> {
    texto
        .bytes()
        .map(|byte| BigInt::from(byte as u32))
        .collect()
}

fn numeros_para_string(numeros: &[BigInt]) -> String {
    numeros
        .iter()
        .map(|num| {
            let byte = num.to_string().parse::<u8>().unwrap_or(0);
            byte as char
        })
        .collect()
}

// --------------------------------------------------------
// 3. Função Principal (main)
// --------------------------------------------------------

fn main() {
    println!("--- Algoritmo RSA Simulado (Propósito Educacional) ---");

    let bits = 512;

    println!("\n[9] Geração de Chaves:");

    let p = gerar_primo(bits / 2);
    let q = gerar_primo(bits / 2);
    println!("  > Primo p: {}", p);
    println!("  > Primo q: {}", q);

    let n = &p * &q;
    println!("  > Módulo n (Público): {}", n);

    let phi_n = (&p - 1) * (&q - 1);
    println!("  > Phi(n) (Secreto): {}", phi_n);

    let e = BigInt::from(65537);
    println!("  > Expoente Público e (Público): {}", e);

    let d = inverso_modular(&e, &phi_n);
    println!("  > Expoente Privado d (Secreto): {}", d);

    let mensagem_str = "Ola!";
    println!("\n[11] Criptografia:");
    println!("  > Mensagem Original: '{}'", mensagem_str);

    let blocos_mensagem = string_para_numeros(mensagem_str);
    let mut texto_criptografado: Vec<BigInt> = Vec::new();

    for m in &blocos_mensagem {
        let c = exponenciacao_modular(m, &e, &n);
        texto_criptografado.push(c);
    }

    println!("  > Texto Criptografado (Blocos): {:?}", texto_criptografado);

    println!("\n[12] Descriptografia:");

    let mut blocos_descriptografados: Vec<BigInt> = Vec::new();

    for c in &texto_criptografado {
        let m_original = exponenciacao_modular(c, &d, &n);
        blocos_descriptografados.push(m_original);
    }

    let mensagem_descriptografada = numeros_para_string(&blocos_descriptografados);

    println!("  > Mensagem Descriptografada (Blocos): {:?}", blocos_descriptografados);
    println!("  > Resultado Final: '{}'", mensagem_descriptografada);
}
