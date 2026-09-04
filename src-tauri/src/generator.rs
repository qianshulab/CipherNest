use crate::{
    error::{VaultError, VaultResult},
    models::{GeneratedPassword, GeneratorOptions},
};

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS: &str = "0O1lI|";

pub fn generate_password(options: &GeneratorOptions) -> VaultResult<GeneratedPassword> {
    if !(8..=128).contains(&options.length) {
        return Err(VaultError::InvalidInput(
            "密码长度必须在 8 到 128 之间".into(),
        ));
    }

    let mut sets: Vec<Vec<u8>> = Vec::new();
    if options.lowercase {
        sets.push(filtered(LOWERCASE, options.exclude_ambiguous));
    }
    if options.uppercase {
        sets.push(filtered(UPPERCASE, options.exclude_ambiguous));
    }
    if options.digits {
        sets.push(filtered(DIGITS, options.exclude_ambiguous));
    }
    if options.symbols {
        sets.push(filtered(SYMBOLS, options.exclude_ambiguous));
    }
    if sets.is_empty() {
        return Err(VaultError::InvalidInput("至少选择一种字符类型".into()));
    }
    if options.require_each && options.length < sets.len() {
        return Err(VaultError::InvalidInput(
            "密码长度不能小于已选择的字符类型数量".into(),
        ));
    }

    let pool: Vec<u8> = sets.iter().flatten().copied().collect();
    let password = loop {
        let mut candidate = Vec::with_capacity(options.length);
        for _ in 0..options.length {
            candidate.push(pool[secure_random_index(pool.len())?]);
        }
        if !options.require_each
            || sets
                .iter()
                .all(|set| candidate.iter().any(|byte| set.contains(byte)))
        {
            break String::from_utf8(candidate)
                .map_err(|_| VaultError::InvalidInput("字符集无效".into()))?;
        }
    };

    let entropy_bits = if options.require_each {
        constrained_entropy_bits(options.length, &sets)
    } else {
        options.length as f64 * (pool.len() as f64).log2()
    };

    Ok(GeneratedPassword {
        password,
        entropy_bits: (entropy_bits * 10.0).round() / 10.0,
        pool_size: pool.len(),
    })
}

fn filtered(source: &str, exclude_ambiguous: bool) -> Vec<u8> {
    source
        .bytes()
        .filter(|byte| !exclude_ambiguous || !AMBIGUOUS.as_bytes().contains(byte))
        .collect()
}

fn secure_random_index(upper: usize) -> VaultResult<usize> {
    debug_assert!((1..=255).contains(&upper));
    let acceptance_zone = 256 - (256 % upper);
    loop {
        let mut byte = [0_u8; 1];
        getrandom::fill(&mut byte)
            .map_err(|_| VaultError::InvalidInput("系统安全随机源不可用".into()))?;
        let value = byte[0] as usize;
        if value < acceptance_zone {
            return Ok(value % upper);
        }
    }
}

fn constrained_entropy_bits(length: usize, sets: &[Vec<u8>]) -> f64 {
    let pool_size: usize = sets.iter().map(Vec::len).sum();
    let mut valid_count = 0_f64;
    for mask in 0..(1_u32 << sets.len()) {
        let excluded: usize = sets
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, set)| set.len())
            .sum();
        let count = (pool_size - excluded) as f64;
        let term = count.powi(length as i32);
        if mask.count_ones() % 2 == 0 {
            valid_count += term;
        } else {
            valid_count -= term;
        }
    }
    valid_count.max(1.0).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_obeys_all_constraints() {
        let options = GeneratorOptions {
            length: 32,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
            require_each: true,
        };
        for _ in 0..100 {
            let generated = generate_password(&options).unwrap();
            assert_eq!(generated.password.len(), 32);
            assert!(!generated
                .password
                .bytes()
                .any(|byte| AMBIGUOUS.as_bytes().contains(&byte)));
            assert!(generated
                .password
                .bytes()
                .any(|byte| byte.is_ascii_lowercase()));
            assert!(generated
                .password
                .bytes()
                .any(|byte| byte.is_ascii_uppercase()));
            assert!(generated.password.bytes().any(|byte| byte.is_ascii_digit()));
            assert!(generated
                .password
                .bytes()
                .any(|byte| SYMBOLS.as_bytes().contains(&byte)));
        }
    }

    #[test]
    fn empty_character_pool_is_rejected() {
        let options = GeneratorOptions {
            length: 20,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
            require_each: false,
        };
        assert!(generate_password(&options).is_err());
    }
}
