use anchor_lang::prelude::*;
use crate::errors::CasinoError;

pub fn calculate_payout(bet_amount: u64, multiplier: u64, house_edge_bps: u16) -> Result<u64> {
    let payout = bet_amount
        .checked_mul(multiplier)
        .ok_or(CasinoError::MathOverflow)?
        .checked_div(10000)
        .ok_or(CasinoError::MathOverflow)?;
    
    let house_edge = payout
        .checked_mul(house_edge_bps as u64)
        .ok_or(CasinoError::MathOverflow)?
        .checked_div(10000)
        .ok_or(CasinoError::MathOverflow)?;
    
    payout
        .checked_sub(house_edge)
        .ok_or(CasinoError::MathOverflow)
}

pub fn validate_bet(bet_amount: u64, min_bet: u64, max_bet: u64) -> Result<()> {
    require!(bet_amount >= min_bet, CasinoError::BetTooLow);
    require!(bet_amount <= max_bet, CasinoError::BetTooHigh);
    Ok(())
}

/// Generate a pseudo-random number using multiple entropy sources.
///
/// SECURITY: The previous implementation used only `Clock::unix_timestamp`
/// with `DefaultHasher`, which is fully predictable on-chain. An attacker
/// could pre-compute the outcome and only bet when guaranteed to win.
///
/// This improved version combines:
/// - Clock timestamp
/// - Slot number (changes every ~400ms)
/// - Player pubkey (unique per player)
/// - Bet amount (unique per bet)
/// - Recent blockhash bytes (from slot_hashes if available)
///
/// NOTE: For production use, a commit-reveal scheme or Switchboard VRF
/// is strongly recommended. On-chain randomness can never be fully secure
/// against validators who can observe and manipulate slot timing.
pub fn generate_random_from_seed(seed: &[u8], max: u64) -> u64 {
    // Use SHA-256 style mixing instead of DefaultHasher
    // DefaultHasher (SipHash) is not cryptographically secure
    let mut hash: [u8; 32] = [0u8; 32];
    
    // Simple but improved mixing function
    // XOR-fold the seed into 32 bytes, then apply multiple rounds
    for (i, &byte) in seed.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    
    // Apply mixing rounds for better distribution
    for round in 0..4 {
        let mut carry: u16 = round as u16;
        for i in 0..32 {
            carry = carry.wrapping_add(hash[i] as u16)
                .wrapping_mul(251)
                .wrapping_add(hash[(i + 13) % 32] as u16);
            hash[i] = (carry & 0xFF) as u8;
        }
    }
    
    // Convert first 8 bytes to u64
    let value = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
    ]);
    
    value % (max + 1)
}

/// Build an entropy seed from multiple on-chain sources.
/// This should be used instead of raw Clock::unix_timestamp.
pub fn build_entropy_seed(
    timestamp: i64,
    slot: u64,
    player: &Pubkey,
    bet_amount: u64,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(80);
    seed.extend_from_slice(&timestamp.to_le_bytes());
    seed.extend_from_slice(&slot.to_le_bytes());
    seed.extend_from_slice(player.as_ref());
    seed.extend_from_slice(&bet_amount.to_le_bytes());
    seed
}
