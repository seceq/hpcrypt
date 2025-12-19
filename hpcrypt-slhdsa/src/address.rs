//! ADRS (Address) structure for SLH-DSA.
//!
//! Per FIPS 205 Figure 13, addresses use a word-aligned format:
//! - Word 0: layer address
//! - Words 1-3: tree address (96 bits, but only 64 bits used for most cases)
//! - Word 4: type
//! - Word 5: key pair address
//! - Word 6: chain address / tree height
//! - Word 7: hash address / tree index

/// Address types as defined in FIPS 205:
///
/// WOTS+ hash address type
pub const ADDR_TYPE_WOTS: u32 = 0;
/// WOTS+ public key compression address type
pub const ADDR_TYPE_WOTS_PK: u32 = 1;
/// Merkle tree node address type
pub const ADDR_TYPE_TREE: u32 = 2;
/// FORS tree node address type
pub const ADDR_TYPE_FORS_TREE: u32 = 3;
/// FORS roots compression address type
pub const ADDR_TYPE_FORS_ROOTS: u32 = 4;
/// WOTS+ pseudorandom function address type
pub const ADDR_TYPE_WOTS_PRF: u32 = 5;
/// FORS pseudorandom function address type
pub const ADDR_TYPE_FORS_PRF: u32 = 6;

/// Word offsets for the address structure
const WORD_LAYER: usize = 0;
const WORD_TREE_HI: usize = 1;   // tree[95:64] - usually 0 for 64-bit tree
const WORD_TREE_MID: usize = 2;  // tree[63:32]
const WORD_TREE_LO: usize = 3;   // tree[31:0]
const WORD_TYPE: usize = 4;
const WORD_KEYPAIR: usize = 5;
const WORD_CHAIN: usize = 6;     // Also used for tree height
const WORD_HASH: usize = 7;      // Also used for tree index

/// Address structure using word-aligned format per FIPS 205.
/// Each field is a 32-bit word stored in big-endian byte order.
#[derive(Clone, Copy, Debug)]
pub struct Address {
    /// 8 words × 4 bytes = 32 bytes total
    bytes: [u8; 32],
}

impl Address {
    /// Create a new zeroed address.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            bytes: [0u8; 32],
        }
    }

    /// Helper to set a word (4 bytes) at the given word index in big-endian.
    #[inline(always)]
    fn set_word(&mut self, word: usize, value: u32) {
        let offset = word * 4;
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// Helper to get a word (4 bytes) from the given word index.
    #[inline(always)]
    fn get_word(&self, word: usize) -> u32 {
        let offset = word * 4;
        u32::from_be_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
    }

    /// Set the layer address.
    #[inline(always)]
    pub fn set_layer(&mut self, layer: u32) {
        self.set_word(WORD_LAYER, layer);
    }

    /// Get the layer address.
    #[inline(always)]
    pub fn layer(&self) -> u32 {
        self.get_word(WORD_LAYER)
    }

    /// Set the tree address (64-bit value stored in words 2-3).
    #[inline(always)]
    pub fn set_tree(&mut self, tree: u64) {
        // Word 1 is always 0 for 64-bit tree
        self.set_word(WORD_TREE_HI, 0);
        // Words 2-3 hold the 64-bit tree value in big-endian
        self.set_word(WORD_TREE_MID, (tree >> 32) as u32);
        self.set_word(WORD_TREE_LO, tree as u32);
    }

    /// Get the tree address.
    #[inline(always)]
    pub fn tree(&self) -> u64 {
        let high = self.get_word(WORD_TREE_MID) as u64;
        let low = self.get_word(WORD_TREE_LO) as u64;
        (high << 32) | low
    }

    /// Set the address type.
    #[inline(always)]
    pub fn set_type(&mut self, addr_type: u32) {
        self.set_word(WORD_TYPE, addr_type);
    }

    /// Set the address type and clear all subsequent fields to zero.
    #[inline(always)]
    pub fn set_type_and_clear(&mut self, addr_type: u32) {
        self.set_word(WORD_TYPE, addr_type);
        // Clear words 5-7
        self.set_word(WORD_KEYPAIR, 0);
        self.set_word(WORD_CHAIN, 0);
        self.set_word(WORD_HASH, 0);
    }

    /// Get the address type.
    #[inline(always)]
    pub fn addr_type(&self) -> u32 {
        self.get_word(WORD_TYPE)
    }

    // WOTS-specific fields

    /// Set the keypair address.
    #[inline(always)]
    pub fn set_keypair(&mut self, keypair: u32) {
        self.set_word(WORD_KEYPAIR, keypair);
    }

    /// Get the keypair address.
    #[inline(always)]
    pub fn keypair(&self) -> u32 {
        self.get_word(WORD_KEYPAIR)
    }

    /// Set the chain address.
    #[inline(always)]
    pub fn set_chain(&mut self, chain: u32) {
        self.set_word(WORD_CHAIN, chain);
    }

    /// Get the chain address.
    #[inline(always)]
    pub fn chain(&self) -> u32 {
        self.get_word(WORD_CHAIN)
    }

    /// Set the hash address.
    #[inline(always)]
    pub fn set_hash(&mut self, hash: u32) {
        self.set_word(WORD_HASH, hash);
    }

    /// Get the hash address.
    #[inline(always)]
    pub fn hash(&self) -> u32 {
        self.get_word(WORD_HASH)
    }

    // Tree-specific fields (shares some words with WOTS fields)

    /// Set the tree height (shares word with chain address).
    #[inline(always)]
    pub fn set_tree_height(&mut self, height: u32) {
        self.set_word(WORD_CHAIN, height);
    }

    /// Get the tree height.
    #[inline(always)]
    pub fn tree_height(&self) -> u32 {
        self.get_word(WORD_CHAIN)
    }

    /// Set the tree index (shares word with hash address).
    #[inline(always)]
    pub fn set_tree_index(&mut self, index: u32) {
        self.set_word(WORD_HASH, index);
    }

    /// Get the tree index.
    #[inline(always)]
    pub fn tree_index(&self) -> u32 {
        self.get_word(WORD_HASH)
    }

    /// Copy layer and tree address from another address.
    #[inline(always)]
    pub fn copy_subtree_addr(&mut self, other: &Address) {
        // Copy words 0-3 (layer + tree)
        self.bytes[0..16].copy_from_slice(&other.bytes[0..16]);
    }

    /// Convert to bytes for hashing.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Update hash field directly in serialized bytes.
    #[inline(always)]
    pub fn update_hash_in_bytes(hash: u32, bytes: &mut [u8; 32]) {
        let offset = WORD_HASH * 4;
        bytes[offset..offset + 4].copy_from_slice(&hash.to_be_bytes());
    }

    /// Update tree height field directly in serialized bytes.
    #[inline(always)]
    pub fn update_tree_height_in_bytes(height: u32, bytes: &mut [u8; 32]) {
        let offset = WORD_CHAIN * 4;
        bytes[offset..offset + 4].copy_from_slice(&height.to_be_bytes());
    }

    /// Update tree index field directly in serialized bytes.
    #[inline(always)]
    pub fn update_tree_index_in_bytes(index: u32, bytes: &mut [u8; 32]) {
        let offset = WORD_HASH * 4;
        bytes[offset..offset + 4].copy_from_slice(&index.to_be_bytes());
    }

    /// Update both tree height and index in serialized bytes.
    #[inline(always)]
    pub fn update_tree_fields_in_bytes(height: u32, index: u32, bytes: &mut [u8; 32]) {
        let chain_offset = WORD_CHAIN * 4;
        let hash_offset = WORD_HASH * 4;
        bytes[chain_offset..chain_offset + 4].copy_from_slice(&height.to_be_bytes());
        bytes[hash_offset..hash_offset + 4].copy_from_slice(&index.to_be_bytes());
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { bytes: *bytes }
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Address {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_basic() {
        let mut addr = Address::new();
        assert_eq!(addr.bytes, [0u8; 32]);

        addr.set_layer(5);
        assert_eq!(addr.layer(), 5);

        addr.set_tree(0x123456789ABCDEF0);
        assert_eq!(addr.tree(), 0x123456789ABCDEF0);

        addr.set_type(ADDR_TYPE_WOTS);
        assert_eq!(addr.addr_type(), ADDR_TYPE_WOTS);
    }

    #[test]
    fn test_wots_fields() {
        let mut addr = Address::new();
        addr.set_type(ADDR_TYPE_WOTS);
        addr.set_keypair(10);
        addr.set_chain(20);
        addr.set_hash(30);

        assert_eq!(addr.keypair(), 10);
        assert_eq!(addr.chain(), 20);
        assert_eq!(addr.hash(), 30);
    }

    #[test]
    fn test_tree_fields() {
        let mut addr = Address::new();
        addr.set_type(ADDR_TYPE_TREE);
        addr.set_tree_height(15);
        addr.set_tree_index(100);

        assert_eq!(addr.tree_height(), 15);
        assert_eq!(addr.tree_index(), 100);
    }

    #[test]
    fn test_to_bytes_roundtrip() {
        let mut addr = Address::new();
        addr.set_layer(1);
        addr.set_tree(0x1234567890ABCDEF);
        addr.set_type(ADDR_TYPE_FORS_TREE);
        addr.set_tree_height(10);
        addr.set_tree_index(50);

        let bytes = addr.to_bytes();
        let addr2 = Address::from_bytes(&bytes);

        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_copy_subtree() {
        let mut addr1 = Address::new();
        addr1.set_layer(3);
        addr1.set_tree(0xABCDEF);

        let mut addr2 = Address::new();
        addr2.copy_subtree_addr(&addr1);

        assert_eq!(addr2.layer(), 3);
        assert_eq!(addr2.tree(), 0xABCDEF);
    }

    #[test]
    fn test_size() {
        assert_eq!(core::mem::size_of::<Address>(), 32);
    }

    #[test]
    fn test_word_aligned_layout() {
        // Verify the word-aligned byte layout matches FIPS 205 Figure 13
        let mut addr = Address::new();
        addr.set_layer(21);
        addr.set_tree(0x123456789ABCDEF0);
        addr.set_type(5);  // WOTS_PRF
        addr.set_keypair(1);
        addr.set_chain(2);
        addr.set_hash(3);

        let bytes = addr.to_bytes();

        // Word 0: layer = 21 (big-endian)
        assert_eq!(&bytes[0..4], &21u32.to_be_bytes());
        // Word 1: tree high = 0 (only 64-bit tree used)
        assert_eq!(&bytes[4..8], &0u32.to_be_bytes());
        // Word 2: tree mid = 0x12345678
        assert_eq!(&bytes[8..12], &0x12345678u32.to_be_bytes());
        // Word 3: tree low = 0x9ABCDEF0
        assert_eq!(&bytes[12..16], &0x9ABCDEF0u32.to_be_bytes());
        // Word 4: type = 5
        assert_eq!(&bytes[16..20], &5u32.to_be_bytes());
        // Word 5: keypair = 1
        assert_eq!(&bytes[20..24], &1u32.to_be_bytes());
        // Word 6: chain = 2
        assert_eq!(&bytes[24..28], &2u32.to_be_bytes());
        // Word 7: hash = 3
        assert_eq!(&bytes[28..32], &3u32.to_be_bytes());
    }
}
