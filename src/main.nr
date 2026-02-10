use dep::std;
use dep::poseidon::poseidon::bn254;
use sha256;
// global DEPTH: u32 = 2; // Depth for 4 leaves is 2


fn merkle_root_4(leaves: [Field; 4]) -> Field {
    // let h01 = poseidon2(leaves[0], leaves[1]);
    let h01 = bn254::hash_2([leaves[0], leaves[1]]);
    // let h23 = poseidon2(leaves[2], leaves[3]);
    let h23 = bn254::hash_2([leaves[2], leaves[3]]);
    //poseidon(h01, h23)
    let root = bn254::hash_2([h01, h23]);
    
    println(root);
    
    root
}


fn main(
    root: pub Field,

    // --- Doesnt work as Field input ---
    // pub_key_x: pub Field,
    // pub_key_y: pub Field,
    // signature: pub [Field; 2],

    pub_key_x: pub [u8; 32],
    pub_key_y: pub [u8; 32],
    signature: pub [u8; 64],

    leaves: [Field; 4]
) {

    // Re-build merkle tree from leaves
    let computed_root = merkle_root_4(leaves);

    assert(computed_root == root); // compares hex strings

    // Verify the ECDSA signature of the merkle root
    let root_bytes: [u8; 32] = root.to_be_bytes();

    println(root_bytes);

    // Hash the root bytes before passing it to signature verification
    // This happens internally in Rust, when ecdsa signature happens
    // IMPORTANT: We remove hashing of root bytes in Rust and Noir implementation to achieve a correct signature verification
    
    // let root_bytes_hash = sha256::digest(root_bytes);

    let valid_signature = std::ecdsa_secp256k1::verify_signature(
        pub_key_x,
        pub_key_y,
        signature,
        root_bytes
    );

    assert(valid_signature);
}
