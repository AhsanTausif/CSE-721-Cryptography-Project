from ciphers.hill import text_to_numbers          # Reuse function to convert letters → numbers (A=0, ..., Z=25)
from ciphers.affine import mod_inverse            # Reuse modular inverse function (needed for matrix inversion)


def hill_cracker(plaintext: str, ciphertext: str):
    """
    Perform a known plaintext attack on the 2×2 Hill Cipher to recover the encryption key matrix.
    
    The Hill Cipher is linear: C = K × P  (mod 26), where:
        - P is a column vector of two plaintext letters (as numbers)
        - C is the corresponding ciphertext vector
        - K is the unknown 2×2 key matrix
    
    With two known plaintext-ciphertext digraph pairs (i.e., 4 letters total), we can form 2×2 matrices:
        C_matrix = K × P_matrix  (mod 26)
    
    Rearranging: K = C_matrix × P_matrix⁻¹  (mod 26)
    
    This function computes exactly that using only the first four letters.
    
    Requirements:
        - Plaintext and ciphertext must correspond exactly.
        - Both must have the same even number of alphabetic characters (≥4).
        - The first four plaintext letters must form an invertible matrix mod 26.
    
    Returns: The recovered 2×2 key matrix as a list of lists of integers.
    """
    
    # Step 1: Convert both texts to numeric lists (ignoring non-letters, uppercase)
    p_nums = text_to_numbers(plaintext)      # e.g., "HELP" → [7, 4, 11, 15]
    c_nums = text_to_numbers(ciphertext)
    
    # Step 2: Basic validation
    if len(p_nums) != len(c_nums):
        raise ValueError("Plaintext and ciphertext must have the same number of letters")
    if len(p_nums) < 4:
        raise ValueError("Need at least 4 letters for a known plaintext attack on 2×2 Hill")
    if len(p_nums) % 2 != 0:
        raise ValueError("Number of letters must be even (no padding mismatch allowed here)")
    
    # Step 3: Form 2×2 plaintext matrix P using the first four letters as columns
    #     First digraph  → first column: [p0, p1]
    #     Second digraph → second column: [p2, p3]
    P = [
        [p_nums[0], p_nums[2]],   # Row 0: first letter of each digraph
        [p_nums[1], p_nums[3]]    # Row 1: second letter of each digraph
    ]
    
    # Step 4: Form 2×2 ciphertext matrix C in the same way
    C = [
        [c_nums[0], c_nums[2]],
        [c_nums[1], c_nums[3]]
    ]
    
    # Step 5: Compute determinant of P modulo 26
    #     det(P) = (P[0][0] * P[1][1] - P[0][1] * P[1][0]) mod 26
    det_p = (P[0][0] * P[1][1] - P[0][1] * P[1][0]) % 26
    
    # Step 6: Find modular inverse of det(P) modulo 26
    #     This exists only if gcd(det_p, 26) == 1
    inv_det = mod_inverse(det_p, 26)
    if not inv_det:
        raise ValueError(
            "The first four plaintext letters form a non-invertible matrix mod 26. "
            "Try using different starting letters or more known text."
        )
    
    # Step 7: Compute inverse of P: inv_P = (1/det) × adjugate(P) mod 26
    #     Adjugate: swap diagonal, negate off-diagonal
    inv_P = [
        [ P[1][1] * inv_det % 26,           (-P[0][1] * inv_det) % 26 ],   # Row 0
        [ (-P[1][0] * inv_det) % 26,         P[0][0] * inv_det % 26 ]    # Row 1
    ]
    
    # Step 8: Recover key matrix K = C × inv_P  (mod 26)
    #     Perform standard 2×2 matrix multiplication
    K = [[0, 0], [0, 0]]   # Initialize result matrix
    for i in range(2):                  # Row index of result
        for j in range(2):              # Column index of result
            # K[i][j] = C[i][0] * inv_P[0][j] + C[i][1] * inv_P[1][j]  mod 26
            K[i][j] = (C[i][0] * inv_P[0][j] + C[i][1] * inv_P[1][j]) % 26
    
    return K