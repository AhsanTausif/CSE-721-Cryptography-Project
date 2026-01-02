# Import the modular inverse function from affine.py
# This is needed for decryption to compute the inverse of the key matrix
from ciphers.affine import mod_inverse


def text_to_numbers(text: str):
    """
    Convert alphabetic characters in the input text to numbers (A=0, B=1, ..., Z=25).
    Non-alphabetic characters are ignored, and the text is converted to uppercase.
    
    Example: "Hello!" -> [7, 4, 11, 11, 14]  (H=7, E=4, L=11, L=11, O=14)
    """
    text = text.upper()                               # Ensure all letters are uppercase
    return [ord(c) - 65 for c in text if c.isalpha()] # ord('A') = 65 → subtract to get 0-25


def numbers_to_text(nums):
    """
    Convert a list of numbers (0-25) back to uppercase letters (0=A, 1=B, ..., 25=Z).
    
    Example: [7, 4, 11, 11, 14] -> "HELLO"
    """
    return "".join(chr(n + 65) for n in nums)         # chr(65) = 'A', so add 65 to get letter


def hill_encrypt(text: str, key_matrix: list[list[int]]):
    """
    Encrypt plaintext using the 2x2 Hill Cipher.
    
    Process:
    1. Convert text to numbers (ignoring non-letters).
    2. If odd length, pad with 'X' (23) to make it even (required for digraphs).
    3. Split into pairs (digraphs).
    4. Treat each pair as a column vector [p1, p2].
    5. Multiply by the key matrix: new_vec = key_matrix * vec mod 26.
    6. Convert resulting numbers back to letters.
    """
    nums = text_to_numbers(text)                       # Step 1: letters → numbers
    
    # Step 2: Pad with 'X' if length is odd (Hill works on pairs)
    if len(nums) % 2 == 1:
        nums.append(23)  # 23 corresponds to 'X'
    
    result = []                                        # Will hold encrypted numbers
    
    # Step 3-5: Process each digraph (pair of letters)
    for i in range(0, len(nums), 2):
        vec = [nums[i], nums[i + 1]]                   # Current plaintext vector (column)
        
        # Matrix multiplication: key_matrix * vec mod 26
        c1 = (key_matrix[0][0] * vec[0] + key_matrix[0][1] * vec[1]) % 26
        c2 = (key_matrix[1][0] * vec[0] + key_matrix[1][1] * vec[1]) % 26
        
        new_vec = [c1, c2]
        result.extend(new_vec)                         # Add ciphertext pair to result
    
    return numbers_to_text(result)                     # Convert final numbers back to text


def hill_decrypt(text: str, key_matrix: list[list[int]]):
    """
    Decrypt ciphertext using the 2x2 Hill Cipher.
    
    Process:
    1. Compute determinant of key matrix mod 26.
    2. Find modular inverse of determinant (required for decryption).
    3. If no inverse exists → key is not valid (not invertible mod 26).
    4. Compute the inverse key matrix using adjugate and inverse determinant.
    5. Multiply each ciphertext digraph by inverse matrix mod 26.
    6. Convert back to letters.
    """
    # Step 1: Determinant = (ad - bc) mod 26 for matrix [[a,b],[c,d]]
    det = (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]) % 26
    
    # Step 2: Find inverse of determinant modulo 26
    inv_det = mod_inverse(det, 26)
    if not inv_det:
        raise ValueError("Key matrix is not invertible modulo 26 (determinant has no inverse)")
    
    # Step 4: Compute inverse matrix = (1/det) * adjugate mod 26
    # Adjugate: swap diagonal, negate off-diagonal
    inv_matrix = [
        [ key_matrix[1][1] * inv_det % 26,          (-key_matrix[0][1] * inv_det) % 26],
        [(-key_matrix[1][0] * inv_det) % 26,           key_matrix[0][0] * inv_det % 26]
    ]
    
    nums = text_to_numbers(text)                       # Convert ciphertext to numbers
    
    # Ciphertext must have even length (no padding check needed on decrypt if encrypted properly)
    if len(nums) % 2 != 0:
        raise ValueError("Ciphertext length must be even (invalid or corrupted)")
    
    result = []
    
    # Step 5: Decrypt each digraph using inverse matrix
    for i in range(0, len(nums), 2):
        vec = [nums[i], nums[i + 1]]                   # Ciphertext vector
        
        p1 = (inv_matrix[0][0] * vec[0] + inv_matrix[0][1] * vec[1]) % 26
        p2 = (inv_matrix[1][0] * vec[0] + inv_matrix[1][1] * vec[1]) % 26
        
        result.extend([p1, p2])
    
    return numbers_to_text(result)                     # Back to plaintext letters