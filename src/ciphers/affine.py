import math  # Used for gcd() to check if 'a' is coprime with 26


def mod_inverse(a: int, m: int = 26) -> int or None:
    """
    Compute the modular multiplicative inverse of 'a' modulo 'm' using brute force.
    
    The inverse of 'a' mod 'm' is a number 'i' such that (a * i) ≡ 1 (mod m).
    This is needed for decryption because we must "undo" the multiplication by 'a'.
    
    This function tries i = 1 to m-1 until it finds the correct inverse.
    Returns None if no inverse exists (i.e., if gcd(a, m) ≠ 1).
    
    Example: mod_inverse(3, 26) → 9, because 3 * 9 = 27 ≡ 1 mod 26
    """
    a = a % m                                            # Normalize a to be within 0–25
    for i in range(1, m):                                # Try all possible values
        if (a * i) % m == 1:                              # Check if this is the inverse
            return i
    return None                                          # No inverse found


def affine_encrypt(text: str, a: int, b: int) -> str:
    """
    Encrypt plaintext using the Affine Cipher: E(x) = (a * x + b) mod 26
    
    - Each letter is converted to a number: A=0, B=1, ..., Z=25
    - Apply the formula: ciphertext_letter = (a * plaintext_number + b) mod 26
    - Convert back to letter
    - Preserves case (upper/lowercase) and leaves non-letters unchanged
    - Requires: gcd(a, 26) == 1 (a must be coprime with 26) for decryption to be possible
    
    Example: a=5, b=8, "hello" → "rovvy"
    """
    # Validation: a must be coprime with 26 for the cipher to be reversible
    if math.gcd(a, 26) != 1:
        raise ValueError("a must be coprime with 26 (gcd(a, 26) == 1)")
    
    result = ""
    for char in text:
        if char.isupper():                                   # Handle uppercase letters
            # Formula: (a * (char - 'A') + b) mod 26 + 'A'
            plaintext_num = ord(char) - 65                    # A → 0, B → 1, ...
            ciphertext_num = (a * plaintext_num + b) % 26
            result += chr(ciphertext_num + 65)               # Back to letter
        elif char.islower():                                 # Handle lowercase letters
            plaintext_num = ord(char) - 97                    # a → 0, b → 1, ...
            ciphertext_num = (a * plaintext_num + b) % 26
            result += chr(ciphertext_num + 97)
        else:
            result += char                                   # Keep spaces, punctuation, etc.
    return result


def affine_decrypt(text: str, a: int, b: int) -> str:
    """
    Decrypt Affine ciphertext using: D(y) = a⁻¹ * (y - b) mod 26
    
    - We need the modular inverse of 'a' (denoted a⁻¹) to "undo" the multiplication
    - Formula: plaintext_number = a⁻¹ * (ciphertext_number - b) mod 26
    - Preserves case and non-letters
    """
    # Find the inverse of 'a' modulo 26
    inv_a = mod_inverse(a, 26)
    if not inv_a:
        raise ValueError("a must be coprime with 26 (gcd(a, 26) == 1)")
    
    result = ""
    for char in text:
        if char.isupper():
            ciphertext_num = ord(char) - 65
            # Reverse formula: inv_a * (ciphertext_num - b) mod 26
            plaintext_num = (inv_a * (ciphertext_num - b)) % 26
            result += chr(plaintext_num + 65)
        elif char.islower():
            ciphertext_num = ord(char) - 97
            plaintext_num = (inv_a * (ciphertext_num - b)) % 26
            result += chr(plaintext_num + 97)
        else:
            result += char
    return result