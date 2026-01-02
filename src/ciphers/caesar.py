def caesar_encrypt(text: str, shift: int) -> str:
    """
    Encrypts the input text using the Caesar Cipher.
    
    The Caesar Cipher is a simple substitution cipher where each letter
    is shifted forward in the alphabet by a fixed number of positions ('shift').
    
    - Only letters are shifted.
    - Case is preserved (uppercase stays uppercase, lowercase stays lowercase).
    - Non-letter characters (spaces, punctuation, numbers) remain unchanged.
    - The shift wraps around the alphabet (e.g., Z + 1 → A).
    
    Example:
        caesar_encrypt("Hello!", 3) → "Khoor!"
        Because: H→K, e→h, l→o, l→o, o→r, !→!
    """
    shift = shift % 26                    # Normalize shift: 27 → 1, -1 → 25, etc.
                                          # Ensures shift is between 0 and 25
    
    result = ""                           # Will hold the encrypted text
    
    for char in text:                     # Process each character one by one
        if char.isupper():                # Handle uppercase letters (A-Z)
            # Convert to 0-25: subtract ord('A') = 65
            # Add shift, wrap with % 26, then add 65 back to get new letter
            encrypted_char = chr((ord(char) - 65 + shift) % 26 + 65)
            result += encrypted_char
        elif char.islower():              # Handle lowercase letters (a-z)
            # Same logic, but base is ord('a') = 97
            encrypted_char = chr((ord(char) - 97 + shift) % 26 + 97)
            result += encrypted_char
        else:
            # Non-letters (spaces, punctuation, digits) are copied as-is
            result += char
    
    return result


def caesar_decrypt(text: str, shift: int) -> str:
    """
    Decrypts Caesar ciphertext by shifting letters backward.
    
    Decryption is the same as encryption but with a negative shift.
    Example: To undo a shift of +3, we use -3 (or equivalently +23 mod 26).
    
    This function reuses caesar_encrypt() with a negative shift for simplicity
    and to avoid duplicating code.
    
    Example:
        caesar_decrypt("Khoor!", 3) → "Hello!"
    """
    # Shifting backward by 'shift' is same as shifting forward by (26 - shift)
    # But using negative shift is clearer and works perfectly
    return caesar_encrypt(text, -shift)