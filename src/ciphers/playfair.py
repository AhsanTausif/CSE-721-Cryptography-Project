def prepare_text(text: str) -> str:
    """
    Preprocess the input text for Playfair encryption/decryption.
    
    Steps:
    1. Convert to uppercase.
    2. Replace all 'J' with 'I' (traditional Playfair combines I/J).
    3. Remove all non-alphabetic characters.
    4. Split into digraphs (pairs of letters):
         - If two identical letters appear consecutively (e.g., "LL"), insert 'X' between them.
         - If the final text has an odd number of letters, append 'X' as padding.
    
    Example:
        "Hello!!" → "HELLO" → "HE LX LO" (X inserted between LL, and final padding if needed)
    
    Returns: A string of uppercase letters with even length, ready for digraph processing.
    """
    text = text.upper().replace("J", "I")                    # Step 1 & 2: Uppercase + J → I
    text = "".join([c for c in text if c.isalpha()])         # Step 3: Keep only letters
    
    prepared = ""
    i = 0
    while i < len(text):
        prepared += text[i]                                  # Add the current letter
        
        if i + 1 < len(text):                                # If there's a next letter
            if text[i] == text[i + 1]:                        # Case: double letter (e.g., "LL")
                prepared += "X"                              # Insert filler 'X'
                i += 1                                       # Skip the second identical letter next iteration
            else:
                prepared += text[i + 1]                      # Add the next letter to form a pair
                i += 2                                       # Move past the pair
        else:
            prepared += "X"                                  # Odd length → pad with 'X'
            i += 1                                           # Done
    
    return prepared


def create_playfair_matrix(key: str):
    """
    Build the 5x5 Playfair key square from the given key phrase.
    
    Rules:
    - Convert key to uppercase and replace 'J' with 'I'.
    - Remove duplicate letters (keep only first occurrence).
    - Fill remaining spots with the rest of the alphabet (A-Z except J).
    - Return a 5x5 grid (list of lists).
    
    Example:
        key = "PLAYFAIR EXAMPLE" → matrix starts with P L A Y F I R E X M ...
    """
    key = key.upper().replace("J", "I")                      # Normalize key
    matrix_str = "".join(dict.fromkeys(key))                 # Remove duplicates, preserve order
    
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"                    # Full alphabet without J
    for c in alphabet:
        if c not in matrix_str:
            matrix_str += c                                  # Append missing letters
    
    # Convert flat string into 5x5 grid
    matrix = [list(matrix_str[i:i+5]) for i in range(0, 25, 5)]
    return matrix


def find_position(matrix: list[list[str]], char: str):
    """
    Find the row and column of a given letter in the 5x5 Playfair matrix.
    
    Returns: (row, col) tuple, or None if not found (should not happen with valid input).
    """
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None  # Safety — should never reach here with proper input


def playfair_encrypt(text: str, key: str) -> str:
    """
    Encrypt plaintext using the Playfair cipher.
    
    Process:
    1. Build the key matrix.
    2. Prepare the text into valid digraphs.
    3. For each digraph (pair of letters):
         - Same row    → replace with letters to the right (wrap around).
         - Same column → replace with letters below (wrap around).
         - Different row & column → form rectangle and take opposite corners.
    
    Returns: Ciphertext (uppercase, no spaces).
    """
    matrix = create_playfair_matrix(key)
    text = prepare_text(text)                                # Get clean digraph-ready text
    
    result = ""
    for i in range(0, len(text), 2):
        r1, c1 = find_position(matrix, text[i])              # Position of first letter
        r2, c2 = find_position(matrix, text[i + 1])          # Position of second letter
        
        if r1 == r2:                                         # Same row
            result += matrix[r1][(c1 + 1) % 5]                # Shift right
            result += matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:                                       # Same column
            result += matrix[(r1 + 1) % 5][c1]                # Shift down
            result += matrix[(r2 + 1) % 5][c2]
        else:                                                # Rectangle rule
            result += matrix[r1][c2]                         # Opposite corners
            result += matrix[r2][c1]
    
    return result


def playfair_decrypt(text: str, key: str) -> str:
    """
    Decrypt Playfair ciphertext using the same key.
    
    Same rules as encryption, but shifts are reversed:
         - Same row    → shift left (c - 1)
         - Same column → shift up (r - 1)
         - Rectangle   → same as encryption (opposite corners)
    
    Note: Input ciphertext should already be in valid digraph form.
    """
    matrix = create_playfair_matrix(key)
    text = prepare_text(text)  # Ensures clean input (removes non-letters, handles J→I)
    
    result = ""
    for i in range(0, len(text), 2):
        r1, c1 = find_position(matrix, text[i])
        r2, c2 = find_position(matrix, text[i + 1])
        
        if r1 == r2:                                         # Same row → shift left
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]
        elif c1 == c2:                                       # Same column → shift up
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]
        else:                                                # Rectangle → same as encrypt
            result += matrix[r1][c2]
            result += matrix[r2][c1]
    
    return result