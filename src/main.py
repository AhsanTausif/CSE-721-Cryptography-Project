import sys
from ciphers.caesar import caesar_encrypt, caesar_decrypt
from ciphers.affine import affine_encrypt, affine_decrypt
from ciphers.playfair import playfair_encrypt, playfair_decrypt
from ciphers.hill import hill_encrypt, hill_decrypt
from crackers.hill_cracker import hill_cracker

# Main console interface
def main():
    while True:
        print("\n=== Crypto Tool ===")
        print("1. Caesar Cipher")
        print("2. Affine Cipher")
        print("3. Playfair Cipher")
        print("4. Hill Cipher")
        print("5. Hill Cipher Cracker (Known Plaintext Attack)")
        print("6. Exit")
        choice = input("Select option (1-6): ").strip()
        
        if choice == '6':
            print("Exiting...")
            sys.exit(0)
        
        if choice not in ['1', '2', '3', '4', '5']:
            print("Invalid choice. Try again.")
            continue
        
        if choice in ['1', '2', '3', '4']:
            print("\na. Encrypt")
            print("b. Decrypt")
            op = input("Select operation (a/b): ").strip().lower()
            if op not in ['a', 'b']:
                print("Invalid operation. Try again.")
                continue
            
            try:
                if choice == '1':
                    shift = int(input("Enter shift (integer): "))
                    if op == 'a':
                        text = input("Enter plaintext: ")
                        print("Encrypted:", caesar_encrypt(text, shift))
                    else:
                        text = input("Enter ciphertext: ")
                        print("Decrypted:", caesar_decrypt(text, shift))
                
                elif choice == '2':
                    a = int(input("Enter a (coprime with 26): "))
                    b = int(input("Enter b: "))
                    if op == 'a':
                        text = input("Enter plaintext: ")
                        print("Encrypted:", affine_encrypt(text, a, b))
                    else:
                        text = input("Enter ciphertext: ")
                        print("Decrypted:", affine_decrypt(text, a, b))
                
                elif choice == '3':
                    key = input("Enter key (string): ")
                    if op == 'a':
                        text = input("Enter plaintext: ")
                        print("Encrypted:", playfair_encrypt(text, key))
                    else:
                        text = input("Enter ciphertext: ")
                        print("Decrypted:", playfair_decrypt(text, key))
                
                elif choice == '4':
                    print("Enter 2x2 key matrix (integers 0-25):")
                    a = int(input("Row 1, Col 1: "))
                    b = int(input("Row 1, Col 2: "))
                    c = int(input("Row 2, Col 1: "))
                    d = int(input("Row 2, Col 2: "))
                    key_matrix = [[a, b], [c, d]]
                    if op == 'a':
                        text = input("Enter plaintext: ")
                        print("Encrypted:", hill_encrypt(text, key_matrix))
                    else:
                        text = input("Enter ciphertext: ")
                        print("Decrypted:", hill_decrypt(text, key_matrix))
            
            except ValueError as e:
                print(f"Error: {e}")
                print("Please check your inputs and try again.")
        
        elif choice == '5':
            try:
                plaintext = input("Enter known plaintext (at least 4 letters): ")
                ciphertext = input("Enter corresponding ciphertext (same length): ")
                key = hill_cracker(plaintext, ciphertext)
                print("Recovered key matrix:")
                print(f"[[{key[0][0]}, {key[0][1]}],")
                print(f" [{key[1][0]}, {key[1][1]}]]")
            except ValueError as e:
                print(f"Error: {e}")
                print("Please check your inputs and try again.")

if __name__ == "__main__":
    main()