import re

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt data using repeating-key XOR."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def find_flag(text: str):
    """Search for a flag in the format THM{...}."""
    match = re.search(r'THM\{[^}]+\}', text)
    return match.group(0) if match else None

def recover_key(cipher_bytes: bytes, known_plaintext: bytes) -> bytes:
    """Recover repeating XOR key using known plaintext."""
    return bytes([c ^ p for c, p in zip(cipher_bytes[:len(known_plaintext)], known_plaintext)])

def main():
    # Intercepted hex message (2 lines combined)
    hex_message = (
        "1c1c01041963730f31352a3a386e24356b3d32392b6f6b0d323c22243f6373"
        "1a0d0c302d3b2b1a292a3a38282c2f222d2a112d282c31202d2d2e24352e60"
    )

    # Convert hex to bytes
    try:
        cipher_bytes = bytes.fromhex(hex_message)
    except ValueError as e:
        print(f"[!] Failed to parse hex: {e}")
        return

    # Known plaintext at the start
    known_plaintext = b"ORDER:"

    # Recover key
    key = recover_key(cipher_bytes, known_plaintext)
    ascii_key = ''.join(chr(b) if 32 <= b < 127 else '.' for b in key)

    print(f"[+] Recovered key (hex): {key.hex()}")
    print(f"[+] Recovered key (ASCII): {ascii_key}")

    # Decrypt full message
    decrypted = xor_decrypt(cipher_bytes, key)
    try:
        decrypted_text = decrypted.decode('utf-8')
    except UnicodeDecodeError:
        decrypted_text = decrypted.decode('utf-8', errors='replace')

    print("\n[+] Decrypted message:")
    print(decrypted_text)

    # Try to find flag
    flag = find_flag(decrypted_text)
    if flag:
        print(f"\n🏁 FLAG FOUND: {flag}")
    else:
        print("\n[!] THM flag not found in message.") 

if __name__ == "__main__":
    main()
