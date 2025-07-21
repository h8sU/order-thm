# 🔐 TryHackMe XOR Cipher Challenge – Message Decryption

This repository contains a Python script that solves a **TryHackMe cryptography challenge** involving a message encrypted with a **repeating-key XOR cipher**.

## 🕵️‍♂️ Challenge Summary

We intercepted a secret message from an adversary group named **Cipher**. All their encrypted messages start with the plaintext header:

ORDER:

Using this known plaintext (known-plaintext attack), we were able to **recover the XOR key**, decrypt the full message, and extract the flag.

## 🔧 How It Works

1. **Hex message** is provided as a string in the script.
2. The script performs the following:
   - Converts hex to raw bytes
   - Recovers the XOR key using the known plaintext `"ORDER:"`
   - Decrypts the entire message using repeating-key XOR
   - Searches for a flag in `THM{...}` format
   - Prints decrypted message and flag if found

## 📁 File Structure

- `decrypt_xor.py` – The Python script
- `README.md` – Description of the project

## ▶️ Usage

Make sure you have Python 3 installed, then run:

```bash
python3 decrypt_xor.py
```

No external libraries are required.


```

## ✅ Flag Format

- Format: `THM{}`
- Extracted based on the decrypted message content and required structure.

## 💡 Learning Objectives

- Understand how XOR encryption works
- Perform known-plaintext attacks
- Manipulate byte arrays in Python
- Use regex to extract flags

## 🧠 Notes

You can reuse this script for other XOR CTF challenges by modifying:
- The `hex_message`
- The `known_plaintext` if different

## 📬 Author

Created by [Šarūnas Adomaitis](https://github.com/h8sU)  
For educational purposes and TryHackMe CTF training.
