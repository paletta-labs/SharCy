<pre>            ██████                               
          ███  ████████                          
          █  ░░░▒▒▒▓▓▓▓███                       
          ██  ░░░▒▒▒▓▒▓▓▓▓██                     
           █     ░░░░▒▒▒▓▓▓▓██                   
           ██     ░░░░▒▒▒▓▓▓▓██                  
            ██      ░░░░▒▒▒▓▓▓▓██                
             ██    ░░░░░▒▒▒▒▓▓▓▓██               
              ██     ░░░░▒▒▒▓▓▓▓▓█               
               █    ░░░░▒▒▒▓▓▓▓▓▓▓██             
               █    ░░░▒▒▒▒▒▒▓▓▓▓▓▓█             
              ██     ░░░░▒▒▒▓▓▓▓▓▓▓██            
              █     ░░░░▒▒▒▒▒▓▓▓▓▓▓▓█            
           ████    ░░░░░▒▒▒▒▓▓▓▓▓▓▓▓██           
       █████    ░░░░░░▒▒▒▒▒▒▒▒▓▓▓▓▓▓███████      
   ███▓▓▓▓█ ▓▓▓▓▓░░█████████████████▓▓▓▓██████</pre>

# SharCy Encryption Tool

SharCy is a command-line encryption tool for securely encrypting, decrypting, and managing sensitive text files, with a focus on storing encrypted data on removable drives (such as USB sticks). It uses strong password-based encryption and file integrity checks to help protect your secrets.

## Features

- **Strong Password Enforcement:** Requires passwords with at least 12 characters, including uppercase, lowercase, digits, and special characters.
- **Modern Encryption:** Uses PBKDF2-HMAC-SHA256 for key derivation and [Fernet](https://cryptography.io/en/latest/fernet/) symmetric encryption.
- **File Integrity:** Protects the salt file with HMAC-SHA256 to detect tampering.
- **Secure Deletion:** Attempts to securely overwrite and delete files.
- **Cross-Platform:** Works on Windows, macOS, and Linux.

## Usage

1. **Run the script:**
   ```sh
   python SharCy-0.1.0-alpha.py
   ```

2. **Select USB Path:**
   - Enter the path to your USB drive (e.g., `/media/usb` or `D:\`), or press Enter to use the script's directory.

3. **Set a Strong Password:**
   - Enter a password that meets the strength requirements.

4. **Choose an Operation:**
   - `1`: Write encrypted text to the USB.
   - `2`: Read and decrypt previously encrypted text.
   - `3`: Securely delete the encrypted file.
   - `q`: Quit the application.

## Security Notes

- **Salt & HMAC:** The salt and its HMAC are stored on the USB drive to ensure integrity.
- **Secure Deletion:** True secure deletion is not guaranteed on SSDs or some filesystems.
- **Password Security:** Passwords are never stored; losing your password means losing access to your data.

## Requirements

- Python 3.8+
- [cryptography](https://pypi.org/project/cryptography/)

Install dependencies with:
```sh
pip install cryptography
```

## License

See [LICENSE.txt](LICENSE.txt).

---

**Warning:** This tool is provided as-is. Always back up your data and test the tool before using it for critical information.