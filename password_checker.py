import requests
import hashlib

def check_password(password: str) -> bool:
    # Convert password to SHA1 hash
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1pwd[:5], sha1pwd[5:]
    
    # Query HaveIBeenPwned API (k-anonymity)
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    if response.status_code != 200:
        raise RuntimeError("Error fetching API results.")
    
    # Check if suffix exists in response
    hashes = (line.split(':') for line in response.text.splitlines())
    return any(h[0] == suffix for h in hashes)

if __name__ == "__main__":
    pwd = input("Enter a password to check: ")
    if check_password(pwd):
        print("⚠️ This password has been pwned! Choose another.")
    else:
        print("✅ Safe! This password was not found in breaches.")
