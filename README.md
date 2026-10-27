# Protected presentation

The site in [`docs/`](docs/) is served by GitHub Pages and is password protected: every file
of the presentation is encrypted (AES-256-GCM, key derived from the password with
PBKDF2-SHA256, 600k iterations) and decrypted in the browser after the password is entered.

## Publishing

```
pip install cryptography
python tools/encrypt_site.py      # encrypts the local site/ folder into docs/
```

The plaintext `site/` folder is not part of this repository.
