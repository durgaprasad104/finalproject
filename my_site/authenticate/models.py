# models.py
from django.db import models
from django.contrib.auth.models import User
from cryptography.fernet import Fernet

# Generate a key for encryption/decryption (this should be securely stored)
key = Fernet.generate_key()
cipher_suite = Fernet(key)

class GeneratedPassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password = models.BinaryField()  # Store encrypted password as binary data
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Encrypt the password before saving
        if isinstance(self.password, str):
            self.password = cipher_suite.encrypt(self.password.encode())
        super(GeneratedPassword, self).save(*args, **kwargs)

    def get_password(self):
        # Decrypt the password when retrieving
        return cipher_suite.decrypt(self.password).decode()
