from django.conf import settings
from django.contrib.auth.hashers import PBKDF2PasswordHasher

from passsword_manager.settings import PEPPER


class PBKDF2PasswordHasherWithPepper(PBKDF2PasswordHasher):

    def encode(self, password, salt, iteration=None):
        return super(PBKDF2PasswordHasherWithPepper, self).encode(password + PEPPER, salt)

    def verify(self, password, encoded):
        return super(PBKDF2PasswordHasherWithPepper, self).verify(password, encoded)
