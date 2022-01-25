from django.contrib.auth.hashers import PBKDF2PasswordHasher


class PBKDF2PasswordHasherWithPepper(PBKDF2PasswordHasher):

    pepper = 'pepper'

    def encode(self, password, salt, iteration=None):
        return super(PBKDF2PasswordHasherWithPepper, self).encode(password + self.pepper, salt)

    def verify(self, password, encoded):
        return super(PBKDF2PasswordHasherWithPepper, self).verify(password, encoded)
