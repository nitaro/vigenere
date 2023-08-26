import string


CHARSET = string.ascii_letters + string.digits + string.punctuation + " "


class Vigenere:
    """A class with which to create a cipher table and encrypt/decrypt text.
    Text for encryption/decryption must be subsets of @charset.

    Example:
        >>> vig = Vigenere("p@sSw0rd")
        >>> enc = vig.encrypt("hello world")
        >>> print(enc)  # w^D3KZNrG v
        >>> print(vig.decrypt(enc) == "hello world")  # True
        >>> print(vig.show())  # tab-delimited cipher table
    """

    def __init__(self, passkey: str, charset: str = CHARSET):
        if not set(passkey).issubset(set(charset)):
            raise ValueError("@passkey must be a subset of @charset.")

        self.passkey = passkey
        self.charset = charset
        self.rows = {
            letter: self.charset[i:] + self.charset[:i]
            for i, letter in enumerate(self.charset)
        }

    def _fitted_passkey(self, text):
        """Returns a string of repeating @self.passkey values that matches the length of @text.

        For example, if @self.passkey is "abc" and @text is "1234" then "abca" is returned:

        a   b   c   a
        1   2   3   4
        """

        fitted_passkey = self.passkey

        if len(fitted_passkey) >= len(text):
            fitted_passkey = fitted_passkey[: len(text)]
        else:
            div, mod = divmod(len(text), len(fitted_passkey))
            for i in range(div - 1):
                fitted_passkey += self.passkey
            fitted_passkey += self.passkey[:mod]

        return fitted_passkey

    def _validate_text(self, text):
        """Raises a ValueError if @text is invalid."""

        if self.passkey in text:
            raise ValueError("Text cannot contain passkey.")

        text_set, charset_set = set(text), set(self.charset)
        if not text_set.issubset(charset_set):
            diff = text_set.difference(charset_set)
            raise ValueError(f"Text contains characters not in @charset: {diff}")

        return

    def encrypt(self, text: str):
        """Returns encrypted version of @text."""

        self._validate_text(text)

        encryption = ""
        for i, passkey_char in enumerate(self._fitted_passkey(text)):
            charset_pos = self.charset.index(passkey_char)
            encrypted_char = self.rows[text[i]][charset_pos]
            encryption += encrypted_char

        return encryption

    def decrypt(self, text: str):
        """Returns decrypted version of @text."""

        self._validate_text(text)

        decryption = ""
        for i, passkey_char in enumerate(self._fitted_passkey(text)):
            row_pos = self.rows[passkey_char].index(text[i])
            decrypted_char = self.charset[row_pos]
            decryption += decrypted_char

        return decryption

    def show(self, sep="\t"):
        """Returns cipher table as @sep-delimited string."""

        if any([sep in self.charset, sep == "\n"]):
            raise ValueError("Value for @sep can't be in @self.charset or equal \\n.")

        table = ""
        for key, vals in self.rows.items():
            table += repr(key) + sep + sep.join([repr(v) for v in vals]) + "\n"

        return table
