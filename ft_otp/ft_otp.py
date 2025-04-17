import argparse
import hmac
import time
from hashlib import sha1

from cryptography.fernet import Fernet, InvalidToken

HEX_KEY_LENGTH = 64
ENCRYPTION_SECRET = b"v0XVPkLLfDJmKZiKFzHMO98yIk26jm0L64U3z_bRVXM="

# Potential code improvements:
# - stricter input validation
# - add a command to generate a new key


class TimeBasedOTP:
    def __init__(self, encryption_secret: str):
        self.fernet = Fernet(encryption_secret)

    @staticmethod
    def is_valid_key(string: str):
        if len(string) != HEX_KEY_LENGTH:
            return False
        try:
            int(string, 16)
            return True
        except ValueError:
            return False

    def _encrypt_key(self, key: str):
        return self.fernet.encrypt(key.encode()).decode()

    def decrypt_key(self, encrypted_key: str):
        return self.fernet.decrypt(encrypted_key.encode()).decode()

    def write_key(self, key: str):
        with open("ft_otp.key", "w") as file:
            file.write(self._encrypt_key(key))

    @staticmethod
    def generate_password(key: str):
        time_step = 30
        current_time = int(time.time())
        time_counter = current_time // time_step
        password_hash = hmac.new(
            bytes.fromhex(key), time_counter.to_bytes(8, byteorder="big"), sha1
        )

        digest = password_hash.digest()
        offset = digest[-1] & 0xF

        byte1 = digest[offset] & 0x7F
        byte2 = digest[offset + 1] & 0xFF
        byte3 = digest[offset + 2] & 0xFF
        byte4 = digest[offset + 3] & 0xFF

        bin_code = (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4

        return f"{bin_code % 1_000_000:06d}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="ft_otp")
    key_arg = parser.add_argument(
        "-g",
        type=str,
        help="Raw key file path or key string used to generate encrypted key",
    )
    encrypted_key_arg = parser.add_argument(
        "-k",
        type=str,
        help="Encrypted key file path or key string used to generate a TOTP",
    )
    args = parser.parse_args()

    if (not args.g and not args.k) or (args.g and args.k):
        raise argparse.ArgumentError(
            key_arg, "error: you must provide exactly one option."
        )

    if args.g:
        totp_key = ""
        totp = TimeBasedOTP(ENCRYPTION_SECRET)

        try:
            with open(args.g, "r") as file:
                file_content = file.read().strip()

                if totp.is_valid_key(file_content):
                    totp_key = file_content
        except FileNotFoundError:
            if totp.is_valid_key(args.g):
                totp_key = args.g

        if not totp_key:
            raise argparse.ArgumentError(
                key_arg,
                f"error: key must be {HEX_KEY_LENGTH} hexadecimal characters.",
            )

        totp.write_key(totp_key)
    elif args.k:
        encrypted_key = ""

        try:
            with open(args.k, "r") as file:
                file_content = file.read().strip()

            encrypted_key = file_content
        except FileNotFoundError:
            encrypted_key = args.k

        totp = TimeBasedOTP(ENCRYPTION_SECRET)
        try:
            totp_key = totp.decrypt_key(encrypted_key)
        except InvalidToken:
            raise argparse.ArgumentError(
                encrypted_key_arg, "error: invalid encrypted key."
            )

        print(totp.generate_password(totp_key))
