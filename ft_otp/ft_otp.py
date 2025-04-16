import argparse

from cryptography.fernet import Fernet

HEX_KEY_LENGTH = 64
ENCRYPTION_SECRET = b"v0XVPkLLfDJmKZiKFzHMO98yIk26jm0L64U3z_bRVXM="


class TimeBasedOTP:
    def __init__(self, encryption_secret: str):
        self.fernet = Fernet(encryption_secret)

    def _encrypt_key(self, key: str):
        return self.fernet.encrypt(key.encode()).decode()

    def decrypt_key(self, encrypted_key: str):
        return self.fernet.decrypt(encrypted_key.encode()).decode()

    def write_key(self, key: str):
        with open("ft_otp.key", "w") as file:
            file.write(self._encrypt_key(key))

    @staticmethod
    def generate_password(key: str):
        return "123456"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="ft_otp")
    input_key_arg = parser.add_argument(
        "-g",
        type=str,
        help="Raw key file path or key string used to generate encrypted key",
    )
    parser.add_argument(
        "-k",
        type=str,
        help="Encrypted key file path or key string used to generate a TOTP",
    )
    args = parser.parse_args()

    if (not args.g and not args.k) or (args.g and args.k):
        raise argparse.ArgumentError(
            input_key_arg, "error: you must provide exactly one option."
        )

    if args.g:
        totp_key = ""

        try:
            with open(args.g, "r") as file:
                file_content = file.read()

                if len(file_content) == HEX_KEY_LENGTH:
                    totp_key = file_content
        except FileNotFoundError:
            if len(args.g) == HEX_KEY_LENGTH:
                totp_key = args.g

        if not totp_key:
            raise argparse.ArgumentError(
                input_key_arg,
                f"error: key must be {HEX_KEY_LENGTH} hexadecimal characters.",
            )

        totp = TimeBasedOTP(ENCRYPTION_SECRET)
        totp.write_key(totp_key)
    elif args.k:
        encrypted_key = ""

        try:
            with open(args.k, "r") as file:
                file_content = file.read()

            encrypted_key = file_content
        except FileNotFoundError:
            encrypted_key = args.k

        totp = TimeBasedOTP(ENCRYPTION_SECRET)
        totp_key = totp.decrypt_key(encrypted_key)
        print(totp.generate_password(totp_key))
