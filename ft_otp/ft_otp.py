import argparse

from cryptography.fernet import Fernet

HEX_KEY_LENGTH = 64
ENCRYPTION_SECRET = b"v0XVPkLLfDJmKZiKFzHMO98yIk26jm0L64U3z_bRVXM="


class TimeBasedOTP:
    def __init__(self, raw_key: str):
        self.raw_key = raw_key
        self.fernet = Fernet(ENCRYPTION_SECRET)

    def _encrypt_key(self):
        return self.fernet.encrypt(self.raw_key.encode()).decode()

    def write_key(self):
        with open("ft_otp.key", "w") as file:
            file.write(self._encrypt_key())


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
        hex_key = ""

        try:
            with open(args.g, "r") as file:
                file_content = file.read()

                if len(file_content) == HEX_KEY_LENGTH:
                    hex_key = file_content
        except FileNotFoundError:
            if len(args.g) == HEX_KEY_LENGTH:
                hex_key = args.g

        if not hex_key:
            raise argparse.ArgumentError(
                input_key_arg,
                f"error: key must be {HEX_KEY_LENGTH} hexadecimal characters.",
            )

        totp = TimeBasedOTP(hex_key)
        totp.write_key()
    elif args.k:
        pass
