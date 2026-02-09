from nacl import signing, encoding
import base64, pathlib, argparse

parser = argparse.ArgumentParser(description='Script that accepts a member name')

parser.add_argument('--who', 
                        type=str, 
                        required=True,
                        help='Name of the member')

args = parser.parse_args()
who= args.who

sk = signing.SigningKey.generate()
vk = sk.verify_key

priv_hex = sk.encode(encoder=encoding.HexEncoder).decode()
pub_b64  = base64.urlsafe_b64encode(vk.encode()).decode().rstrip("=")

pathlib.Path("holder_keys").mkdir(exist_ok=True)
pathlib.Path(f"holder_keys/{who}.privhex").write_text(priv_hex)
pathlib.Path(f"holder_keys/{who}.pubb64").write_text(pub_b64)

print(f"generated PRIVHEX: {priv_hex} for {who}")
print(f"generated PUBB64 : {pub_b64} for {who}")
