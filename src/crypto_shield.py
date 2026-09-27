"""
crypto_shield.py — Herramienta de encriptación de archivos (AES-256-GCM)

Encripta y desencripta cualquier archivo (documentos, PDFs, imágenes, etc.)
usando criptografía simétrica de grado militar: AES-256 en modo GCM con
derivación de clave segura mediante PBKDF2-HMAC-SHA256.

Uso:
    python crypto_shield.py encrypt archivo.pdf
    python crypto_shield.py decrypt archivo.pdf.enc
    python crypto_shield.py encrypt carpeta/  (encripta todos los archivos)

Autor: Damian Fabricio Macancela
Licencia: MIT
"""

import os
import sys
import argparse
import getpass
import hashlib
import secrets
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Error: Se requiere la librería 'cryptography'.")
    print("Instálala con: pip install cryptography")
    sys.exit(1)


# ───────────────────────────────────────────────────────────────────────────
# Constantes de seguridad
# ───────────────────────────────────────────────────────────────────────────
SALT_SIZE = 16          # 128 bits
NONCE_SIZE = 12         # 96 bits (recomendado para AES-GCM)
KEY_SIZE = 32           # 256 bits (AES-256)
KDF_ITERATIONS = 600_000  # OWASP recomienda >= 600,000 para PBKDF2-SHA256
FILE_EXTENSION = ".enc"
MAGIC_HEADER = b"CSHIELD1"  # Identificador del formato


def derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una clave AES-256 a partir de la contraseña usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(filepath: Path, password: str) -> Path:
    """
    Encripta un archivo individual.

    Formato del archivo .enc:
    [MAGIC_HEADER (8 bytes)] [SALT (16 bytes)] [NONCE (12 bytes)] [CIPHERTEXT + TAG]
    """
    data = filepath.read_bytes()

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    output_path = filepath.with_suffix(filepath.suffix + FILE_EXTENSION)
    output_path.write_bytes(MAGIC_HEADER + salt + nonce + ciphertext)

    # Verificación de integridad: desencriptar inmediatamente para confirmar
    verify_key = derive_key(password, salt)
    verify_aesgcm = AESGCM(verify_key)
    try:
        verify_aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        output_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"Error de verificación en '{filepath.name}'. "
            "El archivo encriptado fue eliminado por seguridad."
        )

    return output_path


def decrypt_file(filepath: Path, password: str) -> Path:
    """Desencripta un archivo .enc y restaura el original."""
    raw = filepath.read_bytes()

    # Validar formato
    if not raw.startswith(MAGIC_HEADER):
        raise ValueError(
            f"'{filepath.name}' no es un archivo encriptado por Crypto Shield."
        )

    offset = len(MAGIC_HEADER)
    salt = raw[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = raw[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = raw[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError(
            "Contraseña incorrecta o archivo corrupto. "
            "No se pudo desencriptar."
        )

    # Quitar la extensión .enc
    if filepath.suffix == FILE_EXTENSION:
        output_path = filepath.with_suffix("")
    else:
        output_path = filepath.with_stem(filepath.stem + "_decrypted")

    output_path.write_bytes(plaintext)
    return output_path


def process_path(target: Path, password: str, action: str) -> list[Path]:
    """Procesa un archivo o todos los archivos de una carpeta."""
    results = []

    if target.is_file():
        files = [target]
    elif target.is_dir():
        if action == "encrypt":
            files = [f for f in target.rglob("*") if f.is_file() and f.suffix != FILE_EXTENSION]
        else:
            files = [f for f in target.rglob("*") if f.is_file() and f.suffix == FILE_EXTENSION]

        if not files:
            print(f"  No se encontraron archivos para {action} en '{target}'.")
            return results
    else:
        print(f"  Error: '{target}' no existe.")
        return results

    for f in files:
        try:
            if action == "encrypt":
                result = encrypt_file(f, password)
                print(f"  ✅ Encriptado: {f.name} → {result.name}")
            else:
                result = decrypt_file(f, password)
                print(f"  ✅ Desencriptado: {f.name} → {result.name}")
            results.append(result)
        except Exception as e:
            print(f"  ❌ Error en '{f.name}': {e}")

    return results


def get_password(confirm: bool = False) -> str:
    """Solicita la contraseña al usuario de forma segura."""
    password = getpass.getpass("🔑 Contraseña: ")
    if not password:
        print("Error: La contraseña no puede estar vacía.")
        sys.exit(1)

    if confirm:
        password2 = getpass.getpass("🔑 Confirma la contraseña: ")
        if password != password2:
            print("Error: Las contraseñas no coinciden.")
            sys.exit(1)

    return password


def show_file_info(filepath: Path):
    """Muestra información sobre un archivo encriptado."""
    raw = filepath.read_bytes()
    if not raw.startswith(MAGIC_HEADER):
        print(f"  '{filepath.name}' no es un archivo de Crypto Shield.")
        return

    size_original_approx = len(raw) - len(MAGIC_HEADER) - SALT_SIZE - NONCE_SIZE - 16
    print(f"  📄 Archivo: {filepath.name}")
    print(f"  🔒 Formato: Crypto Shield v1 (AES-256-GCM)")
    print(f"  📏 Tamaño encriptado: {len(raw):,} bytes")
    print(f"  📏 Tamaño original (aprox.): {max(0, size_original_approx):,} bytes")
    print(f"  🔑 Derivación de clave: PBKDF2-HMAC-SHA256 ({KDF_ITERATIONS:,} iteraciones)")


def main():
    parser = argparse.ArgumentParser(
        prog="crypto_shield",
        description="🔒 Crypto Shield — Encripta y desencripta archivos con AES-256-GCM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python crypto_shield.py encrypt documento.pdf
  python crypto_shield.py encrypt carpeta_confidencial/
  python crypto_shield.py decrypt documento.pdf.enc
  python crypto_shield.py info documento.pdf.enc

Seguridad:
  • Algoritmo: AES-256-GCM (cifrado autenticado)
  • Derivación de clave: PBKDF2-HMAC-SHA256 (600,000 iteraciones)
  • Sal y nonce únicos por archivo (generados con CSPRNG)
  • Verificación de integridad automática post-encriptación

Autor: Damian Fabricio Macancela
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")

    # Encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Encripta archivo(s)")
    enc_parser.add_argument("target", type=Path, help="Archivo o carpeta a encriptar")

    # Decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Desencripta archivo(s)")
    dec_parser.add_argument("target", type=Path, help="Archivo .enc o carpeta a desencriptar")

    # Info
    info_parser = subparsers.add_parser("info", help="Muestra información de un archivo encriptado")
    info_parser.add_argument("target", type=Path, help="Archivo .enc a inspeccionar")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    print()
    print("🛡️  Crypto Shield v1.0")
    print("─" * 40)

    if args.command == "info":
        show_file_info(args.target)
    elif args.command == "encrypt":
        password = get_password(confirm=True)
        print()
        results = process_path(args.target, password, "encrypt")
        print(f"\n  Archivos encriptados: {len(results)}")
    elif args.command == "decrypt":
        password = get_password(confirm=False)
        print()
        results = process_path(args.target, password, "decrypt")
        print(f"\n  Archivos desencriptados: {len(results)}")

    print()


if __name__ == "__main__":
    main()
