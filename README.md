# Crypto Shield

**Crypto Shield** es una utilidad de línea de comandos (CLI) escrita en Python para cifrar y descifrar archivos de forma segura. Nació como un proyecto personal para aplicar fundamentos criptográficos robustos en la práctica, sin depender de cajas negras.

Utiliza **AES-256 en modo GCM** (para garantizar tanto la confidencialidad como la integridad de los datos) y **PBKDF2-HMAC-SHA256** para derivar la clave de manera segura a partir de una contraseña.

## Características

- 🔒 **Cifrado Fuerte:** AES-256-GCM.
- 🔑 **Derivación de Claves:** PBKDF2 con 480,000 iteraciones (siguiendo las recomendaciones actuales de OWASP) y un salt único de 16 bytes por archivo.
- 🛡️ **Integridad:** El modo GCM detecta si el archivo cifrado ha sido manipulado (Authentic Encryption).
- 📂 **Soporte Universal:** Funciona con cualquier tipo de archivo (PDF, DOCX, JPG, ZIP).

## Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/DamianMacancela/crypto-shield.git
   cd crypto-shield
   ```

2. Instala las dependencias necesarias (`cryptography`):
   ```bash
   pip install -r requirements.txt
   ```
   *(Si no existe el archivo `requirements.txt`, simplemente ejecuta: `pip install cryptography`)*

## Uso

La herramienta funciona directamente desde la terminal.

**Para cifrar un archivo:**
```bash
python crypto_shield.py encrypt archivo_secreto.pdf
```
*(Te pedirá ingresar una contraseña de forma segura. El archivo resultante será `archivo_secreto.pdf.enc` y el original se conservará).*

**Para descifrar un archivo:**
```bash
python crypto_shield.py decrypt archivo_secreto.pdf.enc
```
*(Ingresa la contraseña que usaste para cifrarlo. Recuperarás `archivo_secreto.pdf`).*

## ¿Por qué construí esto?

Más allá de ser una herramienta útil para proteger datos locales, el objetivo principal fue entender la criptografía moderna escribiendo el código desde cero. Usar `cryptography.hazmat` en Python te obliga a gestionar los vectores de inicialización (IV), los salts y los algoritmos de derivación correctamente. Es un ejercicio excelente para asentar bases en ciberseguridad.

## Advertencia de Seguridad

Esta es una herramienta de aprendizaje y uso personal. Aunque utiliza primitivas criptográficas estándar de la industria, **no** ha sido auditada profesionalmente. Para proteger información de vida o muerte, te recomiendo siempre confiar en software como GPG, Age o VeraCrypt.

## Licencia

[MIT License](LICENSE)
