# 🔒 Crypto Shield — Herramienta de Encriptación de Archivos

> Herramienta de línea de comandos para encriptar y desencriptar archivos
> (documentos, PDFs, imágenes, cualquier tipo) usando criptografía
> **AES-256-GCM** con derivación de clave segura.

## 🎯 Objetivo

Construir una herramienta práctica que resuelva un problema real: proteger
archivos sensibles (documentos legales, PDFs con datos personales, reportes
confidenciales) con criptografía de grado militar, entendiendo no solo *cómo*
funciona sino *por qué* cada decisión de diseño importa para la seguridad.

## 🧭 Contexto y alcance

En el contexto de la **LOPDP** (Ecuador) y el **RGPD**, el cifrado es una de las
medidas técnicas recomendadas para proteger datos personales (Art. 39 LOPDP).
Esta herramienta demuestra cómo implementar esa protección de forma correcta,
evitando errores comunes como:

- Usar algoritmos obsoletos (DES, RC4, MD5)
- No derivar claves correctamente (contraseña directa como clave)
- No autenticar el cifrado (AES-CBC sin HMAC)
- Reutilizar nonces o sales

## 🛠️ Decisiones de diseño y seguridad

| Componente | Elección | Por qué |
|---|---|---|
| Algoritmo | **AES-256-GCM** | Cifrado autenticado (confidencialidad + integridad en una sola operación) |
| Derivación de clave | **PBKDF2-HMAC-SHA256** | Resistente a fuerza bruta; 600,000 iteraciones (recomendación OWASP 2023) |
| Sal | **16 bytes aleatorios** por archivo | Impide ataques de rainbow table; misma contraseña → claves distintas |
| Nonce | **12 bytes aleatorios** por archivo | Tamaño estándar para GCM; generado con CSPRNG del sistema |
| Verificación | Post-encriptación automática | Desencripta inmediatamente para confirmar integridad antes de entregar |

## 🧰 Stack técnico

Python · cryptography · AES-256-GCM · PBKDF2 · Argparse

## ▶️ Cómo usarlo

### Instalación

```bash
pip install cryptography
```

### Encriptar un archivo

```bash
python src/crypto_shield.py encrypt documento.pdf
# Resultado: documento.pdf.enc
```

### Encriptar todos los archivos de una carpeta

```bash
python src/crypto_shield.py encrypt carpeta_confidencial/
```

### Desencriptar

```bash
python src/crypto_shield.py decrypt documento.pdf.enc
# Resultado: documento.pdf (restaurado)
```

### Ver información de un archivo encriptado

```bash
python src/crypto_shield.py info documento.pdf.enc
```

**Salida:**
```
📄 Archivo: documento.pdf.enc
🔒 Formato: Crypto Shield v1 (AES-256-GCM)
📏 Tamaño encriptado: 145,231 bytes
📏 Tamaño original (aprox.): 145,183 bytes
🔑 Derivación de clave: PBKDF2-HMAC-SHA256 (600,000 iteraciones)
```

## 💡 Lecciones aprendidas

- El cifrado **autenticado** (GCM) es fundamentalmente más seguro que el cifrado
  simple (CBC) porque detecta cualquier manipulación del archivo encriptado.
- La derivación de clave con PBKDF2 convierte una contraseña débil en una clave
  criptográficamente fuerte, pero el número de iteraciones debe actualizarse
  periódicamente conforme aumenta la capacidad de cómputo de los atacantes.
- En el contexto legal (LOPDP Art. 39-42), poder demostrar que los datos estaban
  cifrados con un estándar reconocido puede ser un atenuante en caso de brecha.

## ⚠️ Disclaimer

Esta herramienta es un proyecto educativo y de portafolio. Para uso en producción
con datos críticos, se recomienda complementar con soluciones auditadas
profesionalmente y gestión de claves empresarial (KMS).

## 📄 Licencia

MIT
