# Reporte de Seguridad FixGuard

**Objetivo:** `https://balbuenabarber.vercel.app/`
**Fecha de Escaneo:** 6/12/2026, 3:54:09 PM
**Modo:** AGGRESSIVE
**Estado:** COMPLETED

---

## Inteligencia del Objetivo (Recon)

### Stack Tecnológico Detectado
- Vercel
- Next.js

### Subdominios Descubiertos

---

## Vulnerabilidades de Código (SAST)

### [MEDIUM] MISSING_HEADER_CONTENT_SECURITY_POLICY
La cabecera de seguridad 'content-security-policy' no está configurada en la respuesta HTTP del servidor.

### [LOW] MISSING_SECURITY_TXT
No se encontró un archivo 'security.txt' válido en /.well-known/security.txt. (Estándar RFC 9116). Esto dificulta que investigadores éticos reporten vulnerabilidades de forma segura a la empresa.

### [MEDIUM] MISSING_HEADER_X_FRAME_OPTIONS
La cabecera de seguridad 'x-frame-options' no está configurada en la respuesta HTTP del servidor.

### [MEDIUM] MISSING_HEADER_X_CONTENT_TYPE_OPTIONS
La cabecera de seguridad 'x-content-type-options' no está configurada en la respuesta HTTP del servidor.

### [LOW] MISSING_WAF_PROTECTION
No se detectó un Web Application Firewall (WAF) activo (como Cloudflare o AWS WAF). El servidor está directamente expuesto a ataques de Denegación de Servicio (DDoS) y ataques de fuerza bruta masivos.

### [MEDIUM] MISSING_HEADER_PERMISSIONS_POLICY
La cabecera de seguridad 'permissions-policy' no está configurada en la respuesta HTTP del servidor.

### [MEDIUM] MISSING_HEADER_REFERRER_POLICY
La cabecera de seguridad 'referrer-policy' no está configurada en la respuesta HTTP del servidor.

### [LOW] SERVER_HEADER_LEAK
El servidor está exponiendo su versión exacta en la cabecera 'Server': Vercel. Esto facilita a los atacantes buscar vulnerabilidades conocidas.

---

*Reporte generado automáticamente por FixGuard Personal Arsenal Edition.*