# Cambios

Los cambios importantes de Ganki. Las fechas van como año-mes-día.

## 0.1.0 (2026-10-18)

Primera versión pública.

### Qué hace
- Lista los programas instalados con apt y los compara con la lista pública de seguridad
  de Ubuntu, en tu propia computadora. Nada de tus programas se envía a ningún lado.
- Revisa los paquetes de Python (pip) y de Node (npm) con las listas públicas de OSV. Las
  listas se descargan solo si tenés paquetes instalados con esas herramientas.
- Lista las apps de snap y flatpak. No las revisa: traen sus propias librerías.
- Muestra disco, memoria y actualizaciones, y estima cuánto podés recuperar (kernels
  viejos, caché de apt, paquetes huérfanos, Descargas).
- Explica el resultado en voz alta, en español y en inglés, con una voz local (opcional).
- Genera un informe en PDF, con colores por prioridad y agrupado por familia.
- Actualiza o quita un programa solo después de una vista previa y de tu confirmación
  explícita. La contraseña la pide la ventana del propio sistema, nunca Ganki.

### Seguro por diseño
- Escucha solo en `127.0.0.1`, con una clave de acceso al azar.
- Ejecuta solo una lista fija de comandos de lectura. Los que cambian el sistema están
  escritos de forma exacta y no se acepta nada más.
- Sin cuentas, sin estadísticas, sin recursos externos en la página.

### Instalación
- `scripts/install.sh` instala Ganki sin sudo.
- `scripts/install-voice.sh` (opcional) agrega las voces en español e inglés, unos 170 MB.
