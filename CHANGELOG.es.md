# Cambios

Los cambios importantes de Gankhi. Las fechas van como año-mes-día.

## 0.1.0 (2026-10-20)

Primera versión pública. (Durante el desarrollo el proyecto se llamaba Ganki; el instalador pasa una copia vieja al nombre nuevo y conserva sus ajustes.)

### Qué hace
- Lista los programas instalados con apt y los compara con la lista pública de seguridad
  de Ubuntu, en tu propia computadora. Nada de tus programas se envía a ningún lado.
- Revisa los paquetes de Python (pip) y de Node (npm) con las listas públicas de OSV. Las
  listas se descargan solo si tenés paquetes instalados con esas herramientas.
- Lista las apps de snap y flatpak. No las revisa: traen sus propias librerías.
- Muestra disco, memoria y actualizaciones, y estima cuánto podés recuperar (kernels
  viejos, caché de apt, paquetes huérfanos, Descargas).
- Explica el resultado por escrito, sección por sección, en español y en inglés.
- Genera un informe en PDF, con colores por prioridad y agrupado por familia.
- Actualiza o quita un programa, vacía la caché de descargas de apt y quita paquetes sin
  uso (kernels viejos, huérfanos) solo después de una vista previa y de tu confirmación
  explícita. La contraseña la pide la ventana del propio sistema, nunca Gankhi. Gankhi se
  niega a un cambio que quitaría software del que depende el sistema.
- Abre la carpeta de una descarga pesada para que mires el archivo y lo borres vos.
  Gankhi nunca borra tus archivos.
- Pone primero lo que más importa: las actualizaciones que arreglan avisos críticos o
  altos, y las de seguridad de Ubuntu, van antes que el resto.

### Seguro por diseño
- Escucha solo en `127.0.0.1`, con una clave de acceso al azar.
- Ejecuta solo una lista fija de comandos de lectura. Los que cambian el sistema están
  escritos de forma exacta y no se acepta nada más.
- Sin cuentas, sin estadísticas, sin recursos externos en la página.

### Límites conocidos
- Solo Linux (Ubuntu y derivadas; en Debian puro no hay revisión de vulnerabilidades). Probado sobre una base Ubuntu 24.04.
- No hay botón de deshacer. Antes de un cambio se guarda una copia temporal de la lista
  de paquetes, como registro; volver atrás implica reinstalar a mano.
- Los comandos de actualizar y quitar que se muestran para las apps de snap y flatpak son
  para copiar y ejecutar vos; no se ejercitaron en las pruebas automáticas.
- Cerrar la ventana de terminal que se abre con Gankhi lo detiene.

### Instalación
- `scripts/install.sh` instala Gankhi sin sudo.
