# Cambios

Los cambios importantes de Gankhi. Las fechas van como año-mes-día.

## Sin publicar

### Agregado
- Los programas que vienen de afuera de Ubuntu (otro repositorio de apt, un archivo `.deb`, snap, flatpak) se muestran como «Sin revisar» en vez de «al día», con su propio filtro, un tramo en el anillo del resumen, una sección en la página y en el informe PDF, y una frase del asistente.
- Un paquete con una versión más nueva que no corrige sus vulnerabilidades ya no muestra «Sin arreglo» junto a un botón Actualizar resaltado: dice «Hay una versión más nueva, pero todavía no corrige estas vulnerabilidades» y el botón no se resalta. Cuando no hay nada para actualizar, el botón Actualizar ya no se muestra (antes aparecía deshabilitado).
- Un paquete de Ubuntu que solo está desactualizado (hay una versión más nueva) ya no se toma por un archivo `.deb` suelto: apt deja de listar la versión instalada en cualquier repositorio, y Gankhi ahora usa de dónde viene la versión nueva. Esos paquetes vuelven a revisarse con los avisos de Ubuntu, y uno de otro repositorio muestra ese repositorio.
- Un botón en la sección «Sin revisar» copia la lista con una consulta estricta para pegar en la IA que elijas. Pide solo una tabla de 3 columnas (programa, si tu versión es vulnerable con enlaces a los CVE, comando para actualizar) y, debajo, el comando para eliminar los vulnerables, sin explicaciones de más. Le indica que busque en la web en lugar de responder de memoria y que escriba «Aún no reportado» en vez de «No», para que no se confunda la falta de respuesta con un programa seguro. Debe buscar cada programa uno por uno y no llenar toda la columna con la misma respuesta. Gankhi no envía nada.
- La sección «Sin revisar» lista solo lo que Gankhi no puede actualizar por vos (snap y flatpak). Los programas de otros repositorios de apt o archivos `.deb` ya están en la lista de herramientas con la opción de actualizar, así que la sección solo remite a ellos El texto para copiar a una IA los sigue listando, porque poder actualizar un programa no dice si tiene vulnerabilidades, y ahora también pide el comando para eliminarlo.
- La sección de Python y npm lista todos los paquetes (los que no tienen avisos quedan plegados), en la página y en el informe PDF.
- El asistente y el encabezado cuentan lo mismo: programas del sistema más paquetes de Python y npm.
- La vista previa y las páginas de detalle de descargas tienen selector ES/EN.
- Cada parte del anillo de programas (al día, desactualizados, con vulnerabilidades, sin revisar) abre su propia lista.
- Los títulos de las columnas quedan a la vista mientras bajás por la página (en pantallas lo bastante anchas para que las tablas entren).
- Mientras corre un cambio, un aviso claro de «trabajando»; al terminar, un aviso de «terminó» y la salida plegada.

### Cambiado
- Un paquete que viene de otro repositorio ya no se compara con los avisos de Ubuntu, que son sobre las compilaciones propias de Ubuntu.
- Límite conocido: los repositorios que reutilizan el nombre de versión de Ubuntu (Docker, PPA) no se distinguen.

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
