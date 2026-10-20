# Gankhi

**Gankhi** reúne en una sola pantalla lo que normalmente se mira por separado: el inventario de programas, las actualizaciones pendientes, las vulnerabilidades conocidas (comparadas en tu equipo con la lista pública de Ubuntu) y el espacio que podés recuperar. Desde ahí también podés actualizar, quitar y limpiar, siempre con una vista previa y tu confirmación. No envía datos de tu computadora a ningún lado.

Un panel local y privado para Linux basado en Ubuntu.

> **Estado: primera versión pública (0.1.0).** Gankhi puede modificar tu sistema: puede actualizar o quitar programas, vaciar la caché de descargas de apt y quitar paquetes sin uso. Cada cambio muestra primero una vista previa y necesita tu confirmación, y no hay botón de deshacer. Solo se probó en Linux basado en Ubuntu 24.04.

[Read in English](README.md)

## Objetivos

- Inventario del software instalado (apt, snap, flatpak, pip y npm; Docker más adelante) con versión, tamaño y fecha de instalación.
- Mostrar qué programas están desactualizados y cuáles tienen vulnerabilidades conocidas.
- Mostrar las descargas pesadas agrupadas por tipo y abrir su carpeta para que puedas revisarlas (capturas de pantalla y duplicados más adelante).
- Liberar espacio en disco con acciones explícitas que siempre muestran una vista previa.
- Funcionar por completo en tu propia máquina, en tu navegador, sin que salgan datos.

## Principios de diseño

- **Primero solo lectura.** Las funciones que solo muestran información van antes que cualquiera que modifique el sistema.
- **Vista previa antes de actuar.** Cada cambio muestra exactamente qué se ve afectado y, cuando apt puede decirlo, cuánto espacio libera.
- **Elementos protegidos.** Los paquetes esenciales del sistema no se pueden quitar desde la interfaz.
- **Tus archivos son tuyos.** Gankhi nunca borra tus archivos: abre su carpeta para que decidas vos. Antes de un cambio de paquetes guarda una copia temporal de la lista como registro (no hay botón de deshacer).
- **Solo local.** La interfaz web escucha únicamente en `127.0.0.1`.
- **Reutilizar, no reinventar.** Gankhi coordina herramientas probadas en lugar de reimplementarlas.

## Hoja de ruta

- [x] Inventario apt de solo lectura
- [x] Estado de actualizaciones y vulnerabilidades
- [x] Panel web (inglés y español)
- [x] Descargas por tipo
- [x] Paquetes de Python (pip) y npm, revisados con las listas públicas de OSV
- [x] Empaquetado (instalador y lanzador de escritorio)
- [ ] Vista de capturas y duplicados
- [ ] Imágenes de Docker
- [x] Acciones de actualización, borrado y limpieza con protecciones (apt)

## Qué descarga Gankhi

Dos tipos de archivos públicos, solo cuando cambiaron y nunca algo sobre tu computadora: la lista
de vulnerabilidades de Ubuntu de Canonical y, solo si tenés paquetes instalados con `pip` o `npm`,
la lista de OSV de ese ecosistema (`osv-vulnerabilities.storage.googleapis.com`). Los nombres y
versiones de lo que tenés instalado se comparan en tu computadora y no se envían a ningún lado.

## Instalar y usar

Desde una copia de este repositorio, sin `sudo` (todo queda dentro de tu carpeta personal):

```
git clone https://github.com/gankhi/gankhi.git
cd gankhi
scripts/install.sh
```

Después abrí **Gankhi** desde el menú de aplicaciones, o ejecutá `gankhi` en una terminal. Se abre en tu navegador y solo acepta conexiones de tu propia computadora. Se cierra con `Ctrl+C` en su terminal. Si tenés más de un navegador instalado, una ventanita pregunta con cuál abrirlo y puede recordar la elección. Con el segundo ícono **Gankhi (elegir navegador)** vuelve a preguntar. Para quitarlo: `scripts/uninstall.sh`.

**La primera vez**, el escritorio puede preguntar si querés ejecutar el ícono de Gankhi. Elegí «Ejecutar» o «Confiar en este lanzador». Lo pregunta una sola vez; después abre directo. (Si no abre, clic derecho sobre el ícono → «Permitir ejecución».)

Cada inicio crea una clave secreta nueva que no se muestra en la terminal: el navegador se abre con ella y se guarda una copia en `~/.cache/gankhi/dashboard-url`, legible solo por vos.

### Formas de abrir Gankhi

| Querés | Hacé esto |
|---|---|
| Abrirlo en tu navegador predeterminado | Doble clic en el ícono **Gankhi**, o elegilo en el menú de aplicaciones. |
| Abrirlo otra vez | Otro clic en el ícono: vuelve a abrir la copia que ya está corriendo. |
| Elegir el navegador | Con más de un navegador instalado, una ventanita pregunta con cuál abrirlo (lista los que encuentra, o te deja elegir un programa de tus archivos) y puede recordar la elección. Para que vuelva a preguntar, o para deshacer una elección recordada, usá el segundo ícono **Gankhi (elegir navegador)** y respondé "Preguntar siempre" (o `gankhi --ask-browser`). No uses "Abrir con" del administrador de archivos sobre el ícono: eso intenta abrir el archivo del lanzador y el navegador solo lo descarga. |
| Usar siempre un navegador, sin la ventanita | En una terminal: `BROWSER=librewolf gankhi` (el comando de tu navegador). |
| Abrirlo a mano | En una terminal: `gankhi --no-open`, y pegá en cualquier navegador la dirección completa guardada en `~/.cache/gankhi/dashboard-url`. |

Escribir solo `127.0.0.1:PUERTO` no funciona, y es a propósito: la dirección lleva una clave secreta que cambia en cada inicio, para que otros programas de tu computadora no puedan leer tus datos. Si una página dice que falta la clave, abrí Gankhi desde el ícono o con alguna de las formas de arriba.

## Requisitos

Linux con apt y Python 3.10 o superior. Desarrollado y probado sobre una base Ubuntu 24.04. Los sistemas previstos son Ubuntu y sus derivadas (Linux Mint, Linux Lite y similares). En Debian puro el inventario, las actualizaciones y la limpieza usan apt y deberían funcionar, pero la revisión de vulnerabilidades no: usa la lista de Ubuntu, que solo cubre versiones de Ubuntu, así que Gankhi la desactiva ahí. No funciona en Windows ni en macOS.

## Notas de desarrollo

Lo que toque el sistema debe estar cubierto por pruebas automáticas y análisis estático; la hoja de ruta muestra lo que existe hoy.

## Licencia

MIT. Ver [LICENSE](LICENSE).
