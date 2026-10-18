# Ganki

Un panel local para Linux que muestra qué hay instalado en tu computadora, qué está desactualizado y qué podés limpiar con seguridad para liberar espacio en disco.

> **Estado: desarrollo inicial (alfa).** Por ahora nada en este repositorio modifica tu sistema. El primer objetivo es un inventario de solo lectura del software instalado.

[Read in English](README.md)

## Objetivos

- Inventario del software instalado (primero apt; después snap, flatpak, pip, npm y Docker) con versión, tamaño y fecha de instalación.
- Mostrar qué programas están desactualizados y cuáles tienen vulnerabilidades conocidas.
- Encontrar descargas pesadas, capturas de pantalla y archivos duplicados, agrupados por tipo.
- Liberar espacio en disco con acciones explícitas y reversibles.
- Funcionar por completo en tu propia máquina, en tu navegador, sin que salgan datos.

## Principios de diseño

- **Primero solo lectura.** Las funciones que solo muestran información van antes que cualquiera que modifique el sistema.
- **Vista previa antes de actuar.** Cada borrado muestra exactamente qué se ve afectado y cuánto espacio libera.
- **Elementos protegidos.** Los paquetes esenciales del sistema no se pueden quitar desde la interfaz.
- **Reversible por defecto.** Los archivos van a la papelera y se guarda la lista de paquetes antes de los cambios.
- **Solo local.** La interfaz web escuchará únicamente en `127.0.0.1`.
- **Reutilizar, no reinventar.** Ganki coordina herramientas probadas en lugar de reimplementarlas.

## Hoja de ruta

- [x] Inventario apt de solo lectura
- [x] Estado de actualizaciones y vulnerabilidades
- [x] Panel web (inglés y español)
- [x] Descargas por tipo
- [x] Paquetes de Python (pip) y npm, revisados con las listas públicas de OSV
- [x] Empaquetado (instalador y lanzador de escritorio)
- [ ] Vista de capturas y duplicados
- [ ] Imágenes de Docker
- [ ] Acciones de borrado y limpieza con protecciones

## Qué descarga Ganki

Dos tipos de archivos públicos, solo cuando cambiaron y nunca algo sobre tu computadora: la lista
de vulnerabilidades de Ubuntu de Canonical y, solo si tenés paquetes instalados con `pip` o `npm`,
la lista de OSV de ese ecosistema (`osv-vulnerabilities.storage.googleapis.com`). Los nombres y
versiones de lo que tenés instalado se comparan en tu computadora y no se envían a ningún lado.

## Instalar y usar

Desde una copia de este repositorio, sin `sudo` (todo queda dentro de tu carpeta personal):

```
scripts/install.sh
```

Después abrí **Ganki** desde el menú de aplicaciones, o ejecutá `ganki` en una terminal. Se abre en tu navegador y solo acepta conexiones de tu propia computadora. Se cierra con `Ctrl+C` en su terminal. Para quitarlo: `scripts/uninstall.sh`.

Cada inicio crea una clave secreta nueva que no se muestra en la terminal: el navegador se abre con ella y se guarda una copia en `~/.cache/ganki/dashboard-url`, legible solo por vos.

### Formas de abrir Ganki

| Querés | Hacé esto |
|---|---|
| Abrirlo en tu navegador predeterminado | Doble clic en el ícono **Ganki**, o elegilo en el menú de aplicaciones. |
| Abrirlo otra vez | Otro clic en el ícono: vuelve a abrir la copia que ya está corriendo. |
| Elegir el navegador | Con más de un navegador instalado, una ventanita pregunta con cuál abrirlo (lista los que encuentra, o te deja elegir un programa de tus archivos) y puede recordar la elección. Para que vuelva a preguntar: clic derecho en el ícono y **Abrir en otro navegador**, o `ganki --ask-browser`. |
| Usar siempre un navegador, sin la ventanita | En una terminal: `BROWSER=librewolf ganki` (el comando de tu navegador). |
| Abrirlo a mano | En una terminal: `ganki --no-open`, y pegá en cualquier navegador la dirección completa guardada en `~/.cache/ganki/dashboard-url`. |

Escribir solo `127.0.0.1:PUERTO` no funciona, y es a propósito: la dirección lleva una clave secreta que cambia en cada inicio, para que otros programas de tu computadora no puedan leer tus datos. Si una página dice que falta la clave, abrí Ganki desde el ícono o con alguna de las formas de arriba.

## Voz natural (opcional)

Ganki puede explicar tu sistema en voz alta. Los navegadores en Linux casi nunca tienen una voz local, así que `scripts/install-voice.sh` (opcional) agrega Piper y una voz en español argentino y una en inglés dentro de `~/.local/share/ganki/voice`. Descarga unos 170 MB una sola vez; después la voz corre en tu computadora y no se envía nada. Sin ella igual tenés los subtítulos. La página solo admite audio que venga de Ganki (`media-src 'self'`).

## Requisitos

Linux basado en Debian/Ubuntu y Python 3.10 o superior. Desarrollado sobre una base Ubuntu 24.04.

## Notas de desarrollo

Lo que toque el sistema debe estar cubierto por pruebas automáticas y análisis estático; la hoja de ruta muestra lo que existe hoy.

## Licencia

MIT. Ver [LICENSE](LICENSE).
