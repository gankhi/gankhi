"""What a notice means for *this* program: the advice changes with what the program does.

A browser, a virtual machine and a Node.js runtime are exposed in different ways, so
"use it with care" is not an answer. Each kind of program gets its own explanation, and the
notices' own wording (code execution, crashes, leaks...) is summarised from the real data.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

# (pattern on the package name, profile). The first one that matches wins.
PROFILES: tuple[tuple[str, str], ...] = (
    (
        r"^(firefox|chromium|google-chrome|brave|vivaldi|opera|librewolf|epiphany|falkon|midori"
        r"|microsoft-edge|waterfox|floorp|tor-?browser|konqueror)",
        "browser",
    ),
    (r"^(virtualbox|qemu|libvirt|vmware|virt-manager|kvm|gnome-boxes)", "virtual"),
    (r"^(nodejs|node|npm|yarn|deno|bun)$", "node"),
    (r"^python3?(\.\d+)?(-minimal)?$|^pypy", "python"),
    (r"^(openjdk|default-j(re|dk)|oracle-java|temurin)", "java"),
    (r"^(php|ruby|perl|lua)\d*(\.\d+)?(-cli|-fpm)?$", "script"),
    (r"^(golang|rustc|cargo|gcc|g\+\+|clang|llvm|dotnet|mono)", "compiler"),
    (
        r"^(apache2|nginx|lighttpd|caddy|openssh-server|sshd|vsftpd|proftpd|samba|smbd|cups"
        r"|bind9|postfix|dovecot|exim4|avahi|openvpn|wireguard)",
        "service",
    ),
    (r"^(mysql|mariadb|postgresql|redis|mongodb|memcached|sqlite3)", "database"),
    (r"^(docker|podman|containerd|runc|lxc|lxd|buildah)", "container"),
    (r"^(openssl|libssl|gnutls|gnupg|gpg|ca-certificates)", "crypto"),
    (
        r"^(libreoffice|evince|okular|vlc|mpv|totem|ffmpeg|imagemagick|graphicsmagick|gimp"
        r"|inkscape|mupdf|poppler|xpdf|calibre|audacity|kodi|shotwell|eog|ghostscript)",
        "documents",
    ),
    (r"^(thunderbird|evolution|geary|pidgin|telegram|signal|discord|slack|zoom|skype)", "messages"),
    (r"^(zip|unzip|p7zip|7zip|unrar|rar|tar|gzip|bzip2|xz-utils|file-roller|ark)", "archives"),
    (r"^(curl|wget|git|rsync|openssh-client|ftp|lftp|aria2|transmission|qbittorrent)", "network"),
    (r"^(vim|neovim|nano|emacs|gedit|kate|code|sublime-text|mousepad)", "editor"),
)

# When the name is not known: what the package says it is, then its distribution section.
DESCRIPTION_PROFILES: tuple[tuple[str, str], ...] = (
    (r"web browser|internet browser", "browser"),
    (r"virtual machine|hypervisor|virtuali[sz]ation|emulator", "virtual"),
    (r"e-?mail (client|program)|mail client|instant messag|chat client|messenger", "messages"),
    (r"container (runtime|engine)|\bcontainers?\b", "container"),
    (r"database|sql server", "database"),
    (r"(web|http|ftp|dns|mail|ssh|file|print) server|daemon|network service", "service"),
    (
        r"\bpdf\b|office suite|word processor|spreadsheet|image (viewer|editor)|photo"
        r"|video (player|editor)|media player|audio (player|editor)|music player|ebook",
        "documents",
    ),
    (r"archiv|compress", "archives"),
    (r"text editor|code editor|\bide\b", "editor"),
    (r"download manager|torrent|bittorrent|http client|ftp client|version control", "network"),
    (r"compiler|debugger|build system", "compiler"),
)
SECTION_PROFILES = {
    "net": "network",
    "mail": "messages",
    "web": "service",
    "graphics": "documents",
    "video": "documents",
    "sound": "documents",
    "doc": "documents",
    "text": "editor",
    "editors": "editor",
    "database": "database",
    "vcs": "network",
    "interpreters": "script",
    "devel": "compiler",
    "javascript": "node",
    "golang": "compiler",
    "rust": "compiler",
    "java": "java",
}

# profile -> language -> (what the exposure is, what to do while there is no fix)
PROFILE_TEXT: dict[str, dict[str, tuple[str, str]]] = {
    "browser": {
        "es": (
            "Un navegador lee contenido de cualquier sitio, así que un fallo puede aprovecharse "
            "con solo visitar una página o ver un anuncio. Es de los programas donde más "
            "importa estar al día.",
            "evitá sitios desconocidos y descargas, no instales extensiones que no necesites y "
            "para lo delicado (banco, correo) usá otro navegador que sí tenga el parche.",
        ),
        "en": (
            "A browser reads content from any website, so a flaw can be used just by visiting "
            "a page or seeing an advert. It is one of the programs where being up to date "
            "matters most.",
            "avoid unknown sites and downloads, do not install extensions you do not need, and "
            "for anything sensitive (bank, mail) use another browser that already has the fix.",
        ),
    },
    "virtual": {
        "es": (
            "Una máquina virtual aísla otro sistema dentro del tuyo. Un fallo puede, en el peor "
            "caso, permitir que lo que corre adentro afecte al equipo real. Pesa sobre todo si "
            "adentro corrés cosas poco confiables (software dudoso, malware para estudiar).",
            "no corras adentro sistemas ni programas de origen dudoso, desactivá las carpetas "
            "y el portapapeles compartidos y dejá la máquina virtual sin red si probás algo "
            "riesgoso.",
        ),
        "en": (
            "A virtual machine isolates another system inside yours. In the worst case a flaw "
            "lets what runs inside affect the real computer. It matters most if you run "
            "untrusted things inside (dubious software, malware you study).",
            "do not run dubious systems or programs inside, turn off shared folders and the "
            "shared clipboard, and keep the virtual machine offline when you test something "
            "risky.",
        ),
    },
    "node": {
        "es": (
            "Node.js ejecuta código JavaScript con los permisos de tu usuario. Un fallo pesa "
            "si corrés scripts o paquetes npm de terceros, o si dejás un servidor Node "
            "accesible desde la red.",
            "ejecutá solo código y paquetes en los que confiás, no expongas servidores Node a "
            "internet sin necesidad y revisá los paquetes npm de tus proyectos (Ganki los "
            "muestra aparte).",
        ),
        "en": (
            "Node.js runs JavaScript with your user's permissions. A flaw matters if you run "
            "third-party scripts or npm packages, or leave a Node server reachable from the "
            "network.",
            "run only code and packages you trust, do not expose Node servers to the internet "
            "without need, and check the npm packages of your projects (Ganki lists them "
            "separately).",
        ),
    },
    "python": {
        "es": (
            "Python ejecuta lo que le des y lee archivos y datos de la red. Un fallo del "
            "intérprete pesa cuando procesás archivos o datos de origen dudoso, o corrés "
            "scripts ajenos.",
            "no ejecutes scripts de desconocidos, no abras con Python archivos comprimidos o "
            "serializados que no sean tuyos y trabajá con entornos virtuales.",
        ),
        "en": (
            "Python runs whatever you give it and reads files and network data. A flaw in the "
            "interpreter matters when you process files or data of doubtful origin, or run "
            "other people's scripts.",
            "do not run scripts from strangers, do not open archives or serialized files "
            "that are not yours with Python, and work in virtual environments.",
        ),
    },
    "java": {
        "es": (
            "Java corre programas (.jar) en tu equipo. El riesgo está en ejecutar programas "
            "de origen dudoso, no en tenerlo instalado.",
            "no abras programas Java que no conozcas y revisá si todavía necesitás tenerlo "
            "(muchas aplicaciones traen su propio Java).",
        ),
        "en": (
            "Java runs (.jar) programs on your computer. The risk is in running programs of "
            "doubtful origin, not in having it installed.",
            "do not open Java programs you do not know, and check whether you still need it "
            "(many applications bring their own Java).",
        ),
    },
    "script": {
        "es": (
            "Es un lenguaje que ejecuta scripts. El riesgo aparece si corrés scripts ajenos o "
            "si lo usás para atender una web.",
            "ejecutá solo scripts de confianza y, si lo usás en un sitio web, no lo dejes "
            "expuesto sin necesidad.",
        ),
        "en": (
            "It is a language that runs scripts. The risk appears if you run other people's "
            "scripts or use it to serve a website.",
            "run only trusted scripts and, if it serves a website, do not leave it exposed "
            "without need.",
        ),
    },
    "compiler": {
        "es": (
            "Es una herramienta de desarrollo: transforma código en programas. Pesa si "
            "compilás código ajeno, no por el uso cotidiano de tu equipo.",
            "compilá solo código de fuentes de confianza.",
        ),
        "en": (
            "It is a development tool: it turns code into programs. It matters if you build "
            "other people's code, not for everyday use of the computer.",
            "build code only from sources you trust.",
        ),
    },
    "service": {
        "es": (
            "Es un servicio que escucha conexiones de la red: un fallo puede alcanzarse desde "
            "afuera, sin que hagas nada. Si no lo usás, tenerlo instalado es riesgo sin "
            "beneficio.",
            "si no lo necesitás, quitalo o apagalo; si lo necesitás, no lo expongas a "
            "internet y cerrá su puerto en el firewall.",
        ),
        "en": (
            "It is a service that listens for network connections: a flaw can be reached from "
            "outside without you doing anything. If you do not use it, keeping it installed "
            "is risk with no benefit.",
            "if you do not need it, remove or stop it; if you do, do not expose it to the "
            "internet and close its port in the firewall.",
        ),
    },
    "database": {
        "es": (
            "Guarda datos y suele atender conexiones. El peligro mayor es que sea accesible "
            "desde la red o por programas poco confiables.",
            "verificá que escuche solo en tu propio equipo (127.0.0.1) y que no use "
            "contraseñas por defecto.",
        ),
        "en": (
            "It stores data and usually accepts connections. The main danger is it being "
            "reachable from the network or by untrusted programs.",
            "check that it listens only on your own computer (127.0.0.1) and does not use "
            "default passwords.",
        ),
    },
    "container": {
        "es": (
            "Quien usa contenedores tiene un poder casi total sobre el equipo, y un fallo "
            "puede dejar que lo de adentro salga de su aislamiento.",
            "no corras imágenes de origen dudoso, ni con --privileged, ni montes carpetas "
            "importantes de tu equipo adentro.",
        ),
        "en": (
            "Whoever uses containers has almost total power over the machine, and a flaw can "
            "let what is inside escape its isolation.",
            "do not run images of doubtful origin, nor with --privileged, nor mount "
            "important folders of your computer inside.",
        ),
    },
    "crypto": {
        "es": (
            "Es la pieza que cifra las conexiones de muchos programas (sitios seguros, correo, "
            "SSH). Un fallo puede debilitar ese cifrado o romper esos programas.",
            "no se puede evitar usándolo distinto: mientras tanto, no hagas operaciones "
            "sensibles (banco, claves) desde redes públicas.",
        ),
        "en": (
            "It is the piece that encrypts the connections of many programs (secure sites, "
            "mail, SSH). A flaw can weaken that encryption or break those programs.",
            "you cannot avoid it by using it differently: meanwhile, do not do sensitive "
            "things (bank, passwords) on public networks.",
        ),
    },
    "documents": {
        "es": (
            "Abre archivos que vienen de afuera (documentos, imágenes, audio, video). Un "
            "archivo armado a propósito puede aprovechar el fallo al abrirlo.",
            "no abras con él archivos de desconocidos ni descargados de sitios dudosos.",
        ),
        "en": (
            "It opens files that come from outside (documents, images, audio, video). A file "
            "crafted on purpose can exploit the flaw when opened.",
            "do not open files from strangers or from dubious sites with it.",
        ),
    },
    "messages": {
        "es": (
            "Recibe contenido de terceros (mensajes, adjuntos, enlaces). Un mensaje armado "
            "puede aprovechar el fallo.",
            "no abras adjuntos ni enlaces de remitentes desconocidos y desactivá la carga "
            "automática de imágenes remotas.",
        ),
        "en": (
            "It receives content from third parties (messages, attachments, links). A crafted "
            "message can exploit the flaw.",
            "do not open attachments or links from unknown senders and turn off automatic "
            "loading of remote images.",
        ),
    },
    "archives": {
        "es": (
            "Abre paquetes comprimidos. Un archivo armado a propósito puede aprovechar el "
            "fallo al descomprimirlo.",
            "no descomprimas archivos de desconocidos y no lo hagas como administrador.",
        ),
        "en": (
            "It opens compressed archives. A file crafted on purpose can exploit the flaw "
            "when extracted.",
            "do not extract archives from strangers and do not do it as administrator.",
        ),
    },
    "network": {
        "es": (
            "Se conecta a los servidores o repositorios que vos le indicás. El riesgo aparece "
            "al hablar con servidores que no controlás.",
            "usalo solo con direcciones y repositorios de confianza.",
        ),
        "en": (
            "It connects to the servers or repositories you point it to. The risk appears "
            "when talking to servers you do not control.",
            "use it only with addresses and repositories you trust.",
        ),
    },
    "editor": {
        "es": (
            "Un editor suele fallar al abrir un archivo con contenido armado a propósito.",
            "no abras con él archivos de origen dudoso.",
        ),
        "en": (
            "An editor usually fails when opening a file with content crafted on purpose.",
            "do not open files of doubtful origin with it.",
        ),
    },
    # pip / npm packages: libraries used by your own projects
    "pip": {
        "es": (
            "Es una librería de Python que usan tus propios proyectos. El riesgo depende de "
            "dónde corre: un servicio expuesto o un script que procesa datos ajenos pesan más "
            "que una herramienta que usás vos solo.",
            "no la actualices a ciegas: probá tu proyecto y, si procesa datos de terceros, "
            "validalos antes.",
        ),
        "en": (
            "It is a Python library used by your own projects. The risk depends on where it "
            "runs: an exposed service or a script that processes other people's data matters "
            "more than a tool only you use.",
            "do not update blindly: test your project and, if it processes third-party data, "
            "validate it first.",
        ),
    },
    "npm": {
        "es": (
            "Es un paquete de JavaScript que usan tus propios proyectos. El riesgo depende de "
            "dónde corre: en un servidor web o en el navegador de otras personas pesa más que "
            "en una herramienta de desarrollo que usás vos solo.",
            "no lo actualices a ciegas: probá tu proyecto y revisá qué cambia entre versiones.",
        ),
        "en": (
            "It is a JavaScript package used by your own projects. The risk depends on where "
            "it runs: on a web server or in other people's browsers matters more than in a "
            "development tool only you use.",
            "do not update blindly: test your project and check what changes between versions.",
        ),
    },
}

TAILS = {
    "es": {
        "fixed": (
            "Apretá Actualizar en esta fila. Algunas actualizaciones recién se aplican al "
            "cerrar y volver a abrir el programa, o al reiniciar."
        ),
        "no_fix": (
            "Mientras no haya parche: {todo}. Ganki vuelve a revisar en cada análisis y la "
            "etiqueta desaparece sola cuando se publique un arreglo."
        ),
        "eol": (
            "Esta versión ya no recibe arreglos de sus autores: buscá una más nueva o una "
            "alternativa. Si tenés que conservarla: {todo}."
        ),
        "malware": (
            "Este paquete se conoce como malicioso. No lo ejecutes y quitalo ahora. Si ya lo "
            "usaste, cambiá las contraseñas y claves que escribiste o guardaste en esta "
            "computadora y revisá si hay algo que no instalaste vos."
        ),
        "ext_fix": (
            "Actualizalo donde lo uses y corré las pruebas de tu proyecto: cambiar la versión "
            "puede romper algo que dependa de la anterior. Ganki muestra el comando; no "
            "modifica tus proyectos."
        ),
        "ext_no_fix": ("Todavía no hay arreglo: {todo}. Ganki vuelve a revisar en cada análisis."),
        "data": "Qué dicen los avisos: {kinds}. La prioridad más alta es {priority}.",
        "data_more": "Se muestran los primeros {shown} de {total} avisos.",
        "how": "Cómo se aprovecha, según los avisos: {needs}. Por eso: {todo}.",
        "how_unknown": (
            "Los avisos no detallan en qué condiciones se aprovecha, así que va una precaución "
            "general: {todo}."
        ),
        "recheck": "Ganki vuelve a revisar en cada análisis y la etiqueta desaparece sola cuando "
        "se publique un arreglo.",
        "eol_short": "Esta versión ya no recibe arreglos de sus autores: buscá una más nueva o "
        "una alternativa.",
        "update_available": "Hay una versión nueva disponible ({version}): actualizá con el botón.",
        "update_missing": "Tu sistema todavía no ofrece una versión más nueva: no hay nada que "
        "actualizar por ahora.",
    },
    "en": {
        "fixed": (
            "Press Update on this row. Some updates only take effect after you close and "
            "reopen the program, or after a restart."
        ),
        "no_fix": (
            "While there is no patch: {todo}. Ganki checks again on every scan and the label "
            "disappears by itself once a fix is published."
        ),
        "eol": (
            "This version no longer gets fixes from its authors: look for a newer one or an "
            "alternative. If you must keep it: {todo}."
        ),
        "malware": (
            "This package is known to be malicious. Do not run it and remove it now. If you "
            "have already used it, change the passwords and keys you typed or stored on this "
            "computer and check for anything you did not install."
        ),
        "ext_fix": (
            "Update it where you use it and run your project's tests: changing the version "
            "can break something that depends on the old one. Ganki shows the command; it "
            "does not change your projects."
        ),
        "ext_no_fix": "There is no fix yet: {todo}. Ganki checks again on every scan.",
        "data": "What the notices say: {kinds}. The highest priority is {priority}.",
        "data_more": "The first {shown} of {total} notices are shown.",
        "how": "How it can be used, according to the notices: {needs}. So: {todo}.",
        "how_unknown": (
            "The notices do not say under which conditions it can be used, so here is a "
            "general precaution: {todo}."
        ),
        "recheck": "Ganki checks again on every scan and the label disappears by itself once "
        "a fix is published.",
        "eol_short": "This version no longer gets fixes from its authors: look for a newer "
        "one or an alternative.",
        "update_available": "A newer version is available ({version}): update with the button.",
        "update_missing": "Your system does not offer a newer version yet: there is nothing "
        "to update for now.",
    },
}

# What the notices talk about, found in their own wording.
KINDS: tuple[tuple[str, str, dict[str, str]], ...] = (
    (
        "code",
        r"arbitrary code|code execution|execute (arbitrary|code|commands)|command injection",
        {"es": "ejecución de código ajeno", "en": "running someone else's code"},
    ),
    (
        "memory",
        r"buffer overflow|out-of-bounds|use-after-free|heap|memory corruption|overflow",
        {"es": "errores de memoria", "en": "memory errors"},
    ),
    (
        "dos",
        r"denial of service|crash|infinite loop|exhaust|\\bhang\\b|resource consumption",
        {"es": "caídas o bloqueos", "en": "crashes or freezes"},
    ),
    (
        "leak",
        r"information disclosure|disclos|leak|expos|read (arbitrary|sensitive)|obtain "
        r"sensitive",
        {"es": "filtración de información", "en": "information leaks"},
    ),
    (
        "privilege",
        r"privilege|escalat|sandbox escape|root access",
        {"es": "obtener más permisos", "en": "gaining more permissions"},
    ),
    (
        "web",
        r"cross-site|xss|script injection|spoof|phishing|redirect|csrf",
        {"es": "falsificación o inyección en páginas web", "en": "web spoofing or injection"},
    ),
)


# How a problem can be reached, found in the notices' own wording: (key, pattern,
# what it needs, what to do about exactly that) in each language.
CONDITIONS: tuple[tuple[str, str, dict[str, tuple[str, str]]], ...] = (
    (
        "guest",
        r"\bguest\b",
        {
            "es": (
                "hay que estar adentro de la máquina virtual",
                "solo importa si lo que corre adentro es hostil o fue comprometido: limitá lo "
                "que ejecutás adentro y apagá el portapapeles, el arrastrar y las carpetas "
                "compartidas",
            ),
            "en": (
                "the attacker has to be inside the virtual machine",
                "it only matters if what runs inside is hostile or compromised: limit what "
                "you run inside and turn off the shared clipboard, drag and drop and shared "
                "folders",
            ),
        },
    ),
    (
        "local",
        r"logon to the infrastructure|local (user|attacker|access)|locally|low[- ]privileged"
        r"|physical access",
        {
            "es": (
                "hace falta tener acceso a una cuenta de tu equipo",
                "que nadie más use tu usuario o tu sesión y no ejecutes programas de origen "
                "dudoso con tu usuario",
            ),
            "en": (
                "access to an account on your computer is needed",
                "do not let anyone else use your user or session and do not run programs of "
                "doubtful origin as your user",
            ),
        },
    ),
    (
        "network",
        r"remote attacker|over the network|network access|remotely|via (http|https|tcp|udp)"
        r"|network protocol",
        {
            "es": (
                "los avisos mencionan acceso por red",
                "no dejes el servicio accesible desde redes que no controlás (red NAT, firewall)",
            ),
            "en": (
                "the notices mention network access",
                "do not leave the service reachable from networks you do not control (NAT "
                "network, firewall)",
            ),
        },
    ),
    (
        "file",
        r"crafted (file|document|image|archive|input|request)|malicious (file|document|web)"
        r"|user interaction|tricks? a user",
        {
            "es": (
                "hace falta abrir un archivo o contenido armado a propósito",
                "no abras con este programa archivos de origen dudoso",
            ),
            "en": (
                "a file or content crafted on purpose has to be opened",
                "do not open files of doubtful origin with this program",
            ),
        },
    ),
)


def profile_for(
    name: str, ecosystem: str = "", description: str = "", section: str = ""
) -> str | None:
    """The kind of program something is: by name, else by what it says it is, else its section.

    pip and npm packages are told apart by their tool.
    """
    if ecosystem in ("pip", "npm"):
        return ecosystem
    base = name.split(":")[0].lower()
    for pattern, profile in PROFILES:
        if re.search(pattern, base):
            return profile
    lowered = description.lower()
    for pattern, profile in DESCRIPTION_PROFILES:
        if re.search(pattern, lowered):
            return profile
    return SECTION_PROFILES.get(section.split("/")[-1].lower())


def notice_kinds(summaries: list[str], lang: str) -> list[str]:
    """Plain-language kinds of problem found in the notices' own text, most common first."""
    counts: dict[str, int] = {}
    labels: dict[str, str] = {}
    for text in summaries:
        lowered = text.lower()
        for key, pattern, names in KINDS:
            if re.search(pattern, lowered):
                counts[key] = counts.get(key, 0) + 1
                labels[key] = names[lang]
    return [labels[key] for key in sorted(counts, key=lambda k: (-counts[k], k))]


def conditions(summaries: list[str], lang: str) -> list[tuple[str, str]]:
    """(what it needs, what to do) for each way the notices say the problem is reached."""
    joined = " ".join(summaries).lower()
    return [texts[lang] for _key, pattern, texts in CONDITIONS if re.search(pattern, joined)]


def paragraphs(
    tool: Any, kind: str, lang: str, priority_name: Callable[[str], str], generic: str
) -> list[str]:
    """The paragraphs that explain a label for this program.

    ``kind`` is fixed, no_fix, eol, malware, ext_fix or ext_no_fix. ``generic`` is the general
    advice used when the program is not a recognised kind.
    """
    lang = lang if lang in TAILS else "en"
    texts = TAILS[lang]
    result: list[str] = []

    cves = list(getattr(tool, "cves", ()) or ())
    kinds = notice_kinds([c.summary for c in cves], lang)
    if kinds and kind not in ("malware",):
        priority = priority_name(getattr(tool, "top_priority", "") or "")
        line = texts["data"].format(kinds=", ".join(kinds[:3]), priority=priority)
        total = getattr(tool, "cve_count", len(cves))
        if total > len(cves):
            line += " " + texts["data_more"].format(shown=len(cves), total=total)
        result.append(line)

    if not kind.startswith("ext_") and kind != "malware":
        newer = getattr(tool, "update_to", None)
        if newer:
            result.append(texts["update_available"].format(version=newer))
        elif kind in ("no_fix", "eol"):
            result.append(texts["update_missing"])

    profile = profile_for(
        getattr(tool, "name", ""),
        getattr(tool, "tool", ""),
        getattr(tool, "description", ""),
        getattr(tool, "section", ""),
    )
    if kind == "malware":
        result.append(texts["malware"])
    elif profile is None:
        # A program Ganki does not know by name: still use what its own notices say.
        reached = conditions([c.summary for c in cves], lang) if kind in ("no_fix", "eol") else []
        if reached:
            needs = "; ".join(need for need, _action in reached)
            actions = "; ".join(action for _need, action in reached)
            result.append(texts["how"].format(needs=needs, todo=actions))
            result.append(texts["eol_short" if kind == "eol" else "recheck"])
        else:
            result.append(generic)
    else:
        risk, todo = PROFILE_TEXT[profile][lang]
        result.append(risk)
        reached = conditions([c.summary for c in cves], lang) if kind in ("no_fix", "eol") else []
        if reached:
            needs = "; ".join(need for need, _action in reached)
            actions = "; ".join(action for _need, action in reached)
            result.append(texts["how"].format(needs=needs, todo=actions))
            result.append(texts["eol_short" if kind == "eol" else "recheck"])
        elif cves and kind in ("no_fix", "eol", "ext_no_fix"):
            result.append(texts["how_unknown"].format(todo=todo.rstrip(".")))
        else:
            result.append(texts[kind].format(todo=todo.rstrip(".")))
    return result


SANDBOXED_TEXT = {
    "es": {
        "snap": (
            "Esta app es un snap: trae sus propias bibliotecas adentro, y Ubuntu no publica "
            "avisos de seguridad por cada snap. Por eso Ganki no puede decirte si tiene fallos "
            'conocidos, y no te muestra un "al día" que no pueda comprobar. Lo que sí se '
            "sabe: snap revisa y actualiza sus apps solo, varias veces por día. Para forzarlo: "
            "sudo snap refresh."
        ),
        "flatpak": (
            "Esta app es un Flatpak: trae sus propias bibliotecas adentro, y no hay una lista "
            "de avisos de seguridad por cada Flatpak. Por eso Ganki no puede decirte si tiene "
            "fallos conocidos. A diferencia de snap, Flatpak no se actualiza solo: actualizalo "
            "desde el centro de software o con flatpak update."
        ),
        "unknown": (
            "Ganki no reconoce qué tipo de programa es, así que no puede darte una explicación "
            "más específica."
        ),
    },
    "en": {
        "snap": (
            "This app is a snap: it carries its own libraries, and Ubuntu does not publish "
            "security notices for each snap. So Ganki cannot tell you whether it has known "
            'flaws, and it does not show an "up to date" it cannot verify. What is known: '
            "snap checks and updates its apps by itself, several times a day. To force it: "
            "sudo snap refresh."
        ),
        "flatpak": (
            "This app is a Flatpak: it carries its own libraries, and there is no list of "
            "security notices for each Flatpak. So Ganki cannot tell you whether it has known "
            "flaws. Unlike snap, Flatpak does not update by itself: update it from the "
            "software centre or with flatpak update."
        ),
        "unknown": (
            "Ganki does not recognise what kind of program this is, so it cannot give a more "
            "specific explanation."
        ),
    },
}


def sandboxed_paragraphs(app: Any, lang: str) -> list[str]:
    """How Ganki treated a snap or Flatpak app, and what the person can do about it."""
    lang = lang if lang in SANDBOXED_TEXT else "en"
    texts = SANDBOXED_TEXT[lang]
    result = [texts["flatpak" if getattr(app, "tool", "") == "flatpak" else "snap"]]
    profile = profile_for(getattr(app, "name", ""))
    if profile is None:
        result.append(texts["unknown"])
    else:
        result.append(PROFILE_TEXT[profile][lang][0])
    return result
