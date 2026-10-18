"""Interface texts in Spanish and English."""

from __future__ import annotations

LANGUAGES = ("es", "en")
DEFAULT_LANGUAGE = "en"

TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "title": "System summary",
        "scanning": "Scanning this machine... this can take a minute.",
        "rescan": "Scan again",
        "error": "The scan could not finish. Details are in the terminal of Ganki.",
        "unsupported": "This system is not supported: vulnerability data covers Ubuntu releases.",
        "reboot": "A restart is needed to use the updated kernel.",
        "uptime": "on for {time}",
        "last_scan": "Last scan",
        "feed": "Vulnerability data",
        "feed_new": "downloaded just now",
        "feed_cached": "already up to date",
        "disk": "Disk",
        "disk_detail": "{used} used, {free} free of {total}",
        "ram": "Memory (RAM)",
        "ram_detail": "{used} in use, {free} free",
        "programs": "Programs up to date",
        "programs_detail": "{vuln} with vulnerabilities, {old} outdated",
        "reclaim": "Recoverable space",
        "reclaim_hint": "Review before cleaning. Nothing is removed from here yet.",
        "reclaim_kernels": "Old kernels",
        "reclaim_cache": "apt cache",
        "reclaim_orphans": "Orphan packages",
        "kernel": "Kernel in use",
        "kernel_cves": "{n} known vulnerabilities, fixed in {fixed}.",
        "tools": "Installed tools",
        "tools_hint": "Sorted by state: what needs attention comes first.",
        "search": "Search tool",
        "f_all": "All",
        "f_outdated": "Outdated",
        "f_vulnerable": "With vulnerabilities",
        "show_all": "Include libraries and dependencies",
        "apply": "Apply",
        "col_tool": "Tool",
        "col_version": "Version",
        "col_size": "Size",
        "col_state": "State",
        "state_ok": "Up to date",
        "state_outdated": "Outdated",
        "state_vulnerable": "Vulnerability",
        "cve_summary": "CVE: {n}",
        "fixed_in": "Fixed in {version}",
        "cve_split": "{fixed} fixed in {version} · {open} with no fix yet",
        "no_fix_yet": "no fix published yet",
        "hint_fixed": "Fixed in {version} with the distribution's patch. Update to resolve it.",
        "tag_fixed": "Fix available",
        "tag_no_fix": "No fix yet",
        "tag_eol": "No support",
        "tag_malware": "Malicious",
        "tag_how": "How Ganki checks it",
        "sbx_how_hint": "It is not compared with vulnerability lists.",
        "more_fixed": (
            "What to keep in mind: the fix is already in your system's own sources, so you need "
            "nothing from outside. Press Update on this row. Some updates only take effect after "
            "you close and reopen the program, or after a restart (the system core, the browser). "
            "Until then, avoid opening files from unknown sources with it."
        ),
        "more_no_fix": (
            "What to keep in mind: no patch exists yet. That does not mean someone is attacking "
            "you; many of these notices are low priority and the distribution has not fixed them, "
            "or has decided not to. Use this program only with files and sites you trust. If you "
            "do not use it, remove it. Ganki checks again on every scan, so the label disappears "
            "by itself once a fix is published."
        ),
        "more_eol": (
            "What to keep in mind: this version no longer receives fixes from its authors, so new "
            "problems will not be corrected. Look for a newer version or an alternative. If you "
            "must keep it, do not use it with untrusted files or on the internet. Ubuntu Pro can "
            "extend fixes for some packages."
        ),
        "more_malware": (
            "What to keep in mind: this package is known to be malicious. Do not run it. Remove "
            "it now. If you have already used it, change the passwords and keys you typed or "
            "stored on this computer, and check for anything you did not install."
        ),
        "more_ext_fix": (
            "What to keep in mind: updating changes the package's version, and your own projects "
            "may depend on the old one. Update it where you use it and run your project's tests. "
            "Ganki shows the command; it does not change your projects."
        ),
        "hint_no_fix": "There is no patch published for this yet.",
        "hint_some_no_fix": "{n} notices have no patch yet, even after updating.",
        "hint_fixed_part": (
            "Updating to {version} fixes {n} notices. The other {m} stay open because no patch "
            "exists for them yet."
        ),
        "hint_eol": (
            "Its authors no longer publish fixes for this version. Ubuntu may still provide "
            "them, but only with Ubuntu Pro. Move to a supported version when you can."
        ),
        "chip_eol": "Project out of support",
        "col_actions": "Actions",
        "btn_update": "Update",
        "btn_remove": "Remove",
        "btn_update_all": "Update everything",
        "protected": "Protected",
        "protected_hint": "The system depends on it, so Ganki never offers to remove it.",
        "back": "Back",
        "copy": "Copy commands",
        "copied": "Copied",
        "prev_title_update": "Preview before updating {name}",
        "prev_title_remove": "Preview before removing {name}",
        "prev_title_all": "Preview before updating everything",
        "prev_summary": "{up} updated, {new} new, {gone} removed.",
        "prev_download": "Download: {size}",
        "prev_uses": "Uses {size} more disk space",
        "prev_frees": "Frees {size}",
        "prev_list_up": "Would be updated",
        "prev_list_new": "Would be installed",
        "prev_list_gone": "Would be removed",
        "prev_simulation": "Simulation (nothing is changed)",
        "prev_run_title": "Or do it yourself",
        "prev_run_note": (
            "To do it from a terminal instead, copy these two lines: "
            "the first saves your list of programs so you can undo, the second does it."
        ),
        "prev_reboot": "If a new kernel is installed, restart the computer afterwards.",
        "blocked_unknown": "That program is not in the list, so there is nothing to preview.",
        "blocked_protected": "The system needs this program, so Ganki will not remove it.",
        "blocked_drags_protected": "Removing it would also remove software the system depends on.",
        "blocked_failed": "The simulation could not run. Try again after scanning.",
        "everything": "everything",
        "sure_title": "Are you sure you want to continue with {name}?",
        "info_remove": "Removing a program does not delete your documents or personal files.",
        "warn_drags": "{n} more package(s) will also be removed.",
        "warn_data": (
            "{name} may look after data of its own (databases, containers). Back it up first."
        ),
        "warn_reboot": "A new kernel will be installed: restart the computer afterwards.",
        "warn_big": "This is a big download and needs free disk space. Check the numbers above.",
        "understood": "I read the warnings and want to continue.",
        "password_note": (
            "The system's own window asks for your password, never Ganki. It is the password of "
            "your user account, the same one you type with sudo or to log in. The account has "
            "to be an administrator and have a password; if it does not, the system will refuse "
            "and nothing changes: use the command shown below instead. "
            "Your list of programs is saved first, so the change can be undone."
        ),
        "confirm_remove": "Yes, remove {name}",
        "confirm_update": "Yes, update {name}",
        "confirm_all": "Yes, update everything",
        "cancel": "Cancel",
        "run_waiting": "Waiting for you to type your password in the system window...",
        "run_ok": "Done. Scanning again to refresh the numbers.",
        "run_failed": "It did not finish. Read the output above; nothing else was changed.",
        "run_refused": "Ganki refused to run this. Reload the preview and try again.",
        "run_saved": "List of programs saved in",
        "say_scanning": ("We are analysing your system. This can take a few minutes, please wait."),
        "say_intro": "I have just analysed your system.",
        "say_system": (
            "You are running {os}, with the user {user}. The computer has been on for {uptime}."
        ),
        "say_reboot": "It needs a restart to use the updated kernel.",
        "say_disk_ok": (
            "The disk is {percent} percent used and still has {free} free. You have plenty of room."
        ),
        "say_disk_busy": (
            "The disk is {percent} percent used, with {free} free. It is getting full, "
            "so keep an eye on it before big updates."
        ),
        "say_disk_tight": (
            "Careful: the disk is {percent} percent used and only {free} are free. "
            "It is worth freeing space before updating anything."
        ),
        "say_ram_ok": (
            "Memory: {used} of {total} in use, {percent} percent. "
            "The computer is running comfortably."
        ),
        "say_ram_busy": (
            "Memory: {used} of {total} in use, {percent} percent. That is a normal load."
        ),
        "say_ram_high": (
            "Memory: {used} of {total} in use, {percent} percent, which is very tight. "
            "You should review what you have open."
        ),
        "say_programs": (
            "I found {total} programs. {ok} are up to date, {outdated} have an update waiting "
            "and {vulnerable} have known security problems."
        ),
        "say_vuln_none": "None of your programs has a known security problem. Good news.",
        "say_vuln": (
            "About the security problems: {n} programs are affected. {fixable} of them are "
            "already fixed in a newer version, so updating solves them. {unfixable} have no fix "
            "published yet; use those with care and do not open files from unknown sources."
        ),
        "say_vuln_eol": (
            "Some of them are out of support, which means their authors no longer publish fixes. "
            "It is better to move to a supported version."
        ),
        "say_vuln_hidden": (
            "Besides programs, {n} libraries and system packages also have notices. "
            "Most come from the kernel and are solved by updating and removing old kernels."
        ),
        "say_reclaim_brief": "By doing some cleaning you can recover about {total}.",
        "say_reclaim_updates": "You also have {n} updates ready to install.",
        "say_clean_first": (
            "With the disk like this, clean first and update after, so the updates have room."
        ),
        "say_tools_summary": (
            "Programs with security problems: {vulnerable}. Out of date: {outdated}."
        ),
        "say_tools_programs_ok": (
            "None of your programs has a known security problem. Programs out of date: {outdated}."
        ),
        "say_tools_libs_serious": (
            "Counting libraries and system packages, {n} more have security notices, "
            "{serious} of them critical or high priority. Updating everything fixes most."
        ),
        "say_tools_libs_mild": (
            "Counting libraries and system packages, {n} more have security notices, "
            "none critical. Updating everything fixes most."
        ),
        "say_tools_old_kernels": (
            "{n} more notices come from old kernels you are not using. They are solved by "
            "removing them, not by updating."
        ),
        "say_tools_urgent": "These are the most urgent, from programs and libraries together.",
        "say_tools_outdated_only": (
            "I found no security problems. Programs out of date: {outdated}. With Update "
            "everything you bring them up to date."
        ),
        "say_tools_clean": "Everything is up to date and I found no known security problems.",
        "say_reclaim": "You can recover about {total}: {parts}. Review it before cleaning.",
        "say_reclaim_kernels": "{size} in old kernels",
        "say_reclaim_cache": "{size} in downloaded packages",
        "say_reclaim_orphans": "{size} in packages nobody uses",
        "say_downloads": (
            "In your downloads folder there are {files} files taking {size}. "
            "The biggest group is {kind}."
        ),
        "say_and_more": "and others",
        "say_kernel_name": "the system kernel",
        "say_advice_restart": (
            "After updating the kernel, restart the computer so it starts using it."
        ),
        "say_advice_update": (
            "My advice, first: update {names}. The fix already exists, so it is the safest step."
        ),
        "say_advice_expired": (
            "The authors of {names} no longer publish fixes for this version. Ubuntu may still "
            "provide them, but only with Ubuntu Pro. You can keep using it for work on this "
            "computer, but do not run it as a server reachable from the internet, and do not "
            "run code you do not trust. When you can, move to a version that still gets fixes."
        ),
        "say_advice_vm": (
            "{names} has known problems and no fix yet. Many people keep using it and that is "
            "fine, as long as you only run machines you trust, do not browse the web inside "
            "them, and do not expose them to the internet."
        ),
        "say_advice_waiting": (
            "{names} has no fix published yet. You can keep using it, but only with files "
            "and sites you trust, and keep it away from the open internet."
        ),
        "say_outro": (
            "That is all. Use the Update or Remove buttons to see a preview "
            "before anything is changed."
        ),
        "progress_title": "Analysing this machine",
        "progress_hint": (
            "You can see what it is doing right now. Results show up here as they are found."
        ),
        "progress_first_run": (
            "The first scan, or the first one after restarting the computer, can take several "
            "minutes. The next ones are faster."
        ),
        "step_system": "Reading system, disk and memory",
        "step_programs": "Listing installed programs",
        "step_updates": "Checking available updates",
        "step_downloads": "Looking at your downloads folder",
        "step_feed": "Looking for a newer vulnerability list",
        "step_index": "Reading the vulnerability list",
        "step_external": "Checking Python and npm packages",
        "ext_title": "Python and npm packages",
        "ext_sub": "{n} installed with pip or npm; {bad} with security notices.",
        "ext_none": "None of them has a known security notice.",
        "ext_failed": (
            "Could not check {tools}: no connection, or the list could not be read. "
            "Try again later."
        ),
        "ext_col_package": "Package",
        "ext_col_tool": "Installed with",
        "ext_fix": "Update to {version} or newer with {tool}.",
        "ext_fix_hint": "For example: {command}",
        "ext_nofix": "No fix published yet. Use it with care.",
        "ext_malware": "This is a malicious package. Remove it.",
        "ext_no_priority": "unknown",
        "sbx_title": "Snap and Flatpak apps",
        "sbx_sub": "{n} installed. They carry their own libraries, so Ganki does not check them.",
        "sbx_col_source": "Source",
        "ext_cmd_update": "To update it, copy this command and paste it into a terminal:",
        "ext_cmd_remove": "If you do not use it, to remove it:",
        "ext_cmd_npm": (
            'If npm answers "permission denied" (EACCES), run it again with sudo in front.'
        ),
        "ext_cmd_pip": (
            'If pip answers "externally-managed-environment", the system manages that package: '
            "update it with apt or inside a virtual environment."
        ),
        "ext_cmd_note": "Ganki does not run it for you and never touches your projects.",
        "ext_cmd_before_pip": (
            "Before removing it, check that nothing needs it: run python3 -m pip show NAME and "
            "read the Required-by line (replace NAME with the package)."
        ),
        "ext_cmd_before_npm": "Before removing it, check that none of your projects uses it.",
        "sbx_cmd_update": "To update it, copy this command and paste it into a terminal:",
        "sbx_cmd_remove": "If you do not use it, to remove it:",
        "sbx_cmd_shared": (
            "This looks like a base that other apps are built on: removing it can break apps "
            "that seem unrelated. Remove it only if you know nothing needs it."
        ),
        "report_sandboxed": "Snap and Flatpak apps",
        "sbx_note": (
            "{n} apps installed with snap or flatpak. Each one carries its own libraries, "
            "so the Ubuntu list does not describe them and Ganki does not check them. "
            "Keep them updated from their own store."
        ),
        "say_sandboxed": (
            "You also have {snaps} snap and {flatpaks} flatpak apps. They carry their own "
            "libraries, so I only list them; I do not check them for vulnerabilities."
        ),
        "report_external": "Python and npm packages with security notices",
        "say_external_ok": (
            "In Python and npm you have {n} packages and none has a known security notice."
        ),
        "say_external_bad": (
            "In Python and npm you have {n} packages, {bad} with security notices, "
            "{serious} of them critical or high priority. Most urgent: {names}."
        ),
        "say_external_malware": "Warning: {names} is a malicious package. Remove it.",
        "say_external_failed": "I could not check {tools}. Try again later.",
        "step_analysis": "Matching vulnerabilities and preparing the report",
        "fact_system": "System: {os}",
        "fact_disk": "Disk: {percent}% used, {free} free",
        "fact_ram": "Memory: {percent}% in use",
        "fact_packages": "{n} packages installed",
        "fact_updates": "{n} updates available",
        "fact_downloads": "Downloads: {files} files, {size}",
        "fact_feed": "Vulnerability list: {date}",
        "fact_findings": "{n} vulnerability matches found",
        "fact_external": "{n} Python and npm packages checked",
        "card_system": "System",
        "card_free": "{free} free",
        "card_ram_sub": "{used} of {total}",
        "card_updates": "Updates",
        "card_updates_sub": "ready to install",
        "report_open": "PDF report",
        "report_title": "Ganki - System report",
        "report_generated": "Generated on {date}.",
        "report_private": "Made on this computer; nothing was sent anywhere.",
        "report_summary": "Summary",
        "report_computer": "This computer",
        "report_item": "Item",
        "report_value": "Value",
        "report_disk": "{percent}% used - {used} used, {free} free",
        "report_ram": "{percent}% in use - {used} of {total}",
        "report_security": "Programs with security problems",
        "report_outdated": "Programs out of date",
        "report_legend": (
            "Colours: red = deal with it first, yellow = worth doing soon, green = no hurry."
        ),
        "report_libs": "Libraries and system packages with security notices",
        "report_package": "Package",
        "report_fixable": "Fixed by updating",
        "report_nofix": "No fix published yet",
        "report_minor": (
            "More notices, low or negligible priority and no fix published yet: {n}. "
            "They need nothing from you for now."
        ),
        "report_kernel_name": "Linux kernel",
        "report_components": "{n} components",
        "report_versions": "several",
        "report_libs_outdated": "{n} more libraries and system packages have updates waiting.",
        "report_program": "Program",
        "report_version": "Version",
        "report_priority": "Priority",
        "report_action": "What to do",
        "report_new_version": "Available version",
        "report_act_fix": "Update: fixed in {version}",
        "report_act_nofix": "No fix published yet: use it with care, with files you trust",
        "report_act_eol": (
            "Project out of support (Ubuntu fixes only with Ubuntu Pro): "
            "keep it off the internet and move to a supported version"
        ),
        "report_none": "Nothing to report.",
        "report_more": "...and {n} more not listed here.",
        "report_reclaim": "Space you can recover",
        "report_total": "Total",
        "report_caution": "Review everything before cleaning or removing anything.",
        "dl_detail_total": "{files} files, {size}",
        "dl_detail_hint": (
            "This is only a look: Ganki does not delete anything here. Check each item "
            "yourself before removing it."
        ),
        "dl_detail_truncated": "The folder is very large; only part of it was read.",
        "dl_detail_folders": "Where the space is",
        "dl_detail_kinds": "File types",
        "dl_detail_biggest": "Biggest files",
        "dl_detail_name": "Name",
        "dl_detail_type": "Type",
        "dl_detail_files": "Files",
        "dl_detail_no_ext": "(no extension)",
        "assistant_title": "Assistant",
        "assistant_close": "Close the assistant",
        "assistant_open": "Open the assistant",
        "assistant_prompt": "Do you want me to read you the summary when the scan ends?",
        "assistant_listen": "Turn on voice",
        "assistant_play": "Explain my system",
        "assistant_pause": "Stop",
        "assistant_no_voice": (
            "There is no local voice yet. You can still read the captions. For a natural "
            "voice, run scripts/install-voice.sh"
        ),
        "assistant_ready": "Scan finished. Do you want me to explain it?",
        "details_note": "Source: Ubuntu security data, compared locally.",
        "downloads": "Downloads by type",
        "downloads_summary": "{n} files, {size}",
        "downloads_empty": "Nothing found in {folder}.",
        "dl_archives": "Archives (.zip, .tar.gz)",
        "dl_images": "Images (.jpg, .png)",
        "dl_installers": "Installers (.deb, .AppImage)",
        "dl_pdf": "PDF",
        "dl_documents": "Documents (.docx, .odt)",
        "dl_other": "Other",
        "snaps": "Not checked: the real app is a snap",
        "prev": "Previous",
        "next": "Next",
        "page_of": "Page {n} of {total}",
        "none": "Nothing here.",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "negligible": "negligible",
        "unknown": "unknown",
        "ring_used": "used",
        "ring_in_use": "in use",
        "ring_ok": "up to date",
        "show_more": "Show {n} more",
        "show_less": "Show less",
        "reclaim_total": "Review before cleaning",
        "lbl_system": "System",
        "lbl_user": "User",
        "lbl_datetime": "Date and time",
        "lbl_disk": "Disk",
        "disk_free_big": "{free} free",
        "disk_used_of": "{used} used of {total}",
        "last_scan_short": "last scan",
        "x_of_y_ok": "{ok} of {all} programs up to date",
        "pill_vuln": "{n} with vulnerabilities",
        "leg_disk_used": "{size} used",
        "leg_disk_free": "{size} free",
        "leg_ram_used": "{size} in use",
        "leg_ram_free": "{size} free",
        "leg_ok": "{n} up to date",
        "leg_old": "{n} outdated",
        "leg_vuln": "{n} with vulnerabilities",
        "col_origin": "Origin",
        "tools_sub": "{n} programs · sorted by state",
        "search_label": "Search tool",
        "search_ph": "name or description",
        "prompt_cmd": "ganki --summary",
        "review_clean": "Review before cleaning",
    },
    "es": {
        "title": "Resumen del sistema",
        "scanning": "Analizando esta máquina... puede tardar un minuto.",
        "rescan": "Volver a escanear",
        "error": "El análisis no pudo terminar. Los detalles están en la terminal de Ganki.",
        "unsupported": "Este sistema no es compatible: los datos cubren versiones de Ubuntu.",
        "reboot": "Hace falta reiniciar para usar el kernel actualizado.",
        "uptime": "encendido hace {time}",
        "last_scan": "Último escaneo",
        "feed": "Datos de vulnerabilidades",
        "feed_new": "descargados recién",
        "feed_cached": "ya estaban al día",
        "disk": "Disco",
        "disk_detail": "{used} ocupados, {free} libres de {total}",
        "ram": "Memoria RAM",
        "ram_detail": "{used} en uso, {free} libres",
        "programs": "Programas al día",
        "programs_detail": "{vuln} con vulnerabilidades, {old} desactualizados",
        "reclaim": "Espacio recuperable",
        "reclaim_hint": "Revisar antes de limpiar. Todavía no se quita nada desde acá.",
        "reclaim_kernels": "Kernels viejos",
        "reclaim_cache": "Caché de apt",
        "reclaim_orphans": "Paquetes huérfanos",
        "kernel": "Kernel en uso",
        "kernel_cves": "{n} vulnerabilidades conocidas, corregidas en {fixed}.",
        "tools": "Herramientas instaladas",
        "tools_hint": "Ordenadas por estado: lo que necesita atención va primero.",
        "search": "Buscar herramienta",
        "f_all": "Todas",
        "f_outdated": "Desactualizadas",
        "f_vulnerable": "Con vulnerabilidades",
        "show_all": "Incluir bibliotecas y dependencias",
        "apply": "Aplicar",
        "col_tool": "Herramienta",
        "col_version": "Versión",
        "col_size": "Tamaño",
        "col_state": "Estado",
        "state_ok": "Al día",
        "state_outdated": "Desactualizada",
        "state_vulnerable": "Vulnerabilidad",
        "cve_summary": "CVE: {n}",
        "fixed_in": "Corregida en {version}",
        "cve_split": "{fixed} se corrigen en {version} · {open} sin arreglo",
        "no_fix_yet": "sin arreglo publicado",
        "hint_fixed": (
            "Corregida en {version} con parche de la distribución. Actualizá para resolverla."
        ),
        "tag_fixed": "Con arreglo",
        "tag_no_fix": "Sin arreglo",
        "tag_eol": "Sin soporte",
        "tag_malware": "Malicioso",
        "tag_how": "Cómo lo revisa Ganki",
        "sbx_how_hint": "No se compara con listas de vulnerabilidades.",
        "more_fixed": (
            "Qué tener en cuenta: el arreglo ya está en los orígenes de tu propio sistema, así "
            "que no necesitás nada de afuera. Apretá Actualizar en esta fila. Algunas "
            "actualizaciones recién se aplican cuando cerrás y volvés a abrir el programa, o al "
            "reiniciar (el núcleo del sistema, el navegador). Hasta entonces, evitá abrir con él "
            "archivos de origen dudoso."
        ),
        "more_no_fix": (
            "Qué tener en cuenta: todavía no existe un parche. Eso no significa que alguien te "
            "esté atacando; muchos de estos avisos son de prioridad baja y la distribución "
            "todavía no los corrigió, o decidió no hacerlo. Usá este programa solo con archivos y "
            "sitios de confianza. Si no lo usás, quitalo. Ganki vuelve a revisar en cada "
            "análisis, así que la etiqueta desaparece sola cuando se publique un arreglo."
        ),
        "more_eol": (
            "Qué tener en cuenta: esta versión ya no recibe arreglos de sus autores, así que los "
            "problemas nuevos no se van a corregir. Buscá una versión más nueva o una "
            "alternativa. Si tenés que conservarla, no la uses con archivos de origen dudoso ni "
            "en internet. Ubuntu Pro puede extender los arreglos de algunos paquetes."
        ),
        "more_malware": (
            "Qué tener en cuenta: este paquete se conoce como malicioso. No lo ejecutes. Quitalo "
            "ahora. Si ya lo usaste, cambiá las contraseñas y claves que escribiste o guardaste "
            "en esta computadora, y revisá si hay algo que no instalaste vos."
        ),
        "more_ext_fix": (
            "Qué tener en cuenta: actualizar cambia la versión del paquete, y tus propios "
            "proyectos pueden depender de la anterior. Actualizalo donde lo uses y corré las "
            "pruebas de tu proyecto. Ganki te muestra el comando; no modifica tus proyectos."
        ),
        "hint_no_fix": "Todavía no hay un parche publicado.",
        "hint_some_no_fix": "{n} avisos todavía no tienen parche, ni siquiera al actualizar.",
        "hint_fixed_part": (
            "Al actualizar a {version} se corrigen {n} avisos. Los otros {m} siguen abiertos "
            "porque todavía no existe un parche para ellos."
        ),
        "hint_eol": (
            "Sus autores ya no publican arreglos para esta versión. Ubuntu todavía puede "
            "darlos, pero solo con Ubuntu Pro. Pasá a una versión vigente cuando puedas."
        ),
        "chip_eol": "Proyecto sin soporte",
        "col_actions": "Acciones",
        "btn_update": "Actualizar",
        "btn_remove": "Quitar",
        "btn_update_all": "Actualizar todo",
        "protected": "Protegido",
        "protected_hint": "El sistema depende de él, por eso Ganki nunca ofrece quitarlo.",
        "back": "Volver",
        "copy": "Copiar comandos",
        "copied": "Copiado",
        "prev_title_update": "Vista previa antes de actualizar {name}",
        "prev_title_remove": "Vista previa antes de quitar {name}",
        "prev_title_all": "Vista previa antes de actualizar todo",
        "prev_summary": "{up} se actualizarían, {new} nuevos, {gone} se quitarían.",
        "prev_download": "Descarga: {size}",
        "prev_uses": "Usa {size} más de disco",
        "prev_frees": "Libera {size}",
        "prev_list_up": "Se actualizarían",
        "prev_list_new": "Se instalarían",
        "prev_list_gone": "Se quitarían",
        "prev_simulation": "Simulación (no cambia nada)",
        "prev_run_title": "O hacelo vos",
        "prev_run_note": (
            "Para hacerlo desde una terminal, copiá estas dos líneas: "
            "la primera guarda tu lista de programas para poder deshacer, la segunda lo hace."
        ),
        "prev_reboot": "Si se instala un kernel nuevo, reiniciá la computadora después.",
        "blocked_unknown": "Ese programa no está en la lista, no hay nada que previsualizar.",
        "blocked_protected": "El sistema depende de este programa. Ganki no ofrece quitarlo.",
        "blocked_drags_protected": "Quitarlo también quitaría software del que depende el sistema.",
        "blocked_failed": "No se pudo hacer la simulación. Probá de nuevo después de escanear.",
        "everything": "todo",
        "sure_title": "¿Seguro que querés continuar con {name}?",
        "info_remove": "Quitar un programa no borra tus documentos ni tus archivos personales.",
        "warn_drags": "También se quitarán {n} paquete(s) más.",
        "warn_data": (
            "{name} puede cuidar datos propios (bases de datos, "
            "contenedores). Hacé una copia antes."
        ),
        "warn_reboot": "Se instalará un kernel nuevo: reiniciá la computadora después.",
        "warn_big": (
            "Es una descarga grande y necesita espacio libre en disco. Mirá las cifras de arriba."
        ),
        "understood": "Leí las advertencias y quiero continuar.",
        "password_note": (
            "La contraseña la pide la ventana del sistema, nunca Ganki. Es la de tu usuario, la "
            "misma que escribís con sudo o para iniciar sesión. El usuario tiene que ser "
            "administrador y tener una contraseña; si no, el sistema lo rechaza y no cambia "
            "nada: usá el comando que aparece más abajo. "
            "Antes se guarda tu lista de programas, así se puede deshacer."
        ),
        "confirm_remove": "Sí, quitar {name}",
        "confirm_update": "Sí, actualizar {name}",
        "confirm_all": "Sí, actualizar todo",
        "cancel": "Cancelar",
        "run_waiting": "Esperando que escribas tu contraseña en la ventana del sistema...",
        "run_ok": "Listo. Escaneando de nuevo para actualizar las cifras.",
        "run_failed": "No terminó. Leé la salida de arriba; no se cambió nada más.",
        "run_refused": "Ganki se negó a ejecutarlo. Recargá la vista previa y probá de nuevo.",
        "run_saved": "Lista de programas guardada en",
        "say_scanning": (
            "Estamos analizando tu sistema. Puede tardar unos minutos, esperá un momento."
        ),
        "say_intro": "Acabo de analizar tu sistema.",
        "say_system": (
            "Estás usando {os}, con el usuario {user}. La computadora lleva encendida {uptime}."
        ),
        "say_reboot": "Hace falta reiniciar para usar el kernel actualizado.",
        "say_disk_ok": (
            "El disco está ocupado al {percent} por ciento y todavía tiene {free} libres. "
            "Tenés bastante espacio."
        ),
        "say_disk_busy": (
            "El disco está ocupado al {percent} por ciento, con {free} libres. "
            "Se está llenando, así que cuidalo antes de hacer actualizaciones grandes."
        ),
        "say_disk_tight": (
            "Atención: el disco está ocupado al {percent} por ciento y solo quedan {free} libres. "
            "Conviene liberar espacio antes de actualizar."
        ),
        "say_ram_ok": (
            "Memoria: {used} en uso de {total}, el {percent} por ciento. "
            "La computadora anda con comodidad."
        ),
        "say_ram_busy": (
            "Memoria: {used} en uso de {total}, el {percent} por ciento. Es una carga normal."
        ),
        "say_ram_high": (
            "Memoria: {used} en uso de {total}, el {percent} por ciento, muy ajustada. "
            "Deberías revisar qué tenés abierto."
        ),
        "say_programs": (
            "Encontré {total} programas. {ok} están al día, {outdated} tienen una actualización "
            "esperando y {vulnerable} tienen problemas de seguridad conocidos."
        ),
        "say_vuln_none": (
            "Ninguno de tus programas tiene un problema de seguridad conocido. Buenas noticias."
        ),
        "say_vuln": (
            "Sobre los problemas de seguridad: hay {n} programas afectados. {fixable} ya están "
            "corregidos en una versión más nueva, así que actualizando se resuelven. "
            "{unfixable} todavía no tienen arreglo publicado; usalos con cuidado "
            "y no abras archivos de origen dudoso."
        ),
        "say_vuln_eol": (
            "Algunos están fuera de soporte, es decir que sus autores ya no publican arreglos. "
            "Conviene pasar a una versión vigente."
        ),
        "say_vuln_hidden": (
            "Además de los programas, hay {n} bibliotecas y paquetes del sistema con avisos. "
            "La mayoría vienen del kernel y se resuelven actualizando y quitando kernels viejos."
        ),
        "say_reclaim_brief": "Haciendo algunas limpiezas podés recuperar unos {total}.",
        "say_reclaim_updates": "Además tenés {n} actualizaciones listas para instalar.",
        "say_clean_first": (
            "Con el disco así, conviene limpiar primero y actualizar después, "
            "para que las actualizaciones tengan lugar."
        ),
        "say_tools_summary": (
            "Programas con problemas de seguridad: {vulnerable}. Desactualizados: {outdated}."
        ),
        "say_tools_programs_ok": (
            "Ninguno de tus programas tiene un problema de seguridad conocido. "
            "Programas desactualizados: {outdated}."
        ),
        "say_tools_libs_serious": (
            "Contando librerías y paquetes del sistema, hay {n} más con avisos de seguridad, "
            "{serious} de ellos de prioridad crítica o alta. Actualizando todo se arreglan "
            "casi todos."
        ),
        "say_tools_libs_mild": (
            "Contando librerías y paquetes del sistema, hay {n} más con avisos de seguridad, "
            "ninguno crítico. Actualizando todo se arreglan casi todos."
        ),
        "say_tools_old_kernels": (
            "Otros {n} avisos vienen de kernels viejos que no estás usando. Se resuelven "
            "quitándolos, no actualizando."
        ),
        "say_tools_urgent": "Esto es lo más urgente, entre programas y librerías juntos.",
        "say_tools_outdated_only": (
            "No encontré problemas de seguridad. Programas desactualizados: {outdated}. "
            "Con Actualizar todo los ponés al día."
        ),
        "say_tools_clean": "Todo está al día y no encontré problemas de seguridad conocidos.",
        "say_reclaim": "Podés recuperar unos {total}: {parts}. Revisalo antes de limpiar.",
        "say_reclaim_kernels": "{size} en kernels viejos",
        "say_reclaim_cache": "{size} en paquetes descargados",
        "say_reclaim_orphans": "{size} en paquetes que nadie usa",
        "say_downloads": (
            "En tu carpeta de descargas hay {files} archivos que ocupan {size}. "
            "El grupo más grande es {kind}."
        ),
        "say_and_more": "y otros",
        "say_kernel_name": "el kernel del sistema",
        "say_advice_restart": (
            "Después de actualizar el kernel, reiniciá la computadora para que lo use."
        ),
        "say_advice_update": (
            "Mi consejo, primero: actualizá {names}. El arreglo ya existe, es el paso más seguro."
        ),
        "say_advice_expired": (
            "Los autores de {names} ya no publican arreglos para esta versión. Ubuntu todavía "
            "puede darlos, pero solo con Ubuntu Pro. Podés seguir usándolo para trabajar en "
            "esta computadora, pero no lo dejes como servidor accesible desde internet ni "
            "ejecutes código que no conozcas. Cuando puedas, pasá a una versión que todavía "
            "reciba arreglos."
        ),
        "say_advice_vm": (
            "{names} tiene problemas conocidos y todavía no hay arreglo. Mucha gente lo sigue "
            "usando y está bien, siempre que solo corras máquinas de confianza, no navegues "
            "por internet dentro de ellas y no las expongas a la red."
        ),
        "say_advice_waiting": (
            "{names} todavía no tiene arreglo publicado. Podés seguir usándolo, pero solo con "
            "archivos y sitios de confianza, y lejos de internet abierto."
        ),
        "say_outro": (
            "Eso es todo. Con los botones Actualizar o Quitar ves una vista previa "
            "antes de cambiar algo."
        ),
        "progress_title": "Analizando esta máquina",
        "progress_hint": (
            "Acá ves qué está haciendo ahora. Los resultados aparecen a medida que se encuentran."
        ),
        "progress_first_run": (
            "El primer análisis, o el primero después de reiniciar la computadora, puede tardar "
            "varios minutos. Los siguientes son más rápidos."
        ),
        "step_system": "Leyendo sistema, disco y memoria",
        "step_programs": "Listando los programas instalados",
        "step_updates": "Buscando actualizaciones disponibles",
        "step_downloads": "Mirando tu carpeta de descargas",
        "step_feed": "Buscando una lista de vulnerabilidades más nueva",
        "step_index": "Leyendo la lista de vulnerabilidades",
        "step_external": "Revisando paquetes de Python y npm",
        "ext_title": "Paquetes de Python y npm",
        "ext_sub": "{n} instalados con pip o npm; {bad} con avisos de seguridad.",
        "ext_none": "Ninguno tiene avisos de seguridad conocidos.",
        "ext_failed": (
            "No pude revisar {tools}: no hubo conexión o no se pudo leer la lista. "
            "Probá de nuevo más tarde."
        ),
        "ext_col_package": "Paquete",
        "ext_col_tool": "Instalado con",
        "ext_fix": "Actualizá a {version} o más nuevo con {tool}.",
        "ext_fix_hint": "Por ejemplo: {command}",
        "ext_nofix": "Todavía no hay arreglo publicado. Usalo con cuidado.",
        "ext_malware": "Es un paquete malicioso. Quitalo.",
        "ext_no_priority": "sin dato",
        "sbx_title": "Apps de Snap y Flatpak",
        "sbx_sub": "{n} instaladas. Traen sus propias librerías, así que Ganki no las revisa.",
        "sbx_col_source": "Origen",
        "ext_cmd_update": "Para actualizarlo, copiá este comando y pegalo en una consola:",
        "ext_cmd_remove": "Si no lo usás, para quitarlo:",
        "ext_cmd_npm": (
            'Si npm responde "permission denied" (EACCES), repetí el comando con sudo adelante.'
        ),
        "ext_cmd_pip": (
            'Si pip responde "externally-managed-environment", ese paquete lo gestiona el sistema: '
            "actualizalo con apt o dentro de un entorno virtual."
        ),
        "ext_cmd_note": "Ganki no lo ejecuta por vos y nunca toca tus proyectos.",
        "ext_cmd_before_pip": (
            "Antes de quitarlo, fijate que nada lo necesite: corré python3 -m pip show NOMBRE y "
            "leé la línea Required-by (cambiá NOMBRE por el paquete)."
        ),
        "ext_cmd_before_npm": "Antes de quitarlo, fijate que ninguno de tus proyectos lo use.",
        "sbx_cmd_update": "Para actualizarla, copiá este comando y pegalo en una consola:",
        "sbx_cmd_remove": "Si no la usás, para quitarla:",
        "sbx_cmd_shared": (
            "Esto parece una base sobre la que se construyen otras apps: quitarla puede romper "
            "apps que parecen no tener relación. Quitala solo si sabés que nada la necesita."
        ),
        "report_sandboxed": "Apps de Snap y Flatpak",
        "sbx_note": (
            "{n} apps instaladas con snap o flatpak. Cada una trae sus propias librerías, "
            "así que la lista de Ubuntu no las describe y Ganki no las revisa. "
            "Mantenelas al día desde su propia tienda."
        ),
        "say_sandboxed": (
            "También tenés {snaps} apps snap y {flatpaks} flatpak. Traen sus propias "
            "librerías, así que solo las listo; no las reviso por vulnerabilidades."
        ),
        "report_external": "Paquetes de Python y npm con avisos de seguridad",
        "say_external_ok": (
            "En Python y npm tenés {n} paquetes y ninguno tiene avisos de seguridad conocidos."
        ),
        "say_external_bad": (
            "En Python y npm tenés {n} paquetes, {bad} con avisos de seguridad, "
            "{serious} de ellos de prioridad crítica o alta. Lo más urgente: {names}."
        ),
        "say_external_malware": "Atención: {names} es un paquete malicioso. Quitalo.",
        "say_external_failed": "No pude revisar {tools}. Probá de nuevo más tarde.",
        "step_analysis": "Cruzando vulnerabilidades y preparando el informe",
        "fact_system": "Sistema: {os}",
        "fact_disk": "Disco: {percent}% usado, {free} libres",
        "fact_ram": "Memoria: {percent}% en uso",
        "fact_packages": "{n} paquetes instalados",
        "fact_updates": "{n} actualizaciones disponibles",
        "fact_downloads": "Descargas: {files} archivos, {size}",
        "fact_feed": "Lista de vulnerabilidades: {date}",
        "fact_findings": "{n} coincidencias de vulnerabilidades encontradas",
        "fact_external": "{n} paquetes de Python y npm revisados",
        "card_system": "Sistema",
        "card_free": "{free} libres",
        "card_ram_sub": "{used} de {total}",
        "card_updates": "Actualizaciones",
        "card_updates_sub": "listas para instalar",
        "report_open": "Informe PDF",
        "report_title": "Ganki - Informe del sistema",
        "report_generated": "Generado el {date}.",
        "report_private": "Hecho en esta computadora; no se envió nada a ningún lado.",
        "report_summary": "Resumen",
        "report_computer": "Esta computadora",
        "report_item": "Dato",
        "report_value": "Valor",
        "report_disk": "{percent}% usado - {used} usados, {free} libres",
        "report_ram": "{percent}% en uso - {used} de {total}",
        "report_security": "Programas con problemas de seguridad",
        "report_outdated": "Programas desactualizados",
        "report_legend": (
            "Colores: rojo = atendelo primero, amarillo = conviene hacerlo pronto, "
            "verde = sin apuro."
        ),
        "report_libs": "Librerías y paquetes del sistema con avisos de seguridad",
        "report_package": "Paquete",
        "report_fixable": "Se arreglan actualizando",
        "report_nofix": "Sin arreglo publicado todavía",
        "report_minor": (
            "Avisos más, de prioridad baja o despreciable y sin arreglo publicado: {n}. "
            "Por ahora no necesitan nada de tu parte."
        ),
        "report_kernel_name": "Kernel de Linux",
        "report_components": "{n} componentes",
        "report_versions": "varias",
        "report_libs_outdated": (
            "Hay {n} librerías y paquetes del sistema más con actualizaciones esperando."
        ),
        "report_program": "Programa",
        "report_version": "Versión",
        "report_priority": "Prioridad",
        "report_action": "Qué hacer",
        "report_new_version": "Versión disponible",
        "report_act_fix": "Actualizar: arreglado en {version}",
        "report_act_nofix": "Sin arreglo publicado: usalo con cuidado y con archivos de confianza",
        "report_act_eol": (
            "Proyecto sin soporte (arreglos de Ubuntu solo con Ubuntu Pro): "
            "mantenelo lejos de internet y pasá a una versión vigente"
        ),
        "report_none": "Nada para informar.",
        "report_more": "...y {n} más que no se listan acá.",
        "report_reclaim": "Espacio que podés recuperar",
        "report_total": "Total",
        "report_caution": "Revisá todo antes de limpiar o quitar algo.",
        "dl_detail_total": "{files} archivos, {size}",
        "dl_detail_hint": (
            "Esto es solo para mirar: Ganki no borra nada desde acá. Revisá cada cosa "
            "vos antes de quitarla."
        ),
        "dl_detail_truncated": "La carpeta es muy grande; solo se leyó una parte.",
        "dl_detail_folders": "Dónde está el espacio",
        "dl_detail_kinds": "Tipos de archivo",
        "dl_detail_biggest": "Archivos más grandes",
        "dl_detail_name": "Nombre",
        "dl_detail_type": "Tipo",
        "dl_detail_files": "Archivos",
        "dl_detail_no_ext": "(sin extensión)",
        "assistant_title": "Asistente",
        "assistant_close": "Cerrar el asistente",
        "assistant_open": "Abrir el asistente",
        "assistant_prompt": "¿Querés que te lea el resumen cuando termine el análisis?",
        "assistant_listen": "Activar voz",
        "assistant_play": "Explicar mi sistema",
        "assistant_pause": "Detener",
        "assistant_no_voice": (
            "Todavía no hay una voz local. Igual podés leer los subtítulos. Para una voz "
            "natural, ejecutá scripts/install-voice.sh"
        ),
        "assistant_ready": "Terminó el análisis. ¿Querés que te lo explique?",
        "details_note": "Fuente: datos de seguridad de Ubuntu, comparados en tu equipo.",
        "downloads": "Descargas por tipo",
        "downloads_summary": "{n} archivos, {size}",
        "downloads_empty": "No hay nada en {folder}.",
        "dl_archives": "Comprimidos (.zip, .tar.gz)",
        "dl_images": "Imágenes (.jpg, .png)",
        "dl_installers": "Instaladores (.deb, .AppImage)",
        "dl_pdf": "PDF",
        "dl_documents": "Documentos (.docx, .odt)",
        "dl_other": "Otros",
        "snaps": "No revisados: la aplicación real es un snap",
        "prev": "Anterior",
        "next": "Siguiente",
        "page_of": "Página {n} de {total}",
        "none": "Nada por acá.",
        "critical": "crítica",
        "high": "alta",
        "medium": "media",
        "low": "baja",
        "negligible": "despreciable",
        "unknown": "desconocida",
        "ring_used": "ocupado",
        "ring_in_use": "en uso",
        "ring_ok": "al día",
        "show_more": "Ver {n} más",
        "show_less": "Ver menos",
        "reclaim_total": "Revisar antes de limpiar",
        "lbl_system": "Sistema",
        "lbl_user": "Usuario",
        "lbl_datetime": "Fecha y hora",
        "lbl_disk": "Disco",
        "disk_free_big": "{free} libres",
        "disk_used_of": "{used} ocupados de {total}",
        "last_scan_short": "último escaneo",
        "x_of_y_ok": "{ok} de {all} programas al día",
        "pill_vuln": "{n} con vulnerabilidades",
        "leg_disk_used": "{size} ocupados",
        "leg_disk_free": "{size} libres",
        "leg_ram_used": "{size} en uso",
        "leg_ram_free": "{size} libres",
        "leg_ok": "{n} al día",
        "leg_old": "{n} desactualizados",
        "leg_vuln": "{n} con vulnerabilidades",
        "col_origin": "Origen",
        "tools_sub": "{n} programas · ordenados por estado",
        "search_label": "Buscar herramienta",
        "search_ph": "nombre o descripción",
        "prompt_cmd": "ganki --resumen",
        "review_clean": "Revisar antes de limpiar",
    },
}


def pick_language(cookie: str | None, accept_language: str | None) -> str:
    """Language from the saved choice, else the browser's preference, else the default."""
    if cookie in LANGUAGES:
        return str(cookie)
    for part in (accept_language or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in LANGUAGES:
            return code
    return DEFAULT_LANGUAGE


def translate(lang: str, key: str, **values: object) -> str:
    """Text for ``key``; falls back to English, then to the key itself."""
    table = TEXTS.get(lang, TEXTS[DEFAULT_LANGUAGE])
    text = table.get(key) or TEXTS[DEFAULT_LANGUAGE].get(key, key)
    return text.format(**values) if values else text
