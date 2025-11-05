---
layout: single
title: "Sherlocks - Trojan (HTB)"
author_profile: true
published: true
---

Los sherlocks (De HackTheBox) son retos gamificados enfocados a __Blue Team__, en ellos, se encuentran distintas situaciones donde uno debe utilizar herramientas de analsis y artefactos para completar las tareas. Y claro, hay __categorías__ según lo que quieras entrenar, como por ejemplo _DFIR_ (Digital Forensics and Incident Response) que se enfocan en el __análsis de artefactos forenses__ (es decir, trazas de ataques en los sistemas).

![UTMP]({{ "/images/Trojan/logo.png" | relative_url }}){: .align-center}


## Resumen Trojan

En este sherlock nos enfocamos al análisis forense de 3 tipos distintos de artefactos: Captura de tráfico, una captura de Memoria, Captura Tipo Snapshot (memoria) y una captura del disco; Honestamente me he planteado un poco el reto de solucionar una máquina **insane** de este tipo sobre análisis forense, pero para correr primero hay que caminar, y recordar sobre todo los fundamentos del análisis forense que hace tiempo no utilizaba. Volviendo al asunto de la máquina; estaremos tocando conceptos como `ammcache`, `prefetch`, `Network Analysis`, herramientas como `volatility`, `wireshark` y `FTK Imager`.

## Laboratorio

### Descripción

John Grunewald was deleting some old accounting documents when he accidentally deleted an important document he had been working on. He panicked and downloaded software to recover the document, but after installing it, his PC started behaving strangely. Feeling even more demoralised and depressed, he alerted the IT department, who immediately locked down the workstation and recovered some forensic evidence. Now it is up to you to analyze the evidence to understand what happened on John's workstation.

### Desarrollo

Como primer archivo nos dan un comprimido zip que contiene los siguientes archivos:

```java
❯ 7z l Trojan.zip

<SNIP!>
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2023-05-29 20:41:21 .....    505393636    496383667  disk artifacts/disk_artifacts.ad1
2023-05-30 01:00:50 .....   4294967296    859493977  memory capture/memory.vmem
2023-05-30 01:00:50 .....    138411512      1802537  memory capture/memory.vmsn
2023-05-30 01:01:55 .....     64936148     60577571  packet capture/network.pcapng
------------------- ----- ------------ ------------  ------------------------
2023-06-01 06:08:03         5003708592   1418257752  4 files, 3 folders
```

#### Q1: What is the build version of the operating system?

Primero, necesitamos instalar `volatility` para poder examinar las capturas de memoria (requiere por lo menos `python3.8`):

1. Descarga el tarball de [python3.12](https://www.python.org/downloads/) según la versión Linux que tengas
2. Descomprime el tarball en tu directorio local `tar -xf <Archivo.tar.xz>` o `tar -xvzf <archivo.tgz>`
3. Ejecuta `./configure --enable-optimizations` (Llega a tardar varios minutos)
4. `sudo make altinstall`

Luego, ya es posible instalarlo desde el source:

```js
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3/
python3 -m venv venv && . venv/bin/activate
pip install --user -e ".[full]"
```

O bien, instalarlo desde el registro `PyPi` `pip install volatility3` (recomiendo hacerlo así para que sea más accesible)

Y podremos probar la instalación con `vol`

###### Nota: Es posible que surjan problemas con la instalación de 'No se encuentra X módulo', para ello, tendrás que Instalar las librerías desde apt y volver a instalar Python desde 0

Una vez funcionando; nos dirijimos al directorio de la capura de memoria `memory.vmem` y utilizamos `volatility` para obtener detalles de la captura:

```bash
vol -f memory.vmem windows.info
```

Este proceso se tardará buen rato, pero una vez procesado:

![UTMP]({{ "/images/Trojan/Q1.png" | relative_url }}){: .align-center}

Específicamente, la 'build version' es la indicada `minor`

```bash
Q1: 19041
``` 

#### Q2: What is the computer hostname?

Ahora, iniciemos con la captura de tráfico; recordemos que los archivos `pcapng` son archivos de captura de paquetes el cual es interpretable por `wireshark`, muchas herramientas pueden hacer este tipo de capturas, los hacen más pesados que una captura por defecto por ejemplo `tcpdump`, pero dan muchísima más información los `pcapng`, y en lo personal, más cómodo de trabajar.

Al abrir el archivo de captura, veremos varios cientos de paquetes; pero desde los primeros, podremos notar el tipo de paquete como `LLMNR` (Link Local Mutlicast Name Resolution, un protocolo alterno al DNS para resolución de nombres) y si vamos observando el contenido del paquete, veremos la `query` y el campo `Nombre`:

![UTMP]({{ "/images/Trojan/Q2.png" | relative_url }}){: .align-center}


```bash
Q2: DESKTOP-38NVPD0
``` 

#### Q3: What is the name of the downloaded ZIP file?

Ahora, hay un pequeño truco acá en vez de buscar zips entre los paquetes; que en vez de ello, podemos buscar entre los archivos captados por el `pcapng` lléndonos a `File` > `Export Objects` > `HTTP` Y escribir `zip` en la barra de búsqueda; si le damos clic, nos mandará a la linea en la que se hace la descarga.

![UTMP]({{ "/images/Trojan/Q4.png" | relative_url }}){: .align-center}

La respuesta está justo al final de la fila; a unos campos de `hostname`, siendo la respuesta de la siguiente pregunta


```bash
Q3: Data_Recovery.zip
``` 

#### Q4: What is the domain of the website (including the third-level domain) from which the file was downloaded?

La respuesta se menciona anteriormente, pero si vas al paquete, dando clic derecho al campo que quieres extraer; selecciona `Copy` > `Selected`. Sólo haría falta limpiar el resto de la URL ya que te dará el endpoint completo.

```bash
Q4: praetorial-gears.000webhostapp.com
``` 

#### Q5: The user then executed the suspicious application found in the ZIP archive. What is the process PID?

Para este utilizaremos `volatility`, pero antes de jugar con él, necesitamos saber qué proceso buscamos.

Para esto, descargamos el `zip` de la captura de red; 

![UTMP]({{ "/images/Trojan/Downloadzip.png" | relative_url }}){: .align-center}


Y listamos el archivo:

![UTMP]({{ "/images/Trojan/Listzip.png" | relative_url }}){: .align-center}

Entonces, el ejecutable malicioso es `Recovery_Setup.exe`

Entonces, utilizamos `vol` junto con `pslist` para buscar el proceso:

```js
vol -f memory.vmem windows.pslist
```

Verás que mostrará todos los procesos capturados, pero, uno de ellos, tiene el mismo nombre que nuestro ejecutable.

![UTMP]({{ "/images/Trojan/Q5.png" | relative_url }}){: .align-center}

Mostrando nuestra respuesta en el campo `PID`

```bash
Q5: 484
``` 

#### Q6: What is the full path of the suspicious process?

Ahora, para mostrar el path completo de ejecución necesitamos `pstree` pero con la flag `--pid num` ya que si lo ejecutamos sólo, nos mostrará todo el árbol de ejecución de la captura (mucha información)

```js
vol -f memory.vmem windows.pstree --pid 484
```

Si examinamos con atención, veremos que no fue lo único que se ejecutó, pero nuestro proceso sigue ahí junto con su path de ejecución.

![UTMP]({{ "/images/Trojan/Q6.png" | relative_url }}){: .align-center}

```bash
Q6: C:\Users\John\Downloads\Data_Recovery\Recovery_Setup.exe
``` 

#### Q7: What is the SHA-256 hash of the suspicious executable?

Para esto sólo es necesario descomprimir el `zip` de la captura; y utilizar `sha256sum`

```bash
sha256sum Recovery_Setup.exe
```

![UTMP]({{ "/images/Trojan/Q7.png" | relative_url }}){: .align-center}


```bash
Q7: C34601c5da3501f6ee0efce18de7e6145153ecfac2ce2019ec52e1535a4b3193
``` 

#### Q8: When was the malicious program first executed?

Para esto requrirás de otro programa: `FTK Imager` que sólo está disponible para windows; así que estarás de suerte si tu máquina puede ejecutar máquinas virtuales. Mi recomendación, instalar `QUEMY + KVM` que resulta mucho más ligera que Virtualbox y VMWare, preciada para los equipos no tan potentes.

De cualquier forma; También necesitarás registrarte en la plataforma para descargar `FTK Imager` pero igual, es gratuito.

Cuando abras la herramienta, tienes que seleccionar File y Añadir nueva evidencia; en el menú, seleccionarás `Image File` y seleccionas la del disco.

Al procesarse, verás el root de la imagen para que puedas navegar entre los archivos; los que buscamos es el `amcache`.

![UTMP]({{ "/images/Trojan/EvidenceTree.png" | relative_url }}){: .align-center}

El archivo (en realidad una base de datos) `amcache` bajo `ROOT:\Windows\AppCOmpat\Programs\Amcache.hve` que almacena información sobre compatibilidad y ejecución de programas; En forensia digital, lo podemos utilizar para determinar qué programas se ejecutaron (aún si ya fueron eliminados); Pueden verlo como el _historial oculto de programas ejecutados_ en sistemas windows, claro. Entonces, ya con nuestro tree, podemos examinar el hive... ¿cierto?

__No__, Está en formato binario y para leerlo necesitamos un _parser_, por suerte hay muchos que podemos utilizar. En mi caso `regripper` que está para __linux__.

Por esta razón, necesitas exportarlo y moverlo a tu máquina y puedes hacerlo únicamente selecionando el `.hve`, click derecho y `Export Files`

![UTMP]({{ "/images/Trojan/Export.png" | relative_url }}){: .align-center}

Para practicar _trasnferencias de archivos windows>linux_ utilizamos `smbserver` de _Impacket_ para montar un servidor smb en nuestra máquina linux habilitando `smb2`, poniendo el nombre a nuestro share y la ubicación del share en nuestros archivos locales:

```java
❯ sudo smbserver.py -smb2support shared .
[sudo] password for n1c37ry05: 
Impacket v0.13.0.dev0+20250605.14806.5f78065c - Copyright Fortra, LLC and its affiliated companies 

[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
```

Una vez montado, utilizando cmd debemos mapear el share con una letra (por facilidad), además utilizar este tipo de transferencia suele ser menos detectada que otros tipos de subida de archivos, ya que, seguimos utilizando utilidades del sistema como lo es `smb` (otra cosa es que detecten el share externo o desconocido haha).

Para _mapear el share_ utilizamos `net` y es probable que nos pidan credenciales y hay una de dos sopas: que sólo te las pida, no indique nada como es mi caso:

```
net use F: \\192.168.122.1\shared
Enter the user name for '192.168.122.1': a
Enter the password for 192.168.122.1: <a>
The command completed successfully.
```

O también puede ocurrir que te indique `STATUS_ACCESS_DENIED` que es causado por lo siguiente: A veces, la máquina está con la configuración de _enforce de RestrictAnonymous_ (para __restringir conexiones SMB anónimas__) (administrada en: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous`) donde:

* `0` Permite el acceso anónimo
* `1` Acceso anónimo restringido
* `2` No permite el acceso anónimo (por defecto en sistemas recientes)

Y en el caso de que esté configurada con el no permitido, es necesario agregar en el `smbserver` lo siguiente: `-username testuser -password P@ssw0rd`.

Volviendo al caso, ya con el archivo, instalamos regripper:

```
sudo apt install regripper
```

Y finalmente, examinamos el `Amcache.hve`

```java
❯ regripper -r Amcache.hve -f amcache

Parsed Plugins file.
Launching amcache v.20200515
amcache v.20200515
(amcache) Parse AmCache.hve file

***InventoryApplicationFile***
```

Ahora, examinamos la salida y veremos un poco oculto, nuestro programa y su hora de ejecución:


![UTMP]({{ "/images/Trojan/Q8.png" | relative_url }}){: .align-center}

```bash
Q8: 2023-05-30 02:06:29
``` 

#### Q9: How many times in total has the malicious application been executed?

Volviendo a `FTK Imager`; examinamos `ROOT:\Windows\AppCompat\Programs\Install` para revisar programas instalados y sus metadatos; encontramos 5 archivos, 4 `.txt` que si los investigamos, veremos que los 2 pares, apuntan a nuestro ejecutable:

![UTMP]({{ "/images/Trojan/Q9.png" | relative_url }}){: .align-center}

```bash
Q9: 2
``` 

#### Q10: The malicious application references two .TMP files, one is IS-NJBAT.TMP, which is the other?

Ahora, sabiendo que hace referencia a más archivos, es probable que los encontremos en el `prefetch`, el cual es un archivo donde se guardan ciertos datos para acelerar la ejecución en el sistema operativo (de estos datos incluyen nombre, veces ejecutado, última fecha de ejecución, lista de archivos y bibliotecas cargadas) donde por éste último punto, es por lo que investigamos ahí.

Ordenando por fecha, podremos ver 2 archivos TMP surgidos poco después de la primera ejecución:

![UTMP]({{ "/images/Trojan/Q10.png" | relative_url }}){: .align-center}

```bash
Q10: IS-R7RFP.TMP
``` 

#### Q11: How many of the URLs contacted by the malicious application were detected as malicious by VirusTotal?

Ahora, Volvamos a la captura de tráfico!. Podrá bastarnos con filtrar por `HTTP`, el `source IP 192.168.116.133` y buscar la descarga del `zip` y buscar entre el tráfico generado después de la descarga; si quieres una forma un poco más bruta, puedes también ordenar los `destination IP` para que parezcan agrupados; y copiar y pegar cada una de las urls dentro del paquete, o... te fijas también cuales se generaron poco después de la descarga del `zip` y descartando las IP o direcciones URL que sean legítimas, como las de microsoft; y... tarde o temprano verás las siguietes:

![UTMP]({{ "/images/Trojan/Q11.png" | relative_url }}){: .align-center}

Que notaremos que en VT están flageadas.

```bash
Q11: 4
``` 

#### Q12: The malicious application downloaded a binary file from one of the C2 URLs, what is the name of the file?

Esta es bastante sencilla, una vez ubicados los paquetes, tenemos sólo 2 opciones en a primera vista `stuk.php` y `puk.php`, ¿Por qué descarto `dll.php`? En primera, el repetir mucho el patrón de GET hacia un mismo recurso, constantemente (2 segundos entre petición y petición) es un muy fuerte indicativo que sea sólo __la comunicación con el C2__ junto con lo siguiente: _Respuestas al mínimo_

![UTMP]({{ "/images/Trojan/dllphp.png" | relative_url }}){: .align-center}

Entonces, nos dirigimos a `stuk.php` y seguimos su _traza TCP_, 

![UTMP]({{ "/images/Trojan/Q12.png" | relative_url }}){: .align-center}

Y notamos como después de consultar `stuk.php`, hace el request de `puk.php` e inicia una descarga

```bash
Q12: puk.php
``` 

#### Q13: Can you find any indication of the actual name and version of the program that the malware is pretending to be?

Para esta me he perdido completamente :, 

Tuve que pedir ayuda a un compañero y me hizo el gancho a este [writeup](https://medium.com/@mercysitialo/htb-trojan-cc9f177b8da1) Para obtener la respuesta; y parece que donde estaba la respuesta, en `malware bazaar` han quitado el campo donde venía la respuesta :p

![UTMP]({{ "/images/Trojan/Q13.png" | relative_url }}){: .align-center}

```bash
Q13: FinalRecovery v3.0.7.0325
``` 

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.
