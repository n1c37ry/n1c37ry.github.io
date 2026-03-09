---
layout: single
title: "Sherlocks - CafePoisoning (HTB)"
author_profile: true
published: true
toc: true
toc_sticky: true
comments: true
---

Los sherlocks (De HackTheBox) son retos gamificados enfocados a __Blue Team__, en ellos, se encuentran distintas situaciones donde uno debe utilizar herramientas de analsis y artefactos para completar las tareas. En este laboratorio _CafePoisoning_ Estaremos explorando un ataque de __ARP Poison__, esta técnica sirve como método de ejecución principal para lograr un _MiTM_ en la red.

![UTMP]({{ "/images/CafePoisoning/logo.png" | relative_url }}){: .align-center}

## Resumen CafePoisoning

Como mencionamos antes, este laboratorio estaremos explorando el cómo se ve un __ARP Poison__ tanto a nivel de red (mediante una captura de __Wireshark__), luego un poquito de __Malware Analysis__ con la captura forense del equipo, estaremos explorando qué fue lo que hizo el atacante.

## Laboratorio

### Descripción

While grabbing coffee at a cafe, I connected to public Wi-Fi and started a Windows update. The process never completed—it just kept running. As a digital forensics expert, can you help investigate?

### Desarrollo

Iniciamos descargando los artefactos en nuestro equipo de investigación, recuerda que algunos de estos comprimidos (si no es que la mayoría), tienen artefactos potencialmente dañinos para nuestro equipo, por lo que debemos tener en cuenta el aislamiento del equipo de investigación.

Habiendo dicho eso, iniciamos con el zip de la imagen forense y el pcapng

![UTMP]({{ "/images/CafePoisoning/Des_ls.png" | relative_url }}){: .align-center}

Hacemos un reconocimiento incial de ambos archivos, esto con el objetivo de conocer algunas propiedades, como cuántos paquetes se capturaron, los _top talkers_ o si el comprimido zip sí tiene una imagen forense:

![UTMP]({{ "/images/CafePoisoning/Cap_properties.png" | relative_url }}){: .align-center}

![UTMP]({{ "/images/CafePoisoning/Top_Talkers.png" | relative_url }}){: .align-center}

![UTMP]({{ "/images/CafePoisoning/For_Img_sample.png" | relative_url }}){: .align-center}

Esta última imagen, con la presencia de los _prefetch_ podemos indicar con mayor certeza, que sí es una imagen forense y que en un rato, las tiradas irán por este lado.

Conociendo un poco de los archivos, ya podemos iniciar:

#### Q1: The attacker performed a host discovery scan to identify devices on the network. Provide the start time of this activity in UTC.

Bien, existen muchas formas de hacer reconocimiento a la red, esto depende mucho del entorno (si es corporativo por ejemplo, puedes tirar de protocolos de resolución de nombres como `mDNS`, `LLMNR`, `NBNS`...) escaneo por puertos (Si el endpoint responde de alguna forma, tenga o no puerto abierto, confirmaría su presencia), por `IPv6`... `ICMP` y nuestra estrella de hoy: `ARP`. 

Lo que hago generalmente en capturas, es hacer un poco de scroll para ver si hay algo muy extraño, como un montón de paquetes originándose desde un mismo endpoint/dirección; en un rato, si empezamos a explorar la captura de esta manera, tarde o temprano llegaremos a ver...

![UTMP]({{ "/images/CafePoisoning/Q1.png" | relative_url }}){: .align-center}

Observa que las IPs solicitadas no son ni repetidas ni van tan en orden, esto indica fuertemente el uso de alguna herramienta de escaneo, si aún tenemos un poco de dudas, podemos verificar si el atacante hace el barrido completo de la subred:

Primero, seleccionamos alguno de los paquetes sospechosos, seleccionamos `source`, clic derecho y `Preparar como filtro`

![UTMP]({{ "/images/CafePoisoning/Filters_Prep.png" | relative_url }}){: .align-center}

Para completar el filtro, añadimos `&& arp` pues sólo nos interesan _por ahora_ los paquetes __ARP__, cuando obtengamos los resultados, podemos seleccionar, todos los paquetes en los que esté preguntando _quién tiene cierta IP_:

![UTMP]({{ "/images/CafePoisoning/Confirmation.png" | relative_url }}){: .align-center}

El seleccionar todos los paquetes indicarán 254 requests, es decir, escaneo toda la subred. Ya sin ningún espacio para dudas, podemos confirmar que esto fue el escaneo por parte del atacante, e inició en el momento que envía el primer _ARP Request_ de la IP `192.168.1.181`

![UTMP]({{ "/images/CafePoisoning/Q1_1.png" | relative_url }}){: .align-center}

```bash
Q1: 2025-03-10 21:07:05
```

#### Q2: The attacker launched an ARP poisoning attack. Provide the start time in UTC

Ahora sí, _¿Qué es un ARP Poisoning Attack?_:

Un __ARP Poisoning Attack__ es una técnica de envenenamiento de las tablas ARP de los equipos; ARP o _Address Resolution Protocol_ mapea las direcciones MAC (De capa 2) y las relaciona con su equivalente o identidad en direcciones IP (Capa 3), este mapeo, el equipo lo registra en su tabla ARP.

La vulnerabilidad ocurre en el funcionamiento de ARP: ARP _No tiene estado_, es decir, cualquier equipo puede decirle a otro, "oye, la dirección 192.168.0.20 la tengo YO", el equipo, sin ninguna protección, le cree y cambia su tabla ARP.

El __ARP Poisoning__ entra en el momento que un atacante, envía estos paquetes ARP con su dirección (_envenenando la tabla ARP_) diciendo por ejemplo: "Oye, equipo Windows, yo soy la 192.168.0.1 (el gateway)" y luego, va con el gateway y le dice: "Oye, gateway, yo soy la 192.168.0.20 (Windows)" y de esta manera, la comunicación fluye del origen, al atacante y luego al destino original.

Bien, ya con el tiempo de inicio, y la identidad del atacante (lo que también nos resuelve la siguiente pregunta), podemos empezar a filtrar la captura de mejor manera por si necesitamos más detalles de las acciones del atacante, para este momento, sabiendo la naturaleza del ataque, no nos sirve revisar las direcciones IP (capa 3), sino revisar la dirección MAC (Capa 2) y no perdernos de los eventos de red, confundiéndonos quién tiene qué dirección;

Aún con el mismo filtro que mencionamos antes:

```bash
eth.src == 08:00:27:9b:8b:bd && arp
```

Vemos inmediatamente más abajo del descubrimiento de hosts; observen la dirección de ambos equipos (Atacante -> Equipo Huawei): 

![UTMP]({{ "/images/CafePoisoning/Q2.png" | relative_url }}){: .align-center}

Y Nota cómo registra la dirección IP (Viendo que es la misma MAC del atacante) en la comunicación entre Atacante -> Endpoint

![UTMP]({{ "/images/CafePoisoning/Q2_1.png" | relative_url }}){: .align-center}

Esto es justo cómo se ve un __ARP Poisoning Attack__ El atacante haciendo creer que es el destino del otro equipo.

```bash
Q2: 2025-03-10 21:07:33
```

#### Q3: What MAC address did the attacker use during the ARP poisoning attack?

Esto se resuelve haciendo el paso anterior; sabemos cuál es el atacante desde que hace el escaneo como desde que hace el envenenamiento:

```bash
Q3: 08:00:27:9b:8b:bd
```

#### Q4: What is the gateway IP address of the network?

Para saber el gateway podemos _intuir_ que es la dirección que le está proponiendo a la víctima o, por el método largo, podemos filtrar por la MAC del equipo de Huawei (que investigando un poco, es un fabricante de equipos de red (pero no limitado a))

Copiamos la dirección MAC del equipo (`Target MAC address > Copy > Copy As Value`) y lo utilizamos en el filtro:

```bash
eth.src == 58:7f:66:df:fe:02 && arp
```

Y observemos, que estos paquetes son __ANTES__ del __ARP Poisoning__

![UTMP]({{ "/images/CafePoisoning/Q4_Confirmation.png" | relative_url }}){: .align-center}

```bash
Q4: 192.168.1.90
```

#### Q5: Which spoofed domain was accessed by the compromised user?

Bien, recopilemos un poco lo que sabemos, el atacante hizo __ARP Poisoning__, afectó principalmente a 2 equipos: El gateway y lo que parece ser la víctima (`1c:bf:ce:d9:b2:db`), según la pregunta, la victima accedió a un dominio; podemos entonces, buscar la actividad `http` posterior al envenenamiento, aunque para esto, sólo tendríamos que fijarnos en el timestamp y utilizando el filtro:

```bash
eth.src == 1c:bf:ce:d9:b2:db && http
```

Esto nos mostrará la actividad `http` de la víctima:

![UTMP]({{ "/images/CafePoisoning/Q5.png" | relative_url }}){: .align-center}

Como podemos observar, el paquete va hacia el atacante y podemos ver el contenido del paquete `HTTP` indicando a qué dominio está accediendo:

```bash
Q5: devx-corp.net
```

#### Q6: Before the attack the victim accessed this domain's legitimate web server. What was its IP address?

Por ahora, dejamos a un lado la captura, para esta pregunta no nos mostrará mucho más, así que nos moveremos a la imagen forense que tenemos y extraer el archivo;

Abrimos nuestro laboratorio/máquina de análisis windows (ya que facilita __Mucho__ el análisis) y de aquí tenemos varias opciones (donde claro, siempre depende el entorno).

Una opción es revisar los logs (en el caso que tenga `sysmon` y buscar eventos relacionados con el DNS) y buscar el dominio de la pregunta anterior; pero... lamentablemente no tenemos logs de `sysmon`; por lo que tendremos que recurrir a otras maneras, como revisar la caché del navegador:

Cuando un usuario utiliza su navegador, __mucha información de las páginas que visita se queda guardada internamente__, esto para dar una mejor experiencia de usuario (así el navegador evita volver a descargar recursos del servidor y acelerar la experiencia de navegación), ejemplo de estos recursos son imágenes, scripts, estructuras básicas de las páginas... pero, hay metadatos que podemos extraer con programas como `ChromeCacheView`, donde podremos ver las páginas visitadas, el tamaño del recurso guardado, el nombre del servidor y __hasta la IP del servidor__

Entonces, utilizando `ChromeCacheView`, buscamos el cache en la ruta `%USER%\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data`

![UTMP]({{ "/images/CafePoisoning/Q6_1.png" | relative_url }}){: .align-center}

Damos doble clic, y los detalles aparecerán:

![UTMP]({{ "/images/CafePoisoning/Q6.png" | relative_url }}){: .align-center}

```bash
Q6: 137.50.21.6
```

#### Q7: Identify the Wi-Fi network name (SSID) and the authentication algorithm used by the compromised user’s connection.

Excelente; toca identificar qué red utilizó la víctima.

Explorando la imagen, encontramos que tenemos disponible el `Microsoft-Windows-WLAN-AutoConfig%4Operational` donde podemos ver este tipo de datos:

Utilizando _Event Viewer_ en Windows de toda la vida, abrimos nuestro log en la ruta: `DESKTOP-TIT3D2T\C\Windows\System32\winevt\logs` 

![UTMP]({{ "/images/CafePoisoning/Q7_1.png" | relative_url }}){: .align-center}

Y en el _EventID 8001_ Encontramos los detalles de la conexión: 

![UTMP]({{ "/images/CafePoisoning/Q7_1.png" | relative_url }}){: .align-center}

```bash
Q7: Cuppa Ce:WPA2-Personal
```

#### Q8: Identify the download link used to fetch the malicious executable.

Ahora sí, volvemos a la captura para lo último; Si mal no recordamos, el último filtro con el `http` mostró al usuario ya conectándose al servidor malicioso y luego descargando un archivo llamado `update.exe`, examinemos esa entrada:

![UTMP]({{ "/images/CafePoisoning/Q8.png" | relative_url }}){: .align-center}

Justo lo que buscábamos:

```bash
Q8: http://192.168.1.11/update.exe
```

#### Q9: Identify the IP address and port number of the Command-and-Control (C2) server.

Ahora, para esta parte tendremos que examinar el ejecutable, yo utilizaré `ghidra`, pero si tienes la oportunidad de utilizar `IDA` pues mejor haha.

Bien, con `ghidra` abrimos el archivo y permitimos que lo examine.

Una vez que encuentre el entry point, deberemos de navegar por las funciones por si encontramos funcionalidades que podemos catalogar como maliciosas; para esta pregunta, lo más común para encontrar comunicaciones hechas por el ejecutable podremos buscar usos de la función `WSAConnect` de la librería `ws2_32.dll`; no es el único método (Por ejemplo, utilizar funciones de la librería `wininet.dll`, `winhttp.dll` entre muchos otros), pero es un buen punto de inicio; además, de que desde Ghidra, podemos verlo importado:

![UTMP]({{ "/images/CafePoisoning/Q9_1.png" | relative_url }}){: .align-center}

Bueno, desde el entry point, veremos varias funciones, si no llevas tanto con binarios, te acostumbrarás a identificar cuáles son las generadas por el CRT de windows; por ejemplo esta:

![UTMP]({{ "/images/CafePoisoning/Q9_3.png" | relative_url }}){: .align-center}

Y tarde o temprano, encontraremos esta función (está renombrada, así que esperarás un equivalente con `FUN_01010101` o algo así):

![UTMP]({{ "/images/CafePoisoning/Q9_2.png" | relative_url }}){: .align-center}

Dándole una hojeada, nos encontraremos con algo que nos recuerda a la descripción:

![UTMP]({{ "/images/CafePoisoning/Q9_0.png" | relative_url }}){: .align-center}

Esto puede reforzar la idea de que sea la función principal; ahora, si seguimos explorando desde aquí, podremos encontrar esta función:

![UTMP]({{ "/images/CafePoisoning/Q9_4.png" | relative_url }}){: .align-center}

La cual nos lleva a otra... pero si le damos suficiente atención, encontaremos la syscall de `WSAConnect` (La función que realiza __La Conexión__):

![UTMP]({{ "/images/CafePoisoning/Q9_5.png" | relative_url }}){: .align-center}

Estando en la función correcta (potencialmente), vemos una operación XOR:

![UTMP]({{ "/images/CafePoisoning/Q9_6.png" | relative_url }}){: .align-center}

Si lo ponemos en cyberchef, veremos que __es una IP__

![UTMP]({{ "/images/CafePoisoning/Q9_7.png" | relative_url }}){: .align-center}

Si vemos la lógica del decompilado, nos daremos cuenta que el flujo se controla por el valor de `uVar5` (Mientras sea menor que 12), en caso que sea menor, obtiene esta primera IP; cuando supera de ese valor, toma el otro valor (Te reto a decodificarlo haha, recuerda la estructura y cómo el procesador interpreta los datos Little Endian). En cualquiera de los 2 casos, el flujo pasa al siguiente bloque:

![UTMP]({{ "/images/CafePoisoning/Q9_8.png" | relative_url }}){: .align-center}

¿Por qué nos detenemos aquí?, pues la función `getaddrinfo` es una función que traduce una IP a un nombre de dominio, que puede ser usada para también comunicar al C2 donde sus argumentos son la IP/FQDN y el Puerto.

Observa que hay un Ampersand `&` esto indica una dirección de memoria; si le damos doble clic, veremos el puerto:

![UTMP]({{ "/images/CafePoisoning/Q9.png" | relative_url }}){: .align-center}

```bash
Q9: 192.168.1.11:5078
```

#### Q10: The malicious executable is designed to check the C2 server before connecting. Provide the domain name of the C2 server.

Bien, esta fue la parte más pesada, lo juro haha.

Para el nombre del dominio, basta con encontrar la otra operación XOR (Que tampoco está tan lejos de la que encontramos antes):

![UTMP]({{ "/images/CafePoisoning/Q10_1.png" | relative_url }}){: .align-center}

Esto, lo pasamos a cyberchef y tenemos nuestra respuesta.

![UTMP]({{ "/images/CafePoisoning/Q10.png" | relative_url }}){: .align-center}

```bash
Q10: s1rx-update.xyz
```

#### Q11: The malicious executable verifies privileges before execution to ensure it runs as administrator. Which Win32 API function is used for this check?

Un poco investigando en la función principal; podemos encontrar una llamada al inicio del `Main`:

![UTMP]({{ "/images/CafePoisoning/Q11.png" | relative_url }}){: .align-center}

```bash
Q11: CheckTokenMembership()
```

#### Q12: Which command was executed by the attacker to disable Windows Defender?

Bien, terminamos con el binario, ahora volvemos a la imagen forense, si investigamos en los logs de powershell, podremos encontrar que algo fue ejecutado después de la descarga del archivo (Siempre ten en cuenta el orden de los sucesos):

![UTMP]({{ "/images/CafePoisoning/Q12_1.png" | relative_url }}){: .align-center}

En él puede verse que un script fue ejecutado; cuando se trata de scripts en archivos podemos extraerlos desde la MFT si es que la tenemos disponible:

Esto lo podemos revisar desde `MFTExplorer` normalmente podríamos tirar de `prefectch` para saber el tiempo y la ruta de ejecución de powershell, pero si el adversario dejó los artefactos en lugres comunes como su carpeta de descargas, en AppData, en Temp... nos podremos ahorrar este paso.

Dicho y hecho, encontramos el script en descargas con su contenido (recuerda que si el contenido es pequeño, se guarda directamente acá):

![UTMP]({{ "/images/CafePoisoning/Q12_2.png" | relative_url }}){: .align-center}

```bash
Q12: Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
```

#### Q13: A persistence mechanism was created by the attacker. Provide the registry key used for persistence.


Ahora sí, la última pregunta; para esto sí tenemos que apoyarnos con los prefetch, ¿Por qué?, bueno, si buscamos una persistencia dentro del registro, el atacante debió ejecutar `reg.exe` o un comando parecido para registrar su ejecutable/backdoor; sabiendo esto, buscamos alguna entrada tanto en la MFT como en los prefetch.

Para los prefetch vamos a utilizar `PECmd.exe` y parsear todos los archivos para ver ejecuciones de `reg.exe`:

Primero, en la consola utilizamos:

```Java
.\PECmd.exe -d "..\..\DESKTOP-TIT3D2T\C\Windows\prefetch" --csv "c:/temp" --csvf file.csv
```

Y con el csv generado, exploramos las ejecuciones, donde obtenemos un hit:

![UTMP]({{ "/images/CafePoisoning/Q13_1.png" | relative_url }}){: .align-center}

Y ya con el timestamp, buscamos creaciones de archivos en el MFT a la misma hora; para ello, necesitamos igual, parsear de una forma muy similar el MFT:

```Java
.\MFTECmd.exe -f "C:\Users\johndoe\Desktop\DESKTOP-TIT3D2T\C\`$MFT" --csv "c:\temp\out"
```

Luego, podemos procesarlo tranquilamente como más querramos, en mi caso, estuve explorando tanto pocos segundos antes, como después:

```bash
cat 20260309113723_MFTECmd_\$MFT_Output.csv | grep "2025-03-10 21:15:13" 
,.\Windows\System32,Screensaver.scr,.scr,<SNIP>,Windows,2025-03-10 21:15:13.1022905,,2025-03-10 21:15:37.2893096,2025-03-10 21:15:13.1022905,2025-03-10 21:15:37.2893096,2025-03-10 21:15:13.1022905,2025-03-10 21:15:13.1022905,,108123464,527256833,510,,,
```

Este archivo salta a nuestros ojos, porque es un método de persistencia conocido, si no nos suena de mucho, podemos buscarla en internet:

![UTMP]({{ "/images/CafePoisoning/Q13.png" | relative_url }}){: .align-center}

Como observamos, __MITRE__ nos da la ruta del registro; como en primera: Se hizo apenas 2 segundos antes de la ejecución de reg.exe (que hizo el update del valor, esto lo podemos verificar con Registry Explorer :p), después de el inicio de la actividad del atacante, suele ser indicador suficiente para determinar que este fue el método de persistencia.

```bash
Q13: HKCU\Control Panel\Desktop
```

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

_En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!._

