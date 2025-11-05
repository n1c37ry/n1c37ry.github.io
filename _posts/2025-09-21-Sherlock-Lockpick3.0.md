---
layout: single
title: "Sherlocks - Lockpick3.0 (HTB)"
author_profile: true
published: true
---

Los sherlocks (De HackTheBox) son retos gamificados enfocados a __Blue Team__, en ellos, se encuentran distintas situaciones donde uno debe utilizar herramientas de analsis y artefactos para completar las tareas. Y claro, hay __categorías__ según lo que quieras entrenar, como por ejemplo _Malware Analysis_  que se enfocan en el __análsis de artefactos y archivos maliciosos__ con el objetivo de entender su funcionalidad, origen e impacto, para poder crear medidas de detección mejorando la seguridad del entorno.

![UTMP]({{ "/images/Lockpick3/logo.png" | relative_url }}){: .align-center}

## Resumen Lockpick3.0

En este sherlock nos enfocaremos púramente en __análisis estático__ de un exfiltrador de datos; La principal barrera es encontrar la llave, pero una vez encontrada, se vuelve muy sencillo; la verdad es que me explayé bastante en cuanto a analizar las funciones, sobre todo al principio, por lo que aunque considero que fue un Sherlock pequeño, sí fue más puro texto, y si te interesa saber sobre cómo funciona y se ejecuta el código quizá sea buena lectura :), de cualquier forma, sus comentarios son bienvenidos ^-^

## Laboratorio

### Descripción

The threat actors of the Lockpick variant of Ransomware seem to have increased their skillset. Thankfully on this occasion they only hit a development, non production server. We require your assistance performing some reverse engineering of the payload in addition to some analysis of some relevant artifacts. Interestingly we can't find evidence of remote access so there is likely an insider threat.... Good luck! Please note on the day of release this is being utilised for a workshop, however will still be available (and free).

### Desarrollo

Entonces, para iniciar el laboratorio, iniciamos como siempre: Descargamos el archivo y luego __Enumeramos su contenido__ para tener una idea de a lo que nos vamos a enfrentar:

```js
❯ 7z l lockpick3.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs AMD Ryzen 7 4700U with Radeon Graphics          (860F01),ASM,AES-NI)

Scanning the drive for archives:
1 file, 586254887 bytes (560 MiB)

Listing archive: lockpick3.zip

--
Path = lockpick3.zip
Type = zip
Physical Size = 586254887

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-06-03 10:43:35 .....        23144         6458  ubuntu-client
2024-06-03 08:56:38 .....   2147483648    585682141  ubuntu-client-Snapshot2.vmem
2024-06-03 09:39:56 .....      5368436       565696  ubuntu-client-Snapshot2.vmsn
------------------- ----- ------------ ------------  ------------------------
2024-06-03 10:43:35         2152875228    586254295  3 files
```

De forma sorprendente, fuera de lo que me imaginaba, tenemos una captura de memoria, un archivo sin extensión y un snapshot de VMware; por lo que probablemente tendremos o que convertir el `vmsn` a una captura de memoria o bien, montarlo en nuestro sistema aislado (pero lo iremos viendo sobre la marcha). De cualquier modo, utilizamos la contraseña que nos brinda HTB para descomprimir los archivos: `hacktheblue`

```js
❯ 7z x lockpick3.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs AMD Ryzen 7 4700U with Radeon Graphics          (860F01),ASM,AES-NI)

Scanning the drive for archives:
1 file, 586254887 bytes (560 MiB)

Extracting archive: lockpick3.zip
--
Path = lockpick3.zip
Type = zip
Physical Size = 586254887

    
Enter password (will not be echoed):
Everything is Ok                     

Files: 3
Size:       2152875228
Compressed: 586254887
```

Y con ello, podremos empezar a trabajar.

#### Q1: Please confirm the file hash of the malware? (MD5)

Como paso inicial, de los 3 archivos, sólo tenemos uno sin extensión, por lo que podemos examinarlo con `file`

```js
❯ file ubuntu-client
ubuntu-client: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=595b1b2a3a1451774884ddc5d265e25a44e21574, for GNU/Linux 3.2.0, stripped
```

Como se trata de un `ELF` o _Executable and Linkable Format_ podemos hacer todo el proceso desde nuestro sistema linux, a parte, de que es un ejecutable, es casi seguro que sea la muestra que tendremos que estar analizando. Así que para la primer pregunta, tenemos que obtener su `md5`

```js
❯ md5sum ubuntu-client
a2444b61b65be96fcae65924dee8febd  ubuntu-client
```

```bash
Q1: a2444b61b65be96fcae65924dee8febd
```

#### Q2: Please confirm the XOR string utilised by the attacker for obfuscation?

Ahora, empezamos con el análisis de código:

Abrimos `ghidra` y dejamos que haga el análisis sobre el archivo. Cuando ya lo haya hecho; nos dirigiremos a entry (Me estaré apoyando mucho en las imágenes, algunas tendrán nombres distintos gracias a que las renombré)

![UTMP]({{ "/images/Lockpick3/libcstartmain.png" | relative_url }}){: .align-center}

Iniciamos con la primera función `__libc_start_main`, en C, esta librería es importante ya que es la que inicia toda la iniciación necesaria para el call hacia main.

Podemos observar la [estructura desde aquí](https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html):

```js
int __libc_start_main(int (*main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
```

1. El primer argumento es la llamada a la función `main`
2. El segundo y tercer argumento son los argumentos de la ejecución y su dirección en memoria.
2. El 4to argumento es la llamada a la inicialización de main (que muchas veces declara variables globales u otras utilidades que utilizará `main`)
3. El 5to argumento es el exit de `main` (cuando termina la ejecución de `main`, se ejecuta este bloque).

Entonces es lógico iniciar por el `init_main`; si buscamos algo útil, nos encontraremos con un pequeño loop while:

![UTMP]({{ "/images/Lockpick3/init_main.png" | relative_url }}){: .align-center}

Lo que hace a grandes rasgos es que inicializa el contenido de lo que esté en el arreglo `__DT_INIT_ARRAY` y si observamos a dónde apunta...

![UTMP]({{ "/images/Lockpick3/init_main_init_o.png" | relative_url }}){: .align-center}

Y si seguimos a dónde nos lleva, encontramos un bloque como este:

![UTMP]({{ "/images/Lockpick3/init_o.png" | relative_url }}){: .align-center}

Observa dónde indiqué, el `_ITM_registerTMCloneTable` es una instrucción para preparar y registrar memoria transaccional; (El cual protege a un recurso de un fallo de conficto cuando están interactuando 2 o más hilos de ejecución con un mismo recurso). Así, que no tenemos nada malicioso en esta parte; por lo que volvemos al punto de entrada (¿no está de más revisar todo no? hahaha).

Al entrar a la función mapeada como `main`; se llama múltiples veces a la misma función así que podemos verificarla.

![UTMP]({{ "/images/Lockpick3/XOR_main.png" | relative_url }}){: .align-center}

Entrando notamos un `^` que indica una operación XOR; esto a primera vista y a grandes rasgos puedes llegar a esta conclusión:

_La función llama a un `for loop` que se ejecuta `param2` veces; la operación XOR decodifica lo que esté en la dirección `param_1`+`counter` utilizando la llave contenida en `param3`+`counter`_ así que estamos tentando la respuesta; si observas en la definición de la función, notarás el  valor de `param_3` como un long; así que volvemos una función atrás para renombrar para aclarar cómo se llama la función:

![UTMP]({{ "/images/Lockpick3/XOR.png" | relative_url }}){: .align-center}

Entonces, concatenando lo que hay dentro de la función puedes interpretarlo como la imagen; la `xorKey` y su `size`; los primeros argumentos recordemos que es la dirección del primer byte a decodificar y el siguiente argumento, cuántos decodificar; notarán el `& 0xffffffff` que es una máscara de bytes; el cual como sabemos, `xorKey_size` puede ser un long, y esta máscara asegura que sea un tamaño de 32bits sin signo.

Entonces, ¿qué es `param_2[1]` como se define en la linea 16? ¿Recuerdan la definición de `main libc`? Pues justo como mencionamos es __el primer argumento llamado en al ejecución!__.

Entonces, nos movemos a la captura de memoria para analizarla con `volatility3`; pero si la ejecutamos directamente en crudo, es probable que indique lo siguiente: 

```js
❯ ./volatility3-2.26.0/vol.py -f ubuntu-client-Snapshot2.vmem linux.bash
Volatility 3 Framework 2.26.0
Progress:  100.00		Stacking attempts finished
Unsatisfied requirement plugins.Bash.kernel.layer_name: 
Unsatisfied requirement plugins.Bash.kernel.symbol_table_name: 

A translation layer requirement was not fulfilled.  Please verify that:
	A file was provided to create this layer (by -f, --single-location or by config)
	The file exists and is readable
	The file is a valid memory image and was acquired cleanly

A symbol table requirement was not fulfilled.  Please verify that:
	The associated translation layer requirement was fulfilled
	You have the correct symbol file for the requirement
	The symbol file is under the correct directory or zip file
	The symbol file is named appropriately or contains the correct banner

Unable to validate the plugin requirements: ['plugins.Bash.kernel.layer_name', 'plugins.Bash.kernel.symbol_table_name']
```

Esto es por que no hemos importado la firma específica del sistema operativo, para ello, necesitamos enumerar el banner de la captura:

```js
❯ ./volatility3-2.26.0/vol.py -f ubuntu-client-Snapshot2.vmem banners
Volatility 3 Framework 2.26.0
Progress:  100.00		PDB scanning finished                  
Offset	Banner

0x32857fa8	Linux version 5.4.0-163-generic (buildd@lcy02-amd64-067) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #180-Ubuntu SMP Tue Sep 5 13:21:23 UTC 2023 (Ubuntu 5.4.0-163.180-generic 5.4.246)
```

Ahora, descargar el json con las firmas para saber cuál descargar; al descargarlo, hacemos un grep con la primera parte del banner; la ruta al final donde esté "...json.xyz" lo copiamos

```js
❯ wget https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/banners/banners_plain.json

❯ grep -A 2 'Linux version 5.4.0-163-generic (buildd@lcy02-amd64-067) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2))' banners_plain.json          volenv
 "Linux version 5.4.0-163-generic (buildd@lcy02-amd64-067) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #180-Ubuntu SMP Tue Sep 5 13:21:23 UTC 2023 (Ubuntu 5.4.0-163.180-generic 5.4.246)": [
  "Ubuntu/amd64/5.4.0/163/generic/Ubuntu_5.4.0-163-generic_5.4.0-163.180_amd64.json.xz"
 ],
```

Ahora, creamos un directorio en `volatility3_installation>/volatility3/symbols/linux/` y descargamos:

```js
❯  wget https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/Ubuntu/amd64/5.4.0/163/generic/Ubuntu_5.4.0-163-generic_5.4.0-163.180_amd64.json.xz -P volatility3-2.26.0/volatility3/symbols/linux
```

Y ahora, sí, deberíamos poder utilizar `volatility3` sin problemas. Entonces, sabiendo que debió ser ejecutado con un argumento, buscamos ejecuciones de bash:

```js
❯ ./volatility3-2.26.0/vol.py -f ubuntu-client-Snapshot2.vmem linux.bash

<SNIP!>
22683	bash	2024-06-03 15:51:38.000000 UTC	./ubuntu-client xGonaGive1t2Ya
22683	bash	2024-06-03 15:54:24.000000 UTC	sudo apt-get install libcjson-dev
22683	bash	2024-06-03 15:54:31.000000 UTC	./ubuntu-client xGonaGive1t2Ya
```

Y tenemos nuestra respuesta:

```js
Q2: xGonaGive1t2Ya
```

#### Q3: What is the API endpoint utilised to retrieve the key?

Algo largo el camino, ¿no?, Continuemos:

Para encontrar el API endpoint, seguramente tendremos que desencriptar las cadenas de la función XOR; y el flujo es bastante simple:

1. Dirigirse a la dirección de memoria del primer argumento de la llamada

![UTMP]({{ "/images/Lockpick3/XOR_D_1.png" | relative_url }}){: .align-center}

2. Copiar todos los datos y pegarlos en un archivo (limpiando lo de hasta arriba para dejar sólo los hexadecimales y las direcciones)

```js
❯ cat bytes_enc                                                                                                                         volenv
        00106020 10              ??         10h
        00106021 33              ??         33h    3
        00106022 1b              ??         1Bh
        00106023 1e              ??         1Eh
        00106024 1d              ??         1Dh
        00106025 5b              ??         5Bh    [
        00106026 68              ??         68h    h
        00106027 46              ??         46h    F
        00106028 06              ??         06h
        <SNIP>
```

3. Utilizar bash scripting para obtener los valores hexadecimales

```js
❯ cat bytes_enc | cut -d'h' -f1 | awk '{print $NF}' | xargs
11 33 1B 1E 1A 5B 68 46 06 A9 28 1A 59 2D 0E 16 6A 0E 1E 1E 4C 74 18 1F 0B 38 5A 5D 32 05 11 20 56 1A 0F 0D 28 0A 13 04 27 5A 53 29 12 57
```

4. Llevarlo a cyberchef; para transformarlo de hex aplicando XOR con la clave 

![UTMP]({{ "/images/Lockpick3/cyberchef_1.png" | relative_url }}){: .align-center}

5. Repetir con las funciones.

Repetitivo, algo manual pero eficaz diría yo.

Luego de que estés desencriptando todo, verás que obtendrás algunas respuestas futuras, pero las tocaremos en su momento; por el momento necesitaremos seguir examinando el código para encontrar la respuesta; justo después de los bloques obfuscados, nos encontracmos con una función:

![UTMP]({{ "/images/Lockpick3/Q3_1.png" | relative_url }}){: .align-center}

Así que la examinamos y un vistazo rápido nos revela el endpoint; y justo antes, está concatenando el dominio dentro de las cadenas que estuvimos obfuscando, así que esa sería la respuesta.

```bash
Q3: https://plankt-app-3qiqgq.indigiocean.app/connect
```

#### Q4: What is the API endpoint utilised for upload of files?

Ahora si observamos bien, podemos encontrar un pequeño `rabbit hole` para el análisis, algo informal (demasiado) pero funcional:

Sabemos que la función en la que estamos, sirve para obtener el `key`, es fácil concluirlo si observamos los strings a los que apuntan los datos:

![UTMP]({{ "/images/Lockpick3/rabbitQ4.png" | relative_url }}){: .align-center}

Si continuamos bajando, podemos ver strings interesantes:


![UTMP]({{ "/images/Lockpick3/rabbitQ4_1.png" | relative_url }}){: .align-center}

Y pronto, veremos un string, claramente sospechoso que apunta a nuestra respuesta:

![UTMP]({{ "/images/Lockpick3/rabbitQ4_2.png" | relative_url }}){: .align-center}

Podemos seguir desde donde fue llamada y sabremos que estaremos en la función que se utiliza para subir archivos.

![UTMP]({{ "/images/Lockpick3/Q4_1.png" | relative_url }}){: .align-center}

Siendo ahora esta, nuestra respuesta:

```bash
Q4: https://plankt-app-3qiqgq.indigiocean.app/upload/
```

Ahora, si quedas con dudas de qué es `param_2` podrás ir persiguiendo la definición hasta `main` que declara: `undefined1 local_118 [264];`; Si investigamos la función del `KeyRetFunction` podrás ver que se le asigna el valor del `client-id`

#### Q5: What is the name of the service created by the malware?

Ahora, de nuestra lista de strings decodificados, encontraremos uno que nos da la respuesta:

```js
[Unit]
Description=Ubuntu Running
After=network.target
[Service]
ExecStart=/usr/bin/ubuntu-run xGonnaGiveIt2Ya
Restart=always
User=root
[Install]
WantedBy=multi-user.targetiveIt2YaxGonnaGiveIt

systemctl daemon-reload && systemctl enable ubuntu.service <SNIP!>
```

Por lo cual, nuestra respuesta será el que defina después de `enable`:

```bash
Q5: ubuntu.service
```

#### Q6: What is the technique ID utilised by the attacker for persistence?

Ahora, un poco de investigación en [MITRE ATT&CK](https://attack.mitre.org/tactics/TA0003/) Nos dará la respuesta; podemos investigar uno por uno o buscar `systemd` para alguna coincidencia:

```bash
Q6: T1543.003
```


###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.