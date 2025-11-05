---
layout: single
title: "Proyecto Gateway + Raspberry Pi"
author_profile: true
published: true
---

Este es una versión mejorada de un proyecto que realicé en la Universidad; en ese entonces, la implementación no funcionó ya que utilizaba `OpenWrt` y dos interfaces WiFi para hacer una conexión VPN; el objetivo del proyecto era crear una WiFi "Segura" separada de la red pública; digo "segura", por que toda la red, la enrutaba a WiFi usando un proveedor de VPN y claro, el "seguro" dependerá si confías en el proveedor.

Esta es una primera parte de este proyecto final, que la verdad es súmamente versatil en cuanto cómo puede ser utilizada, por ello, en futuros post volveremos a utilizar la RPI.

# Objetivo del Proyecto

El objetivo de este proyecto es algo similar, utilizando la RPI, haremos un gateway para controlar el flujo entre de ambos puntos de la red implementando varios componentes de seguridad: reglas de `iptables` que actuarán como firewall y un __IPS__ que será `Suricata` e implementando un DNS (`PiHole`) aprovechando la capacidad de la RPI y tener una forma de resolución de nombres local.

# Preparación

## Materiales

Estos son los componentes básicos para el proyecto:

* Raspberry Pi 4B (4GB RAM mínimo)
* Memoria Micro USB (16 GB Mínimo)
* Adaptador Micro USB -> USB
* Cable Ethernet 
* Cargador tipo C

Y los componentes que recomiendo para mejorar la funcionalidad y el alcance del proyecto:

* Segundo cable Ethernet
* Adaptador Ethernet -> USB
* Raspberry Case con ventilador
* Router preferido (en mi caso un Archer AX53)

## Flujo de Trabajo

Para esta primera parte, el RPI terminará funcionando como una gateway local (No seguro para redes Públicas) que __bloqueará anuncios, amenazas y con reglas de firewall__.

1. Configuraremos la RPI de forma básica con `SSH` e implementando buenas prácticas como acceso controlado y por llaves.
2. Instalaremos `PiHole` y lo configuraremos con algunas blacklists.
3. Implementaremos algunas reglas de Firewall para permitir el enrutamiento de la red local a Internet.
4. Granularemos las reglas de `iptables` para una protección mayor.
5. Instalaremos `Suricata` y configuraremos sus listas
6. Configuraremos el modo `IPS` de `suricata`
7. Modificaremos las `iptables` para que todo pase por suricata y nuestras reglas.

Será un post algo largo, pero valdrá la pena una vez implementado ya que con esta base, tienes mayor seguridad incluso en una red de la casa sólo con la configuración básica del modem; además que puedes jugar con la localización de la RPI para conectar un equipo que esté a mayor distancia, ideal para aquellos que su escritorio está lejos de donde llega el internet.

# Desarrollo

## 1. Configuración básica de la RPI con SSH

Primero; necesitamos descargar `Raspberry Pi Imager` desde la [página oficial](https://www.raspberrypi.com/software/)

![UTMP]({{ "/images/GatewayP/Raspbdownload.png" | relative_url }}){: .align-center}

No tiene complicación; claro, conectamos nuestra __memoria Micro USB__ con el __adaptador Micro USB -> USB__

Y seleccionamos el modelo de la RPI que corresponda y el sistema operativo al oficial de la Raspberry

![UTMP]({{ "/images/GatewayP/Pimager.png" | relative_url }}){: .align-center}

Después de seleccionar el almacenamiento de la USB, modificamos algunos detalles de la configuración:

Primero, en la pestaña `General` modificamos según plazca; un hostname, el nombre y contraseña, Configuramos el `Wireless LAN` ya que nos conectaremos mediante WiFi primero y luego veremos lo de conectar el ethernet.

![UTMP]({{ "/images/GatewayP/General_Pimager.png" | relative_url }}){: .align-center}

Para tener una seguridad mayor al momento de utilizar SSH, recomiendo sólo permitir la `public-key`, de igual forma, puedes usar contraseña para la autenticación y veremos una forma para generar la key en la RPI e importarla a nuestra computadora para utilizar esa `id rsa` y no la `public-key`; esto nos dará la ventaja de que si cambiamos de dispositivo, sólo bastará con importar la `id rsa` a este equipo nuevo.

![UTMP]({{ "/images/GatewayP/SSH_Pimager.png" | relative_url }}){: .align-center}

Bien, una vez configurado, continuaremos con la imagen y una vez terminado el proceso, conectamos la RPI y la `Micro USB`. Lo siguiente será encontrar la RPI en la red WiFi; para esto puedes ingresar al modem y buscarla según el hostname o el método que prefieras (hay más sencillos!)

Una vez encontrada, accedemos mediante `SSH`.

Lo primero que haremos es desactivar la autenticación por contraseña y evitar la autenticación como `root`, para ello modificaremos algunas lineas del archivo `/etc/ssh/sshd_config`

```bash
PermitRootLogin without-password
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
```

Luego, creamos el par `id rsa` con `ssh-keygen` desde el usuario normal (con los datos de este usuario)

```js
> cd ~/.ssh
> ssh-keygen -t rsa -b 4096
```

Y copiamos la llave privada generada (la que no tiene el `.pub`)

```js
// RPI
> cat id_rsa | base64 -w0
<SNIP!>
// Máquina principal
❯ echo "<SNIP!>" | base64 -d > id_rsa_pi
```
De esta manera, por si llegaramos a cambiar de equipo, podemos usar esta `id_rsa` para tener acceso a la RPI y añadir la clave `id_rsa.pub` del nuevo equipo al `~/.ssh/authorized_keys` de la RPI.

Y finalmente aplicamos la configuración con:

```js
> sudo systemctl restart ssh
```

### 1.1 Configuración de red interna

Ahora, antes de continuar, debemos hacer la red interna y hacer la distinción entre red externa (WiFi) y la red interna (Ethernet) para que en su configuración más sencilla, conectar un equipo o PC mediante Ethernet a la Raspberry y luego enrutarla a la red externa configurando el `nat` con `iptables`.

Para la sencillez de todos: utilizamos `nmtui` desde la RPI:

```
> sudo nmtui
```

Veremos la GUI donde también podremos añadir otra red de ser necesario, pero de momento, __No toques la configuración que tenga del WiFi__, si la modificas y no es correcta; ya no podrás conectarte a la RPI, __esta es otra razón por la que estamos creando la configuración para acceder mediante Ethernet__

Seleccionamos `Edit a connection` y deberíamos ver `Wired connection` o algo parecido y seleccionamos `Edit`

![UTMP]({{ "/images/GatewayP/nmtui.png" | relative_url }}){: .align-center}

Una vez dentro, sólo debemos modificar el campo `IPv4 CONFIGURATION` a `Manual` y asignarle una dirección IP a esta interface con la máscara que querramos la red interna:

![UTMP]({{ "/images/GatewayP/ethernetnmtui.png" | relative_url }}){: .align-center}

En nuestra máquina o PC con la que estamos configurando o bien, usaremos esta red, debemos hacer algo similar: 

1. Usar `nmtui` (o cualquier herramienta para configurar redes)
2. Acceder a `Edit a connection`
3. Modificar el `Wired connection` que corresponda
4. Indicar una dirección IP __Distinta de la configurada en la RPI Y DENTRO DE LA MISMA RED__

_Con este último punto, me refiero a que esté en el mismo segmento, por si te tomas algo y quieres hacer subredes con ethernet; o incluso meter un `192.168.137.2/30` o algo parecido_ eso sí, debemos indicar el _Gateway y el DNS_ apuntando a la dirección de la RPI, por el momento no tendremos acceso a internet desde la interface `Ethernet` pero una vez configuremos las rutas lo tendremos funcionando.


Una vez configurado, tanto desde la RPI y el equipo donde estará conectado, reinicia la configuración del `network manager`:

```js
> sudo systemctl restart NetworkManager
```

De este modo, puedes conectarte mediante SSH por el puerto ethernet; que será necesario ya que en algunos pasos, deshabilitaremos el acceso `SSH` desde la red externa a la RPI

## 2. PiHole

`Pi-Hole` funcionará como un DNS local que bloqueará los anuncios y también puedes bloquear páginas peligrosas desde un mismo punto; para configurarlo sólo tenemos que seguir las instrucciones de su [repositorio de github](https://github.com/pi-hole/pi-hole/#one-step-automated-install)

```js
// Hacemos la actualización de la RPI, claro está:
> sudo apt-get update && sudo apt upgrade

// E instalamos con su one liner
> curl -sSL https://install.pi-hole.net | bash
```

Esto instalará `Pi-Hole` en la RPI, se nos preguntará la red en la que queremos que se ejecute (para ello, creamos la red interna descrita en la __sección 1.1__) y el proveedor principal DNS, que recomiendo los de `Cloudflare` (Sólo avisará que necesita una dirección estática y fue justo lo que hicimos con `nmtui`).

Una vez terminada la instalación, indicará una contraseña y accedemos al portal desde el navegador (de la forma _http(s)://Rpi.local/admin/login_).

Para administrar las listas, basta con dirigirse a la pestaña `List`, y veremos una interface bastante intuitiva:

![UTMP]({{ "/images/GatewayP/PiHoleList.png" | relative_url }}){: .align-center}

Sólo hace falta indicar una lista de dominios para aplicar el `blocklist`. Los que más recomiendo son de los siguientes repositorios:

1. [dns-blocklist - Hagezi](https://github.com/hagezi/dns-blocklists) Que contiene distintas listas según las necesidades que tengas
2. [blocklistproject](https://github.com/blocklistproject/Lists) Utiliza los formatos `Original`
3. [StevenBlack Hosts](https://github.com/StevenBlack/hosts) estas para mi son de las mejores listas
4. Cualquiera que consideres según tus necesidades

Sólo tienes que ir indicando la dirección, indicar `Add blocklist` y desde la sesión de `SSH` ejecutar

```js
> pihole -g
```

Así de sencillo!

### 2.1 Protección Adicional DNS

Ahora, para mejorar aún más la seguridad de las peticiones `DNS` recomiendo utilizar `unbound`, un recursor DNS: La ventaja es: __Privacidad máxima y autonomía__ (escencialmente, le diremos a nuestra RPI que resuelva ella misma todas las consultas `DNS` validándolas con `DNSSEC`) y es más lento, especialmente, después de iniciar el `DNS` pero, también tenemos la alternativa de `DoT` _DNS over TLS_, cuyas ventajas son: __Simplicidad y menor latencia__ donde  __sacrificamos un poco la privacidad__ ya que el proveedor verá las consultas y confiaremos en él, todo lo demás en cuestión de seguridad `DNS`.

Considerando esto; configuraremos ambas alternativas:

#### 2.1.1 DNS + Unbound Recursivo

_`Unbound` es un recursor DNS_, ¿Qué significa?: Significa que el servidor DNS, no confiará en ningún proveedor DNS como tal, sino que buscará ella misma, la resolución directo del root; digamos que buscas _www.ejemplo.com_, `unbound` busca en su caché, si no lo encuentra, empieza a buscar la raíz, para encontrar el TLD y luego el servidor autoritativo para encontrar su registro DNS: `.` (Raíz) > `.com.` (TLD) > `ejemplo.com.` (El servidor autoritativo)

Entonces, para implementarlo, necesitaremos instalar `unbound`:

```js
> sudo apt install unbound
```

Luego, creamos un archivo con la siguiente ruta `/etc/unbound/unbound.conf.d/pi-hole.conf` con los siguientes contenidos

```js
sudo nano /etc/unbound/unbound.conf.d/pi-hole.conf

server:
    interface: 127.0.0.1
    port: 5335

    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    prefetch: yes
    prefetch-key: yes

    root-hints: "/var/lib/unbound/root.hints"

    cache-min-ttl: 3600
    cache-max-ttl: 86400
```

Y descargamos el `root hints` y reiniciamos el servicio:

```js
> sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache
> sudo systemctl restart unbound
> sudo systemctl status unbound
```

Para forzar al DNS de utilizar `Unbound` necesitamos modificar el `DNS` de la `PiHole` para que se utilice a ella misma por el puerto `5335` que es donde está corriendo `unbound`.

En el portal de `PiHole` nos dirigimos a `Settings` > `DNS`, deselecciona todas las opciones del `Upstream DNS Servers` y escribimos `127.0.0.1#5335` en los `Custom DNS servers`

![UTMP]({{ "/images/GatewayP/piholeunbound.png" | relative_url }}){: .align-center}

Para probarlo, puedes hacerlo con `dig` desde la RPI:

```js
> dig google.com

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             3144    IN      A       192.178.56.174

;; Query time: 3 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
```

### DNS over TLS

A diferencia de `unbound` Utilizando `DoT` las consultas se cifrarán desde la RPI, hasta el `Upstream DNS Server` y luego este upstream se encargará de resolver la consulta por nosotros, lo que lo hace mucho más rápido.

Para implementarlo, seguiremos utilizando `unbound`, pero modificando el comportamiento, ya que le indicaremos a dónde enviar las consultas, no indicaremos un `root hint` para la resolución `DNS`. Dicho esto: instalamos `unbound`

```js
> sudo apt install unbound
```

Y modificando/creando el archivo de configuración `/etc/unbound/unbound.conf.d/pi-hole.conf` con los siguientes contenidos:

```js
server:
    interface: 127.0.0.1
    port: 5335

    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes

    prefetch: yes
    prefetch-key: yes
    cache-min-ttl: 3600
    cache-max-ttl: 86400

    auto-trust-anchor-file: "/var/lib/unbound/root.key"

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853
    forward-addr: 1.0.0.1@853
```

La instalación de `PiHole` configura un archivo en la ruta: `/usr/share/dns/root.key` que son los certificados para el `DNSSEC`; así que copiamos y pegamos este archivo a `/var/lib/unbound/root.key`:

```js
> sudo cp /usr/share/dns/root.key /var/lib/unbound/root.key
```

Reiniciamos el servicio de `unbound` y verificamos que esté corriendo

```js
> sudo systemctl restart unbound
> sudo systemctl status unbound
```

Una vez hecho esto, modificamos el `Upstream DNS Server` del `PiHole` hacia nosotros mismos y al puerto `5335` donde está ejecutándose `unbound`; desde el portal, nos dirigimos a `Settings` > `DNS`, deselecciona todas las opciones del `Upstream DNS Servers` y escribimos `127.0.0.1#5335` en los `Custom DNS servers`

Y probamos con `dig`

```js
> dig facebook.com

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;facebook.com.                  IN      A

;; ANSWER SECTION:
facebook.com.           2673    IN      A       31.13.93.35

;; Query time: 3 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; MSG SIZE  rcvd: 57
```

## 3. Enrutamiento y Firewall

Como mencioné antes, desde la conexión `SSH` no tendrá salida a internet; por ello, debemos habilitar el `Forwarding` y configurar el `nat` para que se pueda tener acceso a internet:

Primero, habilitamos el reenvío de paquetes modificando  el archivo `/etc/sysctl.conf`, agregando o descomentando la linea:

```js
net.ipv4.ip_forward=1
```

Y aplicar la configración con:

```js
> sudo sysctl -p
```

Ahora, configuramos el `NAT` con `iptables` y permitiendo el reenvío entre interfaces (_Modifica el nombre de las interfaces y los rangos si es necesario_):

```js
> sudo iptables -t nat -A POSTROUTING -s 192.168.137.0/24 -o wlan0 -j MASQUERADE
> sudo iptables -A FORWARD -i eth0 -o wlan0 -j ACCEPT
> sudo iptables -A FORWARD -i wlan0 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
```

Verificamos la conexión desde la conexión Ethernet, puede ser con `ping`, `curl` o incluso `dig` para probar la resolución del `DNS`; 

```js
❯ dig example.com
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;example.com.                   IN      A

;; ANSWER SECTION:
example.com.            3600    IN      A       23.192.228.80
example.com.            3600    IN      A       23.220.75.232
example.com.            3600    IN      A       23.215.0.136
example.com.            3600    IN      A       23.220.75.245
example.com.            3600    IN      A       23.215.0.138
example.com.            3600    IN      A       23.192.228.84

;; Query time: 356 msec
;; SERVER: 192.168.137.1#53(192.168.137.1) (UDP)
;; MSG SIZE  rcvd: 136
```

_Nota: A veces, hay que configurar las ip routes así como la ruta por defecto, lo que debería de verse algo parecido a esto:_

```js
> ip route show
default via 192.168.0.254 dev wlan0 proto dhcp src 192.168.0.X metric 600 
192.168.0.0/24 dev wlan0 proto kernel scope link src 192.168.0.X metric 600 
192.168.137.0/24 dev eth0 proto kernel scope link src 192.168.137.1 metric 100 
```

En caso de no tener alguna de estas, puedes agregarla con 

```js
sudo ip route add 192.168.0.0/24 dev wlan0
sudo ip route add default via 192.168.0.254 dev wlan0
sudo ip route add 192.168.137.0/24 dev eth0
```

## 4. Reglas IP Tables

Bien, ahora mejoraremos la seguridad con `iptables` restringiendo las conexiones; por suerte, es más sencillo ya que siguen una sintaxis en común:

```js
iptables <Acción> <Cadena> <Condiciones> -m comment --comment "Regla X o por Y" -j <Jumplist o Acción>
```

Eso sí, el orden es súmamente importante y hace falta ver qué tan granular es el acceso que ejecutas aunque hay una regla y recomendación general: __De lo Específico a lo General__, lo que significa que las reglas específicas deben ir lo más arriba posible de la lista.

Primero nos centraremos en las reglas `INPUT`, que son todas las conexiones entrantes, imagina un ping, si deshabilitamos el ping, puede tener salida... pero negará la entrada de la respuesta. Es común confundirse un poco con conectar 2 redes (como es nuestro caso) y pensaremos en las reglas `FORWARD`, pero recuerda que como se aplica un `NAT`, `INPUT` y `OUTPUT` terminan siendo igual de importantes.

Ahora, en el dado caso que querramos indicar algún `DROP`, la mejor práctica es saber cuándo sucedió, por ello, es necesario __Hacer LOG de estos paquetes__ y claro, hacer el `DROP`, con lo siguiente, estamos creando una cadena `LOG_Y_DROP` que registrará el paquete y luego hará el `DROP`:

```js
iptables -N LOG_Y_DROP
iptables -A LOG_Y_DROP -j LOG --log-level 4 --log-prefix "DROP Action: "
iptables -A LOG_Y_DROP -j DROP
```

Finalmente, como consejo, has los comentarios lo más descriptivo posible, qué tal si se te olvida para qué pusiste una regla, seguro que a todos nos pasa.

### 4.1 INPUT

Estas son reglas que son críticas y mejoran la seguridad de la RPI en __conexiones entrantes__:

```js
iptables -A INPUT -i lo -m comment --comment "Accept All Loopback" -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "Accept already Established connections" -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -m comment --comment "Drop malformed Packets" -j LOG_Y_DROP
iptables -A INPUT -i eth0 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource -m comment --comment "Brute force Rules 1"
iptables -A INPUT -i eth0 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name DEFAULT --mask 255.255.255.255 --rsource -m comment --comment "Brute force Rules 2" -
j LOG_Y_DROP
iptables -A INPUT -i eth0 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m comment --comment "Accept New SSH Connections" -j ACCEPT
iptables -A INPUT -s 192.168.137.0/24 -i eth0 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -m comment --comment "Accept New DNS Connections UDP" -j ACCEPT
iptables -A INPUT -s 192.168.137.0/24 -i eth0 -p tcp -m tcp --dport 53 -m conntrack --ctstate NEW -m comment --comment "Accept New DNS Connections TCP" -j ACCEPT
iptables -A INPUT -s 192.168.137.0/24 -i eth0 -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW -m comment --comment "Accept HTTP Traffic" -j ACCEPT
-A INPUT -i wlan0 -m conntrack --ctstate NEW -m comment --comment "Drop All New Incomming Connections" -j LOG_Y_DROP
```

No olvides la regla de "Accept New SSH Connections" ya que sin ella, perderemos contacto con SSH, las demás reglas son para permitir el acceso a las funcionalidades de la RPI sólo desde la red interna; y luego con estas reglas, podemos hacer un __`DROP` por defecto__, que es la práctica recomendada:

```js
sudo iptables -P INPUT DROP
```

### 4.2 OUTPUT

Para `OUTPUT` son pocas menos reglas, pero la base es la misma: limitar lo que puede accederse hacia la red externa (`wlan0`), por lo que debe considerarse igual, las conexiones más comunes; como `HTTP` o `HTTPS` y por supuesto; las request para resolución `DNS` __Recuerda que este puerto puede cambiar si utilizas DoH/DoT o Resolución Recursiva, en ese último caso corrige a `-p udp -m udp --dport 53`__:

```js
iptables -A OUTPUT -o lo -m comment --comment "Allow loopback output connections" -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "Allow established Output connections" -j ACCEPT
iptables -A OUTPUT -o wlan0 -p tcp -m tcp --dport 853 -m comment --comment "Allow output DNS requests" -j ACCEPT
iptables -A OUTPUT -o wlan0 -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "Allow output HTTP connections to internet" -j ACCEPT
iptables -A OUTPUT -o wlan0 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "Allow output HTTPS connections to internet" -j ACCEPT
```

Y cerrar la configuración con el `DROP` por defecto:

```js
sudo iptables -P OUTPUT DROP
```

### 4.3 FORWARD

Para finalizar con las `iptables`, faltan las `FORWARD`, que son menos que las anteriores con acciones específicas: __Permitir a la red interna comunicarse con internet__, __permitir sólo las conexiones establecidas desde internet a la red interna__ y también __Dripean las nuevas conexiones desde internet__

```js
iptables -A FORWARD -s 192.168.137.0/24 -i eth0 -o wlan0 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -m comment --comment "Allow Private network to internet" -j ACCEPT
iptables -A FORWARD -d 192.168.137.0/24 -i wlan0 -o eth0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "Allow Only Established connections from internet" -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth0 -m conntrack --ctstate NEW -m comment --comment "Drop New Incomming connections from internet" -j LOG_Y_DROP
```

Y finalmente: `DROP` por defecto:

```js
sudo iptables -P OUTPUT DROP
```

## 5. Suricata IDS

Ya vamos finalizando esta primera etapa, ahora implementaremos `Suricata` para bloquear conexiones que coincidan con nuestras reglas.

Primero, instalamos `suricata`, disponible desde apt:

```js
> sudo apt install suricata
```

Esto generará el archivo de configuración `suricata.yaml` dentro del directorio `/etc/suricata`, del cual tendremos que ajustar el rango de la `HOME_NET`:

```bash
vars:
  # more specific is better for alert accuracy and performance
  address-groups:
    HOME_NET: "[192.168.137.0/24]"
```

Ahora `suricata` ya sabe qué tráfico inspeccionar identificando la red interna de la externa; ahora, faltará indicar reglas, y para ello, podemos utilizar `suricata-update`, lo tendremos que instalar, utilizar alguna de las listas (en este caso utilizaré `oisf/trafficid`), hacer el `update` de las reglas y reiniciar `suricata`:

```js
> sudo apt install suricata-update
> sudo suricata-update enable-source oisf/trafficid
> sudo suricata-update
> sudo systemctl restart suricata
> sudo systemctl enable suricata
> sudo systemctl status suricata
```
Lo que deja habilitado a `Suricata` en modo `IDS`

## 6. Suricata IPS

Para pasar de modo `IDS` que básicamente es de inspección y reporte, a uno más responsivo que dropee paquetes (`IPS`) sólo hace falta cambiar las reglas para hacer coincidir los drops y luego, configurarlo en las `iptables` para que todo el tráfico pase por suricata y luego se evaluen las demás reglas.

Primero, crearemos un directorio `rules` (si es que no lo hay) dentro de `/etc/suricata` y copiaremos las reglas generadas por `suricata-update`, que están en `/var/lib/suricata/rules/suricata.rules`

```js
> cd /etc/suricata
> mkdir rules
> cd rules
> cp /var/lib/suricata/rules/suricata.rules .
```

Ahora, existen `Classtypes` y prioridades, esto lo podemos ver en las últimas lineas del `/etc/suricata/suricata.yaml`

```js
##
## Auxiliary configuration files.
##

classification-file: /etc/suricata/classification.config
```

¿Y por qué queremos conocerlas?, pues en base a esta clasificación, podemos hacer una forma muy rápida para pasar de las reglas originales, a reglas con drops, y para ello, crearemos un script.

El objetivo es el siguiente: Extraer las reglas con los clasificadores que definamos (como los `Crítical` y `Major` de pripridad 1 y los crítical de Prioridad 2):

El script quedaría de la siguiente maneral:

```bash
#!/usr/bin/env bash
set -euo pipefail

SRULES="/etc/suricata/rules/suricata.rules"
SRULES_BAK="/etc/suricata/rules/suricata.rules.bak"
LRULES="/etc/suricata/rules/local.rules"

CRITICAL_TYPES="command-and-control|exploit-kit|credential-theft|domain-c2|targeted-activity"

echo "→ Extrayendo PRIORIDAD 1 (Major/Critical) …"
sudo grep -E "^[[:space:]]*alert .*classtype:($CRITICAL_TYPES)" "$SRULES_BAK" | \
  grep -E "signature_severity (Major|Critical)" | \
while IFS= read -r rule; do
  old_sid=$(printf "%s" "$rule" | grep -oE 'sid:[0-9]+' | cut -d: -f2)
  new_sid=$(( old_sid + 1000000 ))
  new_rule=$(printf "%s" "$rule" \
    | sed -E "s/^[[:space:]]*alert /drop /" \
    | sed -E "s/sid:${old_sid}/sid:${new_sid}/")
  grep -q "sid:${new_sid}" "$LRULES" || echo "$new_rule"
done | sudo tee -a "$LRULES" > /dev/null

sudo sed -E -i "/classtype:($CRITICAL_TYPES)/{ /signature_severity (Major|Critical)/ s/^([[:space:]]*)/## \1/; }" "$SRULES"

echo "→ Extrayendo PRIORIDAD 2 (Critical) …"
sudo grep -E "^[[:space:]]*alert .*classtype:($CRITICAL_TYPES)" "$SRULES_BAK" | \
  grep -E "signature_severity Critical" | \
while IFS= read -r rule; do
  old_sid=$(printf "%s" "$rule" | grep -oE 'sid:[0-9]+' | cut -d: -f2)
  new_sid=$(( old_sid + 2000000 ))
  new_rule=$(printf "%s" "$rule" \
    | sed -E "s/^[[:space:]]*alert /drop /" \
    | sed -E "s/sid:${old_sid}/sid:${new_sid}/")
  grep -q "sid:${new_sid}" "$LRULES" || echo "$new_rule"
done | sudo tee -a "$LRULES" > /dev/null

sudo sed -E -i "/classtype:($CRITICAL_TYPES)/{ /signature_severity Critical/ s/^([[:space:]]*)/## \1/; }" "$SRULES"

echo ":) Reglas críticas convertidas a drop y comentadas en suricata.rules"
```

Damos permisos de ejecución y ejecutamos el script:

```js
> chmod +x rules_drop_script.sh
> ./rules_drop_script.sh
```

De esta menera, estamos dividiendo el funcionamiento en 2 (cabe aclarar que NO es lo ideal, ya que antes de dropear, deberíamos hacer el `log` o el `alert` del paquete) Las reglas por defecto con el alert, del cual podrémos seguir viendo desde `/var/log/fast.log` y las reglas `Drop` que con ese script, actualizará las lineas que indiquemos, comentando en el archivo original e implementando el `drop` en un nuevo archivo llamado `local.rules` dentro de la carpeta `/etc/suricata/rules`

Lo que sigue es indicar a `suricata` usar ambos archivos de reglas: En el `/etc/suricata/suricata.yaml`, modificamos las siguientes lineas (o las agregamos en la misma sección del `rule-files` - `rule-path`)

```js
default-rule-path: /etc/suricata/rules

rule-files:
  - /etc/suricata/rules/suricata.rules
  - /etc/suricata/rules/local.rules
```

Y finalmente, configuramos las `iptables` para forzar todo el tráfico a través de ellas.

```js
> sudo iptables -A PREROUTING -j MARK --set-xmark 0x0/0x1
> sudo iptables -I INPUT 1 -m mark ! --mark 0x1/0x1 -m comment --comment "Suricata Ingest" -j NFQUEUE --queue-num 0
> sudo iptables -I FORWARD 1 -m mark ! --mark 0x1/0x1 -m comment --comment "Suricata Ingest" -j NFQUEUE --queue-num 0
```

Y reiniciamos suricata:

```js
> sudo systemctl restart suricata
> sudo systemctl status suricata
```

Configurando la RPI (al menos, en configuración básica de seguridad)!.

## 7. Toques finales.

En este punto, podemos conectar incluso un router en el puerto ethernet y desde ahí, configurar el DHCP asegurando las siguientes configuraciones:

* Reservando la dirección `192.168.137.1` del DHCP
* Indicando el DNS apuntando a la `192.168.137.1`
* El Gateway apuntando a `192.168.137.1`



###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.


