---
layout: single
title: "Proyecto SIEM con Wazuh"
author_profile: true
published: true
---

Un proyecto que estoy desarrollando en mi trabajo es la implementación de un manual para el deployment de un SIEM, con agentes incluidos, sé que hay muchos tutoriales en internet pero también quería divertirme con la configuración un poco, sobre todo para la parte del servidor asegurando su acceso hasta de forma casi paranóica, pero, qué más da, está bien probar configuraciones y cosas nuevas de vez en tanto.

# Materiales

No necesitas nada en especial, incluso, en la misma computadora donde te conectas a la nube la podrás monitorear para probar las funcionalidades :)

# Desarrollo

## Creación del Servidor con Linode

En mi caso, estaré creando el servidor para el SIEM en `Linode`, aprovechando el crédito de $100 (por 60 días) justo para 2 meses con el SIEM si sólo quieres hacerlo de proyecto.

Claramente, creas la cuenta y una vez iniciada la sesión, seleccionas `Linodes` y `Create Linode`; ya dentro de la configuración, nos movemos a `Marketplace`

![UTMP]({{ "/images/WazuhConfig/marketplacelinode.png" | relative_url }}){: .align-center}

Buscamos y seleccionamos `wazuh`

![UTMP]({{ "/images/WazuhConfig/wazuhlinode.png" | relative_url }}){: .align-center}

Lo que nos ahorrará varios pasos de instalación; Lo que sigue es típicamente la configuración inicial del servidor, región, y el plan: Para esto las `Shared CPU` son más baratas y mínimo, necesitamos el `Linode 4 GB` que tiene lo mínimo recomendado para `Wazuh`; y para recomendación, el de `Linode 8GB` debería irnos bastante bastante bien:

![UTMP]({{ "/images/WazuhConfig/linodeplan.png" | relative_url }}){: .align-center}

Lo que deberíamos configurar es la contraseña del `root` o bien las llaves `SSH`, sea cual sera, haremos varios retoques a `SSH` para que sea totalmente seguro.

Fuera de ello, no hace falta modificar nada más; aceptamos los cambios indicando "Create Linode" al final y esperamos a que se monte.

Cuando esté disponible, lo veremos dentro del menú `Linodes` y nos dará los comandos de acceso por SSH.

## Configuración SSH

Lo que haremos con SSH es para asegurar que sólo nosotros tengamos acceso al servidor, entonces, se hará de forma más granular, lo que incluye:

* Deshabilitar auntenticación por contraseñA para la autenticación por authorized keys
* Habilitar `fail2ban` para bloquear intentos de inicio de sesión
* Habilitar PAM con Google Authenticator
* Añdadir un bot de telegram que nos avise inicios de sesión

Como ven, esta configuración es mucho mas restrictiva con respecto a lo que hicimos con la RPI en nuestro anterior proyecto pero igual, un SIEM debe asegurarse y aislarse lo más posible del entorno de monitoreo, por ello, la nube también ofrece esta parte, lo que nos corresponde a nosotros es asegurar todo el acceso.

Entonces, iniciemos con deshabilitar la autenticación por contraseña, añadiendo nuestra `id_rsa.pub`.

### Deshabilitar contraseña para un passwordless method

Antes, entendamos el por qué es mejor utilizar estas llaves que una contraseña:

_Las llaves SSH usan criptografía asimétrica, la clave privada nunca se transmite y sólo se usa localmente para firmar, las contraseñas en cambio pueden ser interceptadas o adivinadas; los bots utilizan contraseñas comunes cuando detectan SSH, y si quiere revocarse el acceso, sólo debe eliminarse la entrada en el authotizedkeys a la par de que permiten automatización_ Todo esto, claro, suponiendo que la llave SSH utiliza un algoritmo seguro o una longitud suficientemente segura.

Para crear un par de llaves y utilizarlas para auntenticarnos ante nuestro servidor debemos utilizar `ssh_keygen` y copiar la entrada de la llave pública para ponerlo en el `authorized_keys` de nuestro servidor remoto.

```js
❯ ssh-keygen -t rsa -b 4096
Generating public/private rsa key pair.
Enter file in which to save the key (/home/n1c37ry05/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
<SNIP!>
The key's randomart image is:
+---[RSA 4096]----+
<SNIP!>
+----[SHA256]-----+
```

Recomiendo añadir una `passphrase` para asegurar la llave añadiendo una capa extra de seguridad; ahora con nuestros archivos, copiamos el contenido del archivo `id_rsa` y lo agregamos a `authorized_keys` en el servidor remoto:

```js
❯ cat id_rsa.pub | base64 -w0 

Ci0tLS<SNIP!>S0tLQo= 

Remote_Server # echo "Ci0tLS<SNIP!>S0tLQo=" | bae64 -d >> /home/user/.ssh/authorized_keys
```

Luego, para asegurar que sea el único método de autenticación, debemos modificar una linea en `/etc/ssh/sshd_config` de nuestro servidor remoto:

```bash
PermitRootLogin no
PasswordAuthentication no
```

Con ello, ya hemos asegurado nuestro servidor a utilizar llaves como medio de autenticación.

### Habilitar Fail2Ban

Ahora, crearemos una regla de `fail2ban` para bloquear el intento del login con el usuario root, baneando la IP, y antes que nada, debemos instalar `fail2ban`

```js
Remote_Server # apt install fail2ban
```

Antes de habilitarlo, debemos hacer el filtro (que se encargará de revisar el `auth.log` buscando las condiciones que le indiquemos) 

```js
Remote_Server # nano /etc/fail2ban/filter.d/sshd-root.conf

[Definition]
failregex = ^Invalid user root from <HOST> port \d+ ssh2$
ignoreregex =
```

y Con este archivo de filtro listo, ahora creamos y modificamos un archivo que le llamaremos `/etc/fail2ban/jail.d/sshd-root.conf` añadiendo lo siguiente:

```js
Remote_Server # nano /etc/fail2ban/jail.d/sshd-root.conf

[sshd-root]
enabled  = true
filter   = sshd-root
action   = iptables[name=SSH-root, port=ssh, protocol=tcp]
logpath  = /var/log/auth.log
maxretry = 1
findtime = 600
bantime  = -1 
```

Este contenido hace un __ban indefinido__ por __un intento fallido__ aplicando el filtro que hemos creado para detectar intentos de sesión con `root`. Ahora, iniciamos el servicio y verificamos que todo se ejecuta como debe:

```js
Remote_Server # fail2ban-client reload
Remote_Server # fail2ban-client status sshd-root
Remote_Server # systemctl enable fail2ban
```

### Añadir PAM con Google Authenticator

Bien, ahora configuremos SSH para que use doble factor de autenticación, y en este caso, con Google Authenticator.

Primero, debemos instalar `libpam-google-authenticator` con apt

```js
Remote_Server # apt install libpam-google-authenticator
```

Ahora, para hacer que `SSH` utilice el módulo de Google Authenticator, debemos añadir la siguiente linea a `/etc/pam.d/sshd`

```js
auth required pam_google_authenticator.so
```

Y comentar la siguiente (esto es importante!):

```js
@include common-auth
```

Luego, debemos modificar `/etc/ssh/sshd_config` justo en la siguiente línea:

```js
KbdInteractiveAuthentication yes 
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

Y ejecutamos `google-authenticator` dentro del home del usuario de menores privilegios, nos preguntará por lo siguiente, y en cierto momento generará el QR para usar en la aplicación y te pedirá el código que genere la aplicación:

* Make tokens “time-base””: yes
* Update the .google_authenticator file: yes 
* Disallow multiple uses: yes
* Increase the original generation time limit: no
* Enable rate-limiting: yes

Una vez aplicado esto, necesitas __cambiar los permisos del archivo__ generado:

```js
Remote_Server # chmod 600 .google_authenticator
```

reinicia el servicio de SSH:

```js
Remote_Server # systemctl restart ssh
```

Y listo, has habilitado 2FA para SSH.

### Trazabilidad de inicios de sesión Telegram

El último punto a cubrir es tener trazabilidad en los inicios de sesión, esto lo haré con un bot de telegram, que me reporte los inicios de sesión, obteniendo información relevante.

Lo primero que haremos es hacer el bot en telegram; para esto sólo debemos buscar `BotFather` en `Apps` dentro de telegram.

![UTMP]({{ "/images/WazuhConfig/botfather.png" | relative_url }}){: .align-center}

Te debería de aparecer un botón que indica '_Crear Nuevo Bot_' e Indicar nombre, descripción y más detalles. Finalizando el proceso, debería indicarte un API key y cópiala, la usaremos en una request de `curl`

![UTMP]({{ "/images/WazuhConfig/api_bot.png" | relative_url }}){: .align-center}

Una vez con el bot creado, crea un canal y agrégalo como administrador, le quitarás todos los permisos, excepto `Post Messages`

![UTMP]({{ "/images/WazuhConfig/permisos_bot.png" | relative_url }}){: .align-center}

Cuando lo agregues, ve a la terminal y has la petición:

```js
Remote_Server # curl https://api.telegram.org/bot<TuToken>/getUpdates | jq .
```

Y busca dentro de la respuesta, el campo `id` 

```
{
    "update_id": 717672127,
    "my_chat_member": {
    "chat": 
        {
          "id": <ID_A_ANOTAR>,
          "title": "Notifications",
          "type": "channel"
```

Con estos dos datos: el `id` del grupo y el `API Token` ya podemos contruir las bases del script, primero creamos un archivo `env` para manejar de forma segura ambos datos:

```js
Remote_Server # sudo nano /root/telegram_env

# Content
GROUP_ID=-100<SNIP!>
BOT_TOKEN=846<SNIP!>daYc
```

Luego, creamos el script que será ejecutado con el `PAM` de SSH, para añadir la funcionalidad del tracking de las IPs, estoy utilizando la API de `ipinfo`, les invito a crear una cuenta en su versión gratuita, o bien, utilizar la api que gusten:

```bash
Remote_Server # sudo mkdir /etc/pam_scripts
Remote_Server # sudo nano /etc/pam_scripts/login-notify.sh

# Content

#!/bin/bash

API_TOKEN="<API_TOKEN>"

if [ ! "${PAM_TYPE}" = "open_session" ]; then
    exit 0
fi

# Obtener IP de conexión
login_ip="$(echo $SSH_CONNECTION | cut -d " " -f 1)"

# Consultar IPinfo
login_ip_data=$(curl -s "https://api.ipinfo.io/lite/${login_ip}?token=${API_TOKEN}")

# Extraer campos relevantes
login_ip=$(echo -e $login_ip_data | jq -r ".ip")
login_ip_org=$(echo -e $login_ip_data | jq -r ".as_name")
login_ip_domain=$(echo -e $login_ip_data | jq -r ".as_domain")
login_ip_country_code=$(echo -e $login_ip_data | jq -r ".country_code")
login_ip_country=$(echo -e $login_ip_data | jq -r ".country")
login_ip_continent_code=$(echo -e $login_ip_data | jq -r ".continent_code")
login_ip_continent=$(echo -e $login_ip_data | jq -r ".continent")

# Datos adicionales
login_date="$(date +"%e %b %Y, %a %r")"
login_name="${PAM_USER}"
login_hostname="$(hostname)"

# Construir mensaje
read -r -d '' message << EOM
<b>${login_hostname}</b> ($login_name)
IP: <b><a href="https://ipinfo.io/${login_ip}">${login_ip}</a></b>
ASN Name: ${login_ip_org}
ASN Domain: ${login_ip_domain}
Country: ${login_ip_country} (${login_ip_country_code})
Continent: ${login_ip_continent} (${login_ip_continent_code})
EOM

# Enviar a Telegram
telegram-send.sh TRUE "$message"
```

Y, ahora hacemos el script para enviar el mensaje por telegram (`/usr/bin/telegram-send.sh`):

```bash
Remote_Server # sudo nano /usr/bin/telegram-send.sh
# Content

#!/bin/bash

source /root/telegram_env

if [ "$1" == "-h" ]; then
  echo "Usage: `basename $0` \"text message\""
  exit 0
fi

silent="false"
if [ "$1" == "TRUE" ]; then
        silent="true"
fi

if [ -z "$2" ]
  then
    echo "Add message text as second arguments"
    exit 0
fi

if [ "$#" -ne 2 ]; then
    echo "You can pass only two arguments. For string with spaces put it on quotes"
    exit 0
fi

curl -s --data-urlencode "text=$2" --data "chat_id=$GROUP_ID" --data "parse_mode=HTML" --data "disable_notification=$silent" 'https://api.telegram.org/bot'$BOT_TOKEN'/sendMessage' > /dev/null
```

Para finalizar, debemos agregar la linea `session optional pam_exec.so /etc/pam_scripts/login-notify.sh` dentro del `pam.d/sshd`:

```bash
Remote_Server # sudo nano /etc/pam.d/sshd

# content
session optional pam_exec.so /etc/pam_scripts/login-notify.sh
```

Ajustamos los permisos y estamos listos!:

```js
Remote_Server # sudo chmod 700 /usr/bin/telegram-send.sh
Remote_Server # sudo chmod 700 /etc/pam_scripts/login-notify.sh
```

Y probamos la funcionalidad:

![UTMP]({{ "/images/WazuhConfig/notification_bot.png" | relative_url }}){: .align-center}

##  Configuración Servidor Wazuh

### Agregando un Agente

Bien, ahora con el acceso controlado, nos vamos a nuestro `linode` y hasta abajo en la sección `IP Addresses` encontraremos un registro Reverse DNS

![UTMP]({{ "/images/WazuhConfig/RevDNS.png" | relative_url }}){: .align-center}

Copiamos y pegamos en nuestro navegador, las credenciales las encontraremos en el `/home/TuUsuario/.credentials`

_En caso de que no las encuentres ahí, o en el /root, utiliza `find`, si tampoco resulta, busca `wazuh-install-files.tar` y si tampoco está, reinstala el wazuh con `curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a -o`_

![UTMP]({{ "/images/WazuhConfig/wazuhlogin.png" | relative_url }}){: .align-center}

Una vez en el portal, en la parte superior izquiera, vendrá una opción para agregar un agente; o buen, puedes seleccionar el menú (esquina superior Izquierda, `Agent Management` > `Summary`)

![UTMP]({{ "/images/WazuhConfig/wazuh-agent-administration.png" | relative_url }}){: .align-center}

Y una vez ahí, seleccionar `Deploy New Agent`, en cualquier caso, el deployment es súmamente sencillo:

![UTMP]({{ "/images/WazuhConfig/new-agent-deploy.png" | relative_url }}){: .align-center}

1. __Elige el sistema operativo__; Como tal no generará un ejecutable, sino que generará un comando a copiar y pegar en una consola o terminal como administrador (lo veremos en un momento), pero sí es importante para cuestión de compatibilidad de comandos_

2. __Elige el Servidor__; Esta dirección debe ser a la que enviará la petición los agentes; el método más sencillo es utilizar el `rDNS` generado por el linode (como hicimos para acceder al portal `Wazuh`).

3. __Ajustes Opcionales__; Para tener mayor control sobre los dispositivos (como aplicación de ajustes en varios equipos, grupos, división de responsabilidades, controles que debemos de tener en equipos críticos) puedes elegir un grupo o un nombre descriptivo.

4. __Comando__; El comando resultante, conectará el agente con el servidor, sólo tienes que ejecutarlo en una terminal privilegiada.

_Ojo: El servidor, tiene que admitir conexiones a los puertos `1514/tcp` y `1515/tcp` para administrar correctamente los agentes, si configuras un firewall, ten esto en cuenta._

Luego, sólo hace falta ejecutar el comando resultante y el `NET START Wazuh`

![UTMP]({{ "/images/WazuhConfig/wazuh-agent-powershell.png" | relative_url }}){: .align-center}

_Nota: Si por alguna razón, necesitas hacer debugging, puedes recurri al `ossec.log` dentro de `Program Files (x86)`_

![UTMP]({{ "/images/WazuhConfig/Wazuh-connection.png" | relative_url }}){: .align-center}

En este caso, en el log file indica que se ha conectado correctamente, a punto de ser configurado.

¿Qué sigue?, antes de terminar, veamos como activar algunas opciones útiles y revisar el `Active Response`

### Configuración y monitoreo personalizado

Por defecto, los clientes se comunican con el servidor enviando actualizaciones del `syscheck` cada 12 horas que justo está definido desde el `ossec.conf` (isntalado en cada agente en el mismo directorio que el `ossec.log`), veamos cómo cambiarlo pero ten en cuenta algo: __No se recomienda cambiar este archivo__, en cambio, utilizamos el `agent.conf` que tiene básicamente el mismo funcionamiento.

En el __Wazuh Dashboard__ dirígete a `Agents Management` y `Groups`

![UTMP]({{ "/images/WazuhConfig/agent-management.png" | relative_url }}){: .align-center}

Y seleccionamos el grupo que nos interese cambiar y dentro de él, selecciona la pestaña `Files`, dentro de él, verás el archivo `agent.conf` que sólo hace falta hacer clic en el lapicito.

![UTMP]({{ "/images/WazuhConfig/agent-conf.png" | relative_url }}){: .align-center}

Este archivo, una vez modificado, el servidor detectará el cambio y enviará la configuración a los agentes.

Digamos que tenemos un directorio crítico que nos interese monitorear, dentro del `agent.conf`, agregaremos la siguiente plantilla (deja las llaves de `agent_config`):

```xml
<syscheck>
    <directories realtime="yes" check_all="yes" report_changes="yes">C:\Directorio\a\monitorear</directories>
</syscheck>
```

Guardas la configuración y poco después, empezará a monitorear el directorio deseado.

Para monitorearlo puedes irte al agente y hasta abajo, en la sección `FIM: Recent events`, puedes probar crear un documento y renombrarlo, el resultado será algo como:

![UTMP]({{ "/images/WazuhConfig/FIM_realtime.png" | relative_url }}){: .align-center}

### Integración con antivirus

Ahora, para probar el active response, haremos algo bastante sencillo (les recomiendo mucho que exploren las capacidades) pero el flujo por el que trabaja wazuh es el siguiente:

1. Se genera el evento
2. El servidor la procesa
3. Revisa sus reglas de active response
4. De corresponder, envía la instrucción de ejecuición al agente con el reporte
5. El agente procesa la petición del servidor
6. Ejecuta el programa

Este último punto de la ejecución, puede ser un binario o incluso un script de powershell, que será justo lo que probaremos:

Primero, debemos preparar 2 archivos: __un archivo bat__ que ejecutará __un script de powershell__

Primero, el archivo bat, (que es para probar la funcionalidad), lo pondremos en la ruta `C:\Program Files (x86)\ossec-agent\active-response\bin\test-log-exec.bat`:

```ps1
@echo off
SET LOG_FILE="C:\Program Files (x86)\ossec-agent\logs\active-responses.log"

echo %DATE% %TIME%: test-log.bat: Iniciando. >> %LOG_FILE%

powershell.exe -ExecutionPolicy Bypass -File "%~dp0\test-log.ps1" %*

echo %DATE% %TIME%: test-log.bat: Comando de PowerShell finalizado. >> %LOG_FILE%
```

Y para el powershell, podemos poner algo como esto en `C:\Program Files (x86)\ossec-agent\active-response\bin\test-log.ps1`

```ps1
$logFile = "C:\Program Files (x86)\ossec-agent\active-response\ar_test_output.log"
$arLog = "C:\Program Files (x86)\ossec-agent\logs\active-responses.log"

$logEntry = "-------------------------------------`r`n"
$logEntry += "$(Get-Date): PS1: Active Response DISPARADO.`r`n"
$logEntry += "PS1: ¿Qué hacemos ahora? `r`n"
$logEntry += "-------------------------------------`r`n"

Add-Content -Path $logFile -Value $logEntry

Add-Content -Path $arLog -Value "$(Get-Date): test-log.ps1: Script de PowerShell finalizado."

exit 0
```

Y finalmente, necesitamos modificar sólo 2 bloques dentro del `ossec.conf` (_`Menu > Server Management > Settings > Edit configuration`_) dentro del `Wazuh Manager`:

```xml
  <command>
    <name>test-log</name>
    <executable>test-log-exec.bat</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>test-log</command>
    <location>local</location> 
    <rules_id>554</rules_id>
  </active-response>
```

Este active response sólo hace un pequeño log local cuando se activa el `ID 554` que corresponde a un nuevo archivo (aprovechando que ya tenemos un directorio siendo monitoreado); Una vez modificado, damos en `Save` y `Restart Manager`.

En pocos minutos, el manager hará el cambio y se hará el active response, podemos probarlo creando un nuevo fichero y viendo el log:

![UTMP]({{ "/images/WazuhConfig/active-response-log.png" | relative_url }}){: .align-center}


Y listo! has configurado una respuesta automática!.

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.
