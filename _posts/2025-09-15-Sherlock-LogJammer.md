---
layout: single
title: "Sherlocks - LogJammer (HTB)"
author_profile: true
published: true
---

Los sherlocks (De HackTheBox) son retos gamificados enfocados a __Blue Team__, en ellos, se encuentran distintas situaciones donde uno debe utilizar herramientas de analsis y artefactos para completar las tareas. Y claro, hay __categorías__ según lo que quieras entrenar, como por ejemplo _DFIR_ (Digital Forensics and Incident Response) que se enfocan en el __análsis de artefactos forenses__ (es decir, trazas de ataques en los sistemas).

![UTMP]({{ "/images/LogJammer/logo.png" | relative_url }}){: .align-center}

## Resumen LogJammer

En este Sherlock estaremos manejando únicamente __Análisis de Logs de Windows__ con el `Visor de Eventos` del sistema operativo, veremos las diferencias entre cada archivo y sus registros correspondientes, qué es lo que podemos conseguir de cada uno y qué debemos buscar en ellos. También veremos una forma de hacer filtros para encontrar logs relevantes facilitando nuestra tarea.

## Laboratorio

### Descripción

You have been presented with the opportunity to work as a junior DFIR consultant for a big consultancy. However, they have provided a technical assessment for you to complete. The consultancy Forela-Security would like to gauge your Windows Event Log Analysis knowledge. We believe the Cyberjunkie user logged in to his computer and may have taken malicious actions. Please analyze the given event logs and report back.

### Desarrollo

Como es costumbre, descargamos los archivos correspondientes al sherlock utilizando `7z x` o la herramienta de preferencia con la contraseña `hacktheblue` y en ellos, tal como podríamos sospechar de la descripción... tendremos varios archivos `.evtx` (__Archivos de registro de eventos de Windows__). Para visualizarlos, deberemos utilizar Windows, ya que cuenta con distintas utilidades para tratarlos y hacer distintas cosas con ellos (si quisieramos o la tarea lo requiere).

Antes de avanzar, debemos tener claro lo que cada archivo está registrando, ya que como podrás imaginar, guardan distintos detalles, unos más que otros pero enfocado a tareas específicas:

* Powershell-Operational.evtx: Como sugiere el nombre, guarda eventos relacionados con __operaciones con `PowerShell`__
* Security.evtx: Este archivo registra eventos relacionados con la _seguridad del sistema: __Inicios y cierres de sesión, acceso a objetos, cambios de configuración de seguridad, uso de privilegios__, es uno de los principales logs por los que nos tenemos que fijar al momento de la auditoría.
* System.evtx: Este archivo registra eventos del sistema y acciones relacionadas con los componentes de hardware, __errores del sistema, advertencias, eventos informativos__ y como planteamos, eventos de hardware.
* Windows Defender-Operational.evtx: Este archivo registrará eventos relacionados con las __actividades y el funcionamiento de `Windows Defender`__
* Windows Firewall-Firewall.evtx: Finalmente este archivo registra _eventos relacionados con el firewall de Windows_. __Conexiones permitidas, bloqueadas, cambios en la configuración del firewall, alertas de seguridad, eventos de inicio y detención del firewall__

Una vez entendido esto y en nuestro sistema Windows, abrimos el visor de eventos y para importar los archivos, elegimos: `Action` > `Open Saved Log` o su equivalente en español

![UTMP]({{ "/images/LogJammer/eventimport.png" | relative_url }}){: .align-center}

Una vez elejido el `evtx` lo importará a una carpeta y lo abrirá, puedes importarlos todos para que sea más cómodo moverse entre ellos repitiendo el proceso (tienes que seleccionar `Event Viewer (Local)` o su equivalente para que el menú `Action` permita la opción `Open Saved Log`)

![UTMP]({{ "/images/LogJammer/savedlogs.png" | relative_url }}){: .align-center}

Con ello podemos empezar con las tareas:

#### Q1: When did the cyberjunkie user first successfully log into his computer? (UTC)

Para ello buscamos en el `Security.evtx` ya que como mencionamos antes, se registrarán los inicios de sesión; si buscamos sólo el ID correspondiente al inicio de sesión `EventID 4624` nos encontraremos con __67 eventos__ por lo que tenemos que afinar la búsqueda, para ello tenemos que entender algunas cosas de la estructura de los logs:

Si seleccionamos un log cualquiera, primero veremos que son __hechos con estructura XML__, la estructura que continua ya dependerá del log file a tratar, pero en este caso, podemos verlo seleccionando `Friendly View`:

![UTMP]({{ "/images/LogJammer/xmlstructure.png" | relative_url }}){: .align-center}

Y al hacer el filtro, notaremos que también lo hace con `XML` podemos observarlo si seleccionamos `Filter Current Log` y `XML`

![UTMP]({{ "/images/LogJammer/xmlsearch.png" | relative_url }}){: .align-center}

```xml
<QueryList>
  <Query Id="0" Path="file://C:\Users\myuser\Documents\Sherlock\Security.evtx">
    <Select Path="file://C:\Users\myuser\Documents\Sherlock\Security.evtx">*[System[(EventID=4624)]]</Select>
  </Query>
</QueryList>
```

Como vemos, el filtro actual está filtrando el `EventID=4624` dentro de `System`, lo que podemos confirmar si abrimos la estructura:

![UTMP]({{ "/images/LogJammer/systemeventid.png" | relative_url }}){: .align-center}

Para poner mayores filtros, debemos habilitar la edición de las búsquedas y con una pequeña [guía de filtros](https://techcommunity.microsoft.com/blog/askds/advanced-xml-filtering-in-the-windows-event-viewer/399761) en mano, podemos continuar.

Tenemos varios métodos, hacer múltiples `Select` para unir búsquedas en una sóla o, podemos utilizar múltiples términos a buscar utilizando operadores lógicos como lo es: `and` seleccionando: el `EventID=4624` y `TargetUserName=cyberjunkie` (este último pues contiene el dato de qué usuario está haciendo el login) pero recordando que este último campo no está en `System`, sino en `EventData`:

```xml
<QueryList>
  <Query Id="0" Path="file://C:\Users\myuser\Documents\Sherlock\Security.evtx">
    <Select Path="file://C:\Users\myuser\Documents\Sherlock\Security.evtx">*[System[(EventID=4624)]] and *[EventData[Data[@Name='TargetUserName'='cyberjunkie']]</Select>
  </Query>
</QueryList>
```

Mostrando muchos menos resultados, pero como indica la pregunta, elegimos el que sea el más antiguo:

![UTMP]({{ "/images/LogJammer/Q1.png" | relative_url }}){: .align-center}

###### Nota: Recuerda que el formato de la hora es en UTC, que se registra en el SystemTime dentro del log

```bash
Q1: 27/03/2023 XX:37:09
```

#### Q2: The user tampered with firewall settings on the system. Analyze the firewall event logs to find out the Name of the firewall rule added?

Dentro del log del inicio de sesión de la pregunta anterior, nos encontraremos con el SID del usuario, útil si queremos correlacionar logs.

```
SID: S-1-5-21-3393683511-3463148672-371912004-1001
```

Ahora, nos dirigimos al `Windows Firewall-Firewall` y añadimos algo más al filtro: El tiempo; que ahora que tenemos el timestamp del primer inicio de sesión, podremos usarlo para reducir bastante otros logs:

![UTMP]({{ "/images/LogJammer/timefilter.png" | relative_url }}){: .align-center}

Ya de por sí, abremos reducido bastante los resultados retornados, pero si queremos reducir aún más, podemos añadir otro más con el SID:

```xml
<QueryList>
  <Query Id="0" Path="file://C:\Users\myuser\Documents\Sherlock\Windows Firewall-Firewall.evtx">
    <Select Path="file://C:\Users\myuser\Documents\Sherlock\Windows Firewall-Firewall.evtx">*[System[TimeCreated[@SystemTime&gt;='2023-03-27T14:37:09.000Z']]] and *[EventData[Data[@Name='ModifyingUser']='S-1-5-21-3393683511-3463148672-371912004-1001']]</Select>
  </Query>
</QueryList>
```

Retornando sólo un resultado:

![UTMP]({{ "/images/LogJammer/Q2.png" | relative_url }}){: .align-center}

```bash
Q2: XXXXXXX C2 Bypass
```

#### Q3: Whats the direction of the firewall rule?

En el mismo log, indica la dirección; vendrá en el XML como número pero si vemos la vista general, nos dirá lo que indica

![UTMP]({{ "/images/LogJammer/Q3.png" | relative_url }}){: .align-center}

```bash
Q3: XXXXXound
```

#### Q4: The user changed audit policy of the computer. Whats the Subcategory of this changed policy?

Para esta tarea, sólo podremos correlacionarla por tiempo, y en este caso en particular, un poco de suerte; ya que podremos sólo filtrar el `Security.evtx` por `EventID 4719` que corresponde a Cambios hechos a la Política de Auditoría del Sistema.

```bash
Q4: Other Object Access Events
```

#### Q5: The user "cyberjunkie" created a scheduled task. Whats the name of this task?

Las tareas programadas las encontraremos con los `Security.evtx`, como sabemos el nombre del usuario, podemos hacer una búsqueda bastante sencilla utilizando `xml`:

```xml
<QueryList>
  <Query Id="0" Path="file://C:\Users\myuser\Documents\Sherlock\Security.evtx">
    <Select Path="file://C:\Users\myuser\Documents\Sherlock\Security.evtx">*[EventData[Data[@Name='SubjectUserName']='cyberjunkie']]</Select>
  </Query>
</QueryList>
```

Nos retornará sólo un resultado, con nuestra respuesta en el campo `TaskName`

![UTMP]({{ "/images/LogJammer/Q5.png" | relative_url }}){: .align-center}


```bash
Q5: HTB-XXXXXXXX
```

#### Q6: Whats the full path of the file which was scheduled for the task?

En el mismo log, en uno de los campos/items indica `Command` con una ruta hacia un script de powershell:

![UTMP]({{ "/images/LogJammer/Q6.png" | relative_url }}){: .align-center}

```bash
Q6: C:\Users\CyberJunkie\Desktop\XXXXXXXXXX.ps1
```

#### Q7: What are the arguments of the command?

De la misma forma, notarás el argumento del comando en el mismo log, justo en el siguiente campo:

```bash
Q7: -A cyberjunkie@XXXXXXXX.eu
```

#### Q8: The antivirus running on the system identified a threat and performed actions on it. Which tool was identified as malware by antivirus?

Esta tarea la podremos completar fácilmente por el bajo ruido del `Windows Defender-Operational.evtx`; los _EventCodes_ más significativos son los `1116` indicando una detección de amenaza y el `1117` que indica la acción de esa amenaza (y las 5007 que indican un cambio en la configuración del `Defender`)

Entonces, sabiendo esto, debemos observar los `EventID 1116` donde deveríamos ver el reporte:

![UTMP]({{ "/images/LogJammer/Q8.png" | relative_url }}){: .align-center}

En el mismo, notarás el campo `Name:` que indicará la amenaza reconocida, junto con una herramienta bastante conocida

```bash
Q8: XXXXXXX
```

#### Q9: Whats the full path of the malware which raised the alert?

En el mismo reporte, indicará el PATH en el que fue encontrado, recuerda incluir también la extensión del archivo descargado

```bash
Q9: C:\Users\CyberJunkie\Downloads\XXXXXXXX.VX.X.X.zip
```

#### Q10: What action was taken by the antivirus?

Para averiguar la acción tomada, debemos inspeccionar el `EventID 1117`

![UTMP]({{ "/images/LogJammer/Q10.png" | relative_url }}){: .align-center}

Donde la respuesta la encontraremos en el campo `Action`

```bash
Q10: XXXXXXXX
```

#### Q11: The user used Powershell to execute commands. What command was executed by the user?

Para esta utilizaremos `Powershell-Operational.evtx` donde buscaremos el `EventID 4104` que corresponde a un _Script Block Logging_ (donde se registrarán ejecuciones de powershell vaya) pero correlacionando el `SID` (_Security UserID_) que ya habíamos registrado desde antes y filtrando los eventos que estén fuera del tiempo que tenemos registrada de la instrusión:

```xml
<QueryList>
  <Query Id="0" Path="file://C:\Users\htb-student\Documents\Sherlock\Powershell-Operational.evtx">
    <Select Path="file://C:\Users\htb-student\Documents\Sherlock\Powershell-Operational.evtx">*[System[TimeCreated[@SystemTime&gt;='2023-03-27T14:37:09.000Z']]] and *[System[EventID=4104 and Security[@UserID='S-1-5-21-3393683511-3463148672-371912004-1001']]]</Select>
  </Query>
</QueryList>
```

Donde en uno de los 3 bloques, mostrará un comando:

![UTMP]({{ "/images/LogJammer/Q11.png" | relative_url }}){: .align-center}

```bash
Q11: Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1
```


#### Q12: We suspect the user deleted some event logs. Which Event log file was cleared?

Cuando borramos el Log file, puede llegar a registrarse en distintas partes, pero siempre depende del log file que se esté targeteando, por ejemplo, en el `Security.evtx` se genera un `EventID 1102` con el nombre del usuario que lo limpió, mientras que en otros logs como `System.evtx`, `Application.evtx` entre otos se genera un `EventID 104` refiriéndose a la misma operación. Si lo buscamos en los log files, veremos la entrada en el `System.evtx`. Si hacemos la búsqueda con sólo el filtro del ID, veremos que tendremos 15 eventos...

![UTMP]({{ "/images/LogJammer/Q121.png" | relative_url }}){: .align-center}

Mientras que si buscamos por la fecha correspondiente de todo el ataque/tiempo que nos es importante, retornará sólo un resultado y nuestra respuesta:

![UTMP]({{ "/images/LogJammer/Q12.png" | relative_url }}){: .align-center}

```bash
Q12: Microsoft-Windows-Windows Firewall With Advanced Security XXXXXXXX
```


###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.

