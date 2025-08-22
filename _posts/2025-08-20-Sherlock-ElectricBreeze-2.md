---
layout: single
title: "Sherlocks - ElectricBreeze-2 (HTB)"
author_profile: true
published: true
---

Los sherlocks (De HackTheBox) son retos gamificados enfocados a __Blue Team__, en ellos, se encuentran distintas situaciones donde uno debe utilizar herramientas de analsis y artefactos para completar las tareas. Y claro, hay __categorías__ según lo que quieras entrenar, como por ejemplo _Malware Analysis_ que se enfocan en el __análsis de malware y archivos maliciosos__ donde habrá que descubrir las características del artefacto malicioso para averiguar qué es lo que hace.

![UTMP]({{ "/images/ElectricBreeze/logo.png" | relative_url }})

## Resumen ElectricBreeze-2

Este sherlock es un sherlock fácil enfocado al análisis dinámico de una muestra de malware `jar`, junta un poquito de todo el __proceso de análisis__ para una muestra sencilla de analizar, ideal para acostumbrarse al __proceso de análisis estático__.

## Laboratorio

### Descripción

_Your boss is concerned about Volt Typhoon and some of their malware developments. He has requested that you obtain a copy of the associated malware and conduct a static analysis to identify any useful information. Please report back with your findings._

### Desarrollo

En este sherlock, no se nos dan archivos directamente, las preguntas nos irán guiando poco a poco para desentrañar las acciones del malware.

#### Q1: Use MalwareBazaar to download a copy of the file with the hash '4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37'. What is the URL to do this?

_MalwareBazaar_ Es una plataforma de _abuse.ch_ y _Spamhaus_  dedicada a compartir muestras de malware con la comunidad de seguridad de la información, inteligencia de amenazas y proveedores de antivirus, es una de las bases de datos más grandes relacionadas con muestras de malware, proveen sus características, reglas YARA, e incluso, la familia del malware.

Para inciar entonces, necesitamos crear una cuenta y buscar el hash; las muestras generalmente se dan con los hases __MD5__, __SHA256__, __SHA1__, entre muchos otros, esto permite diferenciar la muestra de malware de las otras (excepto firmas como __imphash__ o __ssdeep__ que tratan de detectar muestras parecidas). Dada la extensión del hash, podemos sospechar que se trata de un __SHA256__, por lo que utilizamos la siguiente búsqueda:

```bash
sha256:4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37
```

Nos regresará un hit:

![UTMP]({{ "/images/ElectricBreeze/Hit1.png" | relative_url }})

Y dando click en el hash, podremos ver sus características y la opción de descargar la muestra, por lo que sólo tendremos que copiar el link de `Descargar Muestra`:

![UTMP]({{ "/images/ElectricBreeze/Q1.png" | relative_url }})

```bash
Q1: https://bazaar.abuse.ch/download/4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37/
```

#### Q2: What is the password to unlock the zip?

Antes de dar con la respuesta es importante puntualizar algo, debemos estar concientes de que las muestras que descargamos tienen el potencial de comprometer nuestro sistema y a parte de ello, se contribuyen con medidas adicionales (a veces) para tratar de evitar este escenario; se quitan las extensiones y se comprimen con contraseña, esto __que se considera estandar en la industria__ una clase de recordatorio de que _estás trabajando con una muestra de malware y debe considerarse peligrosa a la medida de lo posible_ (Aunque otras veces, __puede no ser la misma__)

![UTMP]({{ "/images/ElectricBreeze/Q2.png" | relative_url }})

```bash
Q2: infected
```

#### Q3: What is the extension of the file once unzipping?

Descargando el archivo, podemos moverlo a un directorio donde podamos organizarnos tranquilamente y extraemos el archivo (en mi caso, con `7z`)

```bash
7z x ElectricBreeze2.zip
```

Y listando, podremos ver el contenido y la respuesta:

![UTMP]({{ "/images/ElectricBreeze/Q3.png" | relative_url }})

```javascript
Q3: .jar
```

#### Q4: What is a suspicious directory in META-INF?

El `META-INF` es un directrio reservado en los `.jar` (y en `.ear` y `.war`) que contiene información de metadatos sobre el archivo, a forma general, el describir el contenido y dar instrucciones de como comportarse al ser ejecutado o utilizado como librería, es decir, que __da un insight sobre cómo está armado y cómo se comporta__.

Esto, puede hacerse de varias maneras, la sencilla, es descomprimiendo el `.jar` u otra, analizando los strings, esto aprovechando que sabemos que la respuesta se encuentra en el `META-INF`:


```bash
strings 4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37.jar | grep META-INF
```

Y nos saldrá un ouput reducido, donde si observamos cada uno, el que salta a la vista tiene un nombre efectivamente sospechoso... ¿será bueno que algo tendría el string `memShell`?

![UTMP]({{ "/images/ElectricBreeze/Q4.png" | relative_url }})

```bash
Q4: Director_tomcat_memShell
```

#### Q5: One of the files in this directory may give some insight into the threat actor's origin. What is the file?

Ahora sí, tendremos que descomprimir el .jar para analizarlo más a fondo:

```bash
unzip 4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37.jar -d stage0
```

Y entrando al nuevo directorio `stage0` podremos ver los contenidos de `META-INF` a detalle:

```javascript
tree META-INF
META-INF
├── MANIFEST.MF
└── maven
    ├── org.example
    │   └── Director_tomcat_memShell
    │       ├── pom.properties
    │       └── pom.xml
    └── org.javassist
        └── javassist
            ├── pom.properties
            └── pom.xml
```

Dado que el archivo sospechoso se encuentra dentro de `Director_tomcat_memShell` tenemos que enumerar ambos, pero en el `.xml`, encontramos algo en particular:

![UTMP]({{ "/images/ElectricBreeze/Q5.png" | relative_url }})

```bash
Q5: pom.xml
```

#### Q6: According to Google Translate, what language is the suspicious text?

Para esto, sencillamente sólo tenemos que copiar y pegar:


![UTMP]({{ "/images/ElectricBreeze/Q6.png" | relative_url }})

```bash
Q6: Chinese
```

#### Q7: What is the translation in English?

Con la imagen anterior, también podemos ver la respuesta a esta pregunta:

```bash
Q7: Check for the latest version
```

#### Q8: According to this file, what is the application's name?

Revisando el `.xml` puedes dar con la respuesta, sólo habrá que ver el campo name del archivo:

![UTMP]({{ "/images/ElectricBreeze/Q8.png" | relative_url }})

#### Q9: The VersaMem web shell works by hooking Tomcat. Which file holds the functionality to accomplish this?

Ahora, del XML, podemos extraer un poco de más información, ¿a qué funciones llama?:

![UTMP]({{ "/images/ElectricBreeze/Lxml.png" | relative_url }})

Esto indica una ruta dentro del `.jar` la cual apunta a la clase Main que guardará todas las funcionalidades.

```javascript
com/versa/vnms/ui ❯ tree .       
.
├── config
│   └── Config.class
<SNIP>
├── TestMain.class
├── transformer
<SNIP>
```

```javascript
Q9: com/versa/vnms/ui/TestMain.class
```

#### Q10: There is a command that determines the PID for the hook. What is the program used in this line of code?

Ahora, para examinar el `TestMain.class` necesitamos un decompiler para poder ver los contenidos, yo recomiendo utilizar [JD-GUI](https://java-decompiler.github.io/) Pero puedes utilizar otro sin problema.

En mi caso:

```bash 
java -jar ~/Documents/Tools/uncategorized/jd-gui/jd-gui-1.6.6.jar TestMain.class
```

Navegando al `TestMain.class` podremos encontrar la función de entrada, más técnicamente el inyector y con ello, nuestra respuesta:

![UTMP]({{ "/images/ElectricBreeze/Q10.png" | relative_url }})

```bash 
Q10: pgrep
```

#### Q11:The functionality for the webshell is in a different file. What is its name?


Para esta pregunta, es un poco de seguir el flujo de la ejecución; _imaginar visualmente cómo se ejecuta_ te ayudará a entender a fondo qué es lo que hace, Entonces si iniciamos en Main y bajamos poco a poco, la función llama a otra en la misma clase:

![UTMP]({{ "/images/ElectricBreeze/T1.png" | relative_url }})

Siguiendo el flujo, veremos que llega a `TestMain` que rápidamente, inicia la clase `init`; luego `init` llamará a `config.init`

![UTMP]({{ "/images/ElectricBreeze/T2.png" | relative_url }})

Cuando la ejecución alcanza la clase `Config`, que a forma general, empieza a configurar dinámicamente guardando parámetros y parseando cadenas; pero nada más allá, a lo que si continuamos viajando por las clases, parece repetitivo, y no llama a nada más fuera de sí.

![UTMP]({{ "/images/ElectricBreeze/T3.png" | relative_url }})

Esta parte, concluimos que devuelve algún valor y continua la ejecución antes de ser llamada: justo en `init` en el `Main`. La siguiente clase que llamará es justo... 

```bash
CoreClassFileTransformer coreClassFileTransformer = new CoreClassFileTransformer(inst);
```

Que crea un objeto `CoreClassFileTransformer` 

Y vemos las siguientes 2 clases:

![UTMP]({{ "/images/ElectricBreeze/T4.png" | relative_url }})

Si observamos la clase `WriteTestTransformer` y su contenido, notaremos el string `insertShell` y justo después, strings interesantes relacionados con manejo de sesiones http:

![UTMP]({{ "/images/ElectricBreeze/Q11.png" | relative_url }})

Lo que nos da una pista sólida de que esta es la clase que buscamos.

```bash
Q11: com/versa/vnms/ui/init/WriteTestTransformer.class
```

#### Q12: What is the name of the function that deals with authentication into the webshell?

Observando las 2 cadenas, en una de ellas veremos que tiene distintos parámetros como `String accessPwd` o `if (accessPwd.equals(pwd)) || accessPwd.equals(authStr)` también es pista sólida de que sea para este propósito:

```bash
Q12: getInsertCode
```

#### Q13: What request parameter must be present to activate the webshell logic?

Desde aquí, podemos hacer algo para __facilitar el análisis__; si bien podemos _investigar la linea de inicio a fin_ podemos pasar al formato en el que está escrito el payload; notarás los __espacios__ y los __newlines__ así que sólo habrá que hacer un `echo` de la función y potencialmente obtendremos el formato funcional y limpio:

```
❯ echo "{\n            String pwd = <SNIP> this.internalDoFilter($1, $2);\n        }" > Stage1
```

Y un simple cat, mostrará un formato mucho más cómodo de trabajar

![UTMP]({{ "/images/ElectricBreeze/N1.png" | relative_url }})

Ahora, justo al inicio, está el parámetro esperado por `getParameter` que es el char `p`

```java
String pwd = .getParameter("p");
```

```bash
Q13: p
```

#### Q14: What is the hardcoded access password used to validate incoming webshell requests?

Dado que el siguiente parámetro es un string MUY parecido a _password_ (_accessPwd_) es lógico pensar que esta es la clave de acceso.

```bash
Q14: 5ea23db511e1ac4a806e002def3b74a1
```

#### Q15: What type of encryption is used?

Si avanzamos con la cadena un poco, veremos una serie de números y el string AES lo que nos dice que esta es la llave y justo esta es la que utiliza para encriptar:

```java
SecretKeySpec(new byte[]{56, 50, 97, 100, <SNIP>, 97, 97}, "AES");
```

```bash
Q15: AES
```

#### Q16: What cipher mode is used to encrypt the credentials?

Justo después, en la siguiente linea, encontraremos la cadena del __modo de cifrado__:

```java
ipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

```bash
Q16: ECB
```

#### Q17: What is the key?

Hace 2 preguntas atrás, hemos conseguido la llave:

```bash
Q17: 56, 50, 97, 100, 52, 50, 99, 50, 102, 100, 101, 56, 55, 52, 99, 53, 54, 101, 101, 50, 49, 52, 48, 55, 101, 57, 48, 57, 48, 52, 97, 97
```

#### Q18: What is the value of the key after decoding?

Si observamos con atención, podremos notar que los valores _se concentran desde los 50 hasta los 100, da un indicio de que pueda ser_ `ASCII`.

Para convertirlo, no necesariamente tenemos que quitar las comas `,`, sólo usamos un convertidor `ASCII` como el de [RapidTables](https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html) donde ingresamos toda la cadena al campo `Decimal (bytes)` y _copiamos el texto resultante_ (el texto decodificado).

![UTMP]({{ "/images/ElectricBreeze/Q18.png" | relative_url }})

```bash
Q18: 82ad42c2fde874c56ee21407e90904aa
```

#### Q19: To avoid static detection, the method name is constructed at runtime and passed to java.lang.reflect.Method, what is the decimal byte array used to construct the string name?

Si continuamos el flujo de la función, veremos el método `java.lang.reflect.Method` mencionado donde se declara el arreglo buscado.

![UTMP]({{ "/images/ElectricBreeze/Q19.png" | relative_url }})

```bash
Q19: 100, 101, 102, 105, 110, 101, 67, 108, 97, 115, 115
```

Que equivale al string `defineClass`

#### Q20: What is the Base64-encoded string that is returned to the client if the class is successfully defined?

Siguiendo la lógica del programa, podemos puntualizar que este bloque `if` está confirmando si se encuentra la clase `clzn`, en el caso que no se haya cargado, __intenta cargarla directamente__ desde los datos pasados en el parámetro `clzd` al cargar la clase después de cargarla de forma reflexiva con el `ClassLoader`, __escribe la respuesta cifrada en b64__ con `httpResponse.getWriter().write`:

```bash
Q20: R2qBFRx0KAZceVi+MWP6FGGs8MMoJRV5M3KY/GBiOn8=
```

#### Q21: What is the decrypted string?

Esto lo podemos hacer con cyberchef; primero, sabemos que es un base64 (por la pregunta anterior pero podemos sospecharlo fuertemente por caracteres como `+/=`) y el resultante estará cifrado en _AES/ECB_ (pero no olvidemos el `PKCS5Padding` que indica) que __no necesitamos Initialization Vector para descencriptar__. Así que sólo tenemos que agregar el _From base64_, agregar el _AES Decrypt_ ingresar el _key_ (__la cadena de la pregunta 18__) en UTF-8, El modo _ECB/NoPadding_ y el _Raw Input_

![UTMP]({{ "/images/ElectricBreeze/Q21.png" | relative_url }})

```bash
Q21: classDefine by clzd
```

#### Q22: There is another class to log passwords for exfiltration. What is this file?

Ahora, retornemos la ejecución a `CoreClassFileTransformer`, donde fue llamada `WriteTestTransformer`, avanzando a la siguiente linea, encontramos `CapturePassTransformer` y un overview rápido, encontramos una función con un __nombre muy directo__ `captureLoginPasswordCode` que nos da una razón para creer que es este archivo class el que buscamos.

```bash
Q22: com/versa/vnms/ui/init/CapturePassTransformer.class
```

#### Q23: What is the main malicious function in this class?

Esta pregunta se responde con la anterior, en primera el nombre tan directo pero también repite el patrón de crear un one liner de una función más grande como la clase anterior.

```bash
Q23: captureLoginPasswordCode
```

#### Q24: The same AES key from the previous method is being used. What is the variable name it is being saved as in this function?

Repitamos el proceso de pasar el one liner a un archivo para facilitar su lectura, y vemos que efectivamente, utiliza la misma llave.

![UTMP]({{ "/images/ElectricBreeze/Q23.png" | relative_url }})

```bash
Q24: secretKey
```

#### Q25: What file is used to hold credentials before exfiltration?

Si observamos el código, podemos darnos cuenta rápidamente de una declaración de una ruta absoluta en una variable llamada `logFile`, y un `bash -c`, con estos elementos, podemos interpretar __exactamente lo que hace__ este bloque: `logData` (que es texto en b64) es buscado dentro de `logFile` (`/tmp/.temp.data`) con `grep` (con la opción `-q` para indicar `quiet`), es decir, busca si existe ya dentro del archivo, __si NO encuentra esos datos__, entonces se añade el `logData` a `logFile`, habiendo entendido esto, el archivo que mantiene las credenciales es `logFile` o bien `/tmp/.temp.data`

```bash
Q25: /tmp/.temp.data
```


###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.



