---
layout: single
title: "Sherlocks - Malevolent ModMaker (HTB)"
author_profile: true
published: true
---

Los sherlocks (De HackTheBox) son retos gamificados enfocados a __Blue Team__, en ellos, se encuentran distintas situaciones donde uno debe utilizar herramientas de analsis y artefactos para completar las tareas. Y claro, hay __categorías__ según lo que quieras entrenar, como por ejemplo _Malware Analysis_  que se enfocan en el __análsis de artefactos y archivos maliciosos__ con el objetivo de entender su funcionalidad, origen e impacto, para poder crear medidas de detección mejorando la seguridad del entorno.

![UTMP]({{ "/images/MalevolentModMaker/logo.png" | relative_url }}){: .align-center}

## Resumen Malevolent ModMaker

En este escenario de análisis de malware, exploraremos varios métodos de análisis estático, principalmente de `strings` en binarios de go (también se recomienda utilizar HxD o `Malcat`, entre más métodos por conocer... mejor!). Luego, exploraremos el flujo con `ghidra` y debuggearemos con `x64dbg` para ver los cambios en el programa en tiempo real para analizar una muestra de ransomware.

## Laboratorio

### Descripción

Bob, a senior software engineer at Acme Inc., was taking a break from correcting AI code to check in with his favorite gaming community. One of the newer members shared a new program that can make mods for a popular game. Eager to try new things, when he ran it as administrator (as instructed), all of his files were deleted and replaced! He immediately called the help desk, so they locked his machine and an incident response was called!

### Desarrollo

Podemos iniciar entonces con la descarga de los archivos y vemos el contenido resumido a un __archivo txt y un archivo zip__. 

```js
❯ ls             
    danger.txt
    danger.zip

```

El archivo txt es un _aviso_ sobre el archivo de que puede interactuar con tu máquina por lo que es indispensable tener buenas prácticas como el aislar el sistema, y finalmente, la contraseña para el archivo; donde podemos ver algunos archivos interesantes...

#### Q1: Right from the start, based on the incident details, the .TXT file's contents, and the extension appended to the other .TXT file, what type of malware infection is this?

```js
❯ ls             
    bruh.exe
    D.txt
    goteem.exe
    MCModMaker-v.1.4.exe
    probably_important.txt.goteem
```

Enfocándonos a la pregunta, examinamos el archivo `D.txt` y tenemos una pista clara de lo que es...

```js
HA! GOTEEM! To get your files back, gotta pay us 1 BTC to: d32a7dafsd432789df798

We'll give you the decryption key, then you run the following command from the folder with `bruh.exe`:
.\bruh.exe -key <DECRYPTION_KEY> 
```

Sumando el contexto de que los archivos fueron borrados, reemplazados y esta nota, indica claramente varias cosas:

* El ejecutable es un `Ransom`.
* El archivo `bruh.exe` es el desencriptador.
* Hay una dirección de una cartera de bitcoin, es muy probable que podramos hacer Threat Intelligence para obtener más detalles sobre el threat actor o campañas similares (si es que se llegara a requerir)

Así que la respuesta a la pregunta... Definitivamente es un:

```bash
Q1: Ransomware
```

#### Q2: What mechanism does MCModMaker-v.1.4.exe use to send information back to the C2 server?

Ahora, examinando inicialmente con file, vemos que efectivamente, es un PE de windows:

```js
❯ file MCModMaker-v.1.4.exe 
MCModMaker-v.1.4.exe: PE32+ executable (console) x86-64, for MS Windows, 8 sections
```

Y haciendo un escaneo con strings, nos daremos cuenta que ¡hay una cantidad insana de ellos! (y esto puede indicar...)


```js
/usr/local/go/src/net/http/pattern.go
/usr/local/go/src/net/http/servemux121.go
/usr/local/go/src/net/http/status.go
/usr/local/go/src/net/http/clone.go
/usr/local/go/src/net/http/roundtrip.go
/usr/local/go/src/os/exec/exec.go
/usr/local/go/src/os/exec/exec_windows.go
/usr/local/go/src/os/exec/lp_windows.go
/root/CompletelySafe/main.go
*m	p
PuO#
`3_(
```

Que es un ejecutable hecho con __golang__; y esto tiene cierto impacto para nuestro análisis:

* Los ejecutables de __golang__ son particularmente _complicados_, de la forma en que son _estáticamente vinculados_, lo que se traduce en que todas las bibliotecas están dentro del ejecutable.
* Entonces, resulta en un archivo muy grande, con muchas funciones generadas por el compilador.
* Herramientas tradicionales como Ghidra o IDA, se ven un poco limitados en cuestión de reconocimiento de funciones e incluso de strings

Pero no todo es exactamente malo, existen plugins y extensiones que pueden ayudar a estas herramientas a resolver estos puntos débiles y, a parte nos cambia mucho la forma de examinar los strings: Cuando desarrollas malware en `Golang` te darás cuenta que el __OpSec es súmamente crítico__ ya que en la compilación se obtienen detalles del sistema en que fue creado, como las rutas absolutas del entorno y algunas variables, así que si no se obfusca un poco... es relativamente sencillo ver detalles que podrías querer ocultar como atacante.

Entonces, podemos saber muchos detalles si no está ofuscado, así que podemos continuar utilizando strings pero con __búsquedas mucho más específicas__

Si buscamos un C2... entonces, buscamos... `url` o bien, el puro esquema (el `http`):

```js
 ❯ strings MCModMaker-v.1.4.exe | grep "http://" 
<SNIP!>
public exponent is not a positive numbercrypto/cipher: incorrect nonce length given to GCMchacha20: SetCounter attempted to rollback counteredwards25519 invalid SetUniformBytes input lengthhttps://discordapp.com/api/webhooks/213742/clmlP5yKhttp2: invalid Transfer-Encoding request header: %qprotocol error received %T before a SETTINGS framelimiterEvent.stop: invalid limiter event type foundpotentially overlapping in-use allocations detectedruntime: netpoll
<SNIP>
```

Obtenemos distintos dominios, pero uno de ellos, nos dice exáctamente cómo se comunica, utilizando el mecanismo de:

```bash
Q2: Warhook
```

#### Q3: What command does MCModMaker-v.1.4.exe run suggesting that it is meant to execute other binaries or scripts?

Ahora, sólo tenemos que plantearnos... cómo piensa ejecutar comandos?, pues lo más común, buscar nuestras consolas favoritas: __cmd__ y __powershell__

![UTMP]({{ "/images/MalevolentModMaker/Q3.png" | relative_url }}){: .align-center}

Como notarán en la imagen, ambos strings pueden indicar ejecución, pero especialmente, el de `powershell`, indica una ejecución _evadiendo la protección_ (`bypass`) del `Execution-Policy`. _Es importante resaltar que los strings pueden combinarse pero en evasión del execution policy, el argumento es sólo `bypass`_

Siendo el comando de powershell, nuestra respuesta:

```bash
Q3: powershell -c $cmd
```

#### Q4: What is the value of the API key contained within the URL which suggests it enumerates geolocation data?

Seguimos utilizando strings, ahora lo más sencillo, es buscar `api` como sugiere la pregunta, en dado caso que no nos de resultados, cambiamos el término a `API` o algo parecido o filtramos aún más la búsqueda.

```js
strings MCModMaker-v.1.4.exe | grep "http" | grep "api"
```

Dentro de todo lo que devuelve, veremos una `URL` con los strings `country,city` y la `apiKey` que nos habla la pregunta

![UTMP]({{ "/images/MalevolentModMaker/Q4.png" | relative_url }}){: .align-center}

```bash
Q4: ZVaVoDH7
```

#### Q5: What domain is the C2 server that serves the ransomware payload?

Volvemos al mismo comando de la segunda pregunta; recuerda que si buscamos un dominio, es muy probable que esté incluyendo el schema `http` o bien `https`.

```js
 ❯ strings MCModMaker-v.1.4.exe | grep "http://" 
```

![UTMP]({{ "/images/MalevolentModMaker/Q5.png" | relative_url }}){: .align-center}

Es importante que notes los 3 dominios, pero en especial, __uno que apunta hacia un ejecutable__, siendo nuestra respuesta:

```bash
Q5: goolang.god
```

#### Q6: While analyzing the MCModMaker-v.1.4.exe, what format is the data that is returned to the C2 server?

Ahora, buscamos cabeceras `HTTP`, si la pregunta es cuál es el formato, deberíamos pensar en la cabecera `Content-Type`, si no están en la misma linea, es probable que necesitemos un poco de margen para ubicar el tipo correcto:

```js
❯ strings MCModMaker-v.1.4.exe | grep "Content-Type" -A 10
```

Si vamos revisando poco a poco todos los strings, notaremos poco después que vendrán especificadas en un sólo espacio, todos los valores de las cabeceras que utiliza:

![UTMP]({{ "/images/MalevolentModMaker/contenttype.png" | relative_url }}){: .align-center}

Donde en particular, debemos notar una cabecera que si tenemos un poquito de familiaridad con web proxies u `http` podremos saber que es la respuesta.

![UTMP]({{ "/images/MalevolentModMaker/Q6.png" | relative_url }}){: .align-center}

```bash
Q6: content/php
```

#### Q7: What specific filetype is enumerated by goteem.exe for encryption?

Ahora, cambiamos de ejecutable, para examinarlo confirmamos si sigue siendo hecho en go:

```js
❯ strings goteem.exe | grep go  
```

Que al final veremos la versión utilizada:

```js
<SNIP!>
/usr/local/go/src/strings/strings.go
/usr/local/go/src/strings/builder.go
/root/goteem/main.go
go1.23.4
```

Una vez confirmado, podemos seguir intentando localizar información con `strings`, ahora, como nos piden extensiones o filetypes, podemos buscar estos términos `docx` `pdf` `xml` `extension` `filetypes` `file` `name`, el chiste es que veas qué tipo de información devuelve cada búsqueda y consideres si fue significativa, y si lo fue, agregar más terminos para centrar más la búsqueda. Un buen término es `file`, que si revisamos un poco...


```bash
unexpected argument typeError creating cipher for file %s: %v
Error generating nonce for file %s: %v
Error writing encrypted file %s: %v
error: Error creating GCM for file %s: %v
```

Es posible que estemos cerca de la respuesta, y si no es con ese término, saber cómo se define %s puede ser muy buen camino; pero si seguimos revisando buscando extensiones, podremos captar una medio oculta:

```js
Error scanning for .txt files: runtime: cgocallback with sp=runtime: bad g in cgocallback
```

Dándonos una fuerte indicación de la extensión objetivo del malware:

```BASH
Q7: TXT
```

#### Q8: What is the full string that's displayed when goteem.exe enumerates a restricted Windows folder?

Ahora, buscamos un aviso y strings fuertes o lógicos para la pregunta pueden ser: `restricted` `restrict` `deny` `access` o parecidos, donde en uno de ellos, obtenemos un hit y la respuesta:

![UTMP]({{ "/images/MalevolentModMaker/Q8.png" | relative_url }}){: .align-center}

```BASH
Q8: Skiping file: %d (Acess denied)
```

#### Q9: Within the encryptFile function, in case file was read successfully, what is the function name found at the call instruction?

Finalmente es momento de utilizar un decompilador para revisar la funcionalidad del programa. Esto podremos lograrlo utilizando `ghidra` en su versión actualizada (11.4.2) que puede hacer un gran trabajo en decompilar el programa; si queremos añadir más detalles que nos puedan ayudar, también podemos utilizar `GoResolver` de [este repositorio](https://github.com/volexity/GoResolver/tree/main).

Entramos a `ghidra` y creamos un nuevo poryecto con _File > New Project_ y elegimos el nombre y pocos detalles maś. Luego importamos el archivo con _File > Import File_.

Al abrir el archiv (con doble clic sobre el archivo) veremos el _ASM_ y el _Decompiler_, y como ya nos proporcionan el nombre de la función, podemos utilizar `strings`.

Seleccionamos entonces _Search > For Strings_ ingresamos `encrypt` y veremos una coincidencia llamada `main.encryptFile`

![UTMP]({{ "/images/MalevolentModMaker/ghidrasearch.png" | relative_url }}){: .align-center}

Y seleccionamos el `XREF` y la dirección (indica la dirección de donde es llamada esta función) luego, seleccionamos `main::main.encryptFIle entryOff` que nos dirigirá justo a donde podremos examinar la función y para verla visualmente, seleccionamos Display Function Graph


![UTMP]({{ "/images/MalevolentModMaker/functiongraph.png" | relative_url }}){: .align-center}

Ahora iniciemos con el análisis, después de un `while loop`, avanzamos hacia el siguiente fragmento, el cual contiene un call de una función llamada `os::os:ReadFile`, como vemos en las instrucciones, si la función devuelve otra cosa que no sea un cero, continúa el flujo hacia `004b71cb` (ya que la instrucción `JZ LAB__004B7293` indica que si devuelve un 0, el flujo sigue hacia `LAB__004B7293`) 

![UTMP]({{ "/images/MalevolentModMaker/ghidrafalse.png" | relative_url }}){: .align-center}

Ahora, si examinamos ese flujo, nos encontraremos muy pronto lo que pasa si continuamos ese flujo viendo las instrucciones del decompilador:

![UTMP]({{ "/images/MalevolentModMaker/ghidraerror.png" | relative_url }}){: .align-center}

__Esta rama finaliza con un error__ sobre la lectura del archivo, esto según la pregunta, indica que estamos en el punto donde la lectura es fallida, entonces... para la respuesta, sólo debemos movernos al flujo en `LAB__004B7293` donde ahora sabemos, que es cuando la lectura es exitosa.

![UTMP]({{ "/images/MalevolentModMaker/Q9.png" | relative_url }}){: .align-center}

Una vez aquí, verás una instrucción `CALL` y por nuestra pregunta, apunta a ser nuestra respuesta:

```BASH
Q9: crypto_bes_NewCypher
```

#### Q10: What is the decryption key?

Ahora, continuemos el flujo con la misma lógica que la anterior.

Inmediantamente después, la instrucción `JZ LAB_004b7391` indica que en caso de que nuestra función `crypto/aes.NewCipher` devuelva un 0, el flujo continuará hacia `LAB_004b7391`, caso contrario, el flujo continua a `004b72cb`. donde al final de ese flujo, indica un error pero ahora, __sobre el cifrado del archivo__

![UTMP]({{ "/images/MalevolentModMaker/ghidracripterror.png" | relative_url }}){: .align-center}

Puedes tenerlo en cuenta como para un indicador 'del buen camino' y no asustarte tanto, eso sí, aquí es crítico que entiendas cómo funciona el ensamblador, las operaciones y el flujo de las operaciones, ¿por qué? por que es fundamental que entiendas cómo se mueven las cosas entre los registros y las direcciones, con suerte, en el laboratorio no es tan necesario profundizar para la respuesta, pero tampoco es taaan sencillo.

Antes de meternos a la función `crypto/aes.NewCipher` podemos seguir leyendo el decompilador y entender qué es lo que hace en sí, `Newcipher`, cuál es su funcionamiento. 

Veamos en el decompilado:

```js
  mVar10 = crypto/aes::crypto/aes.NewCipher([Var9);
  local_120 = mVar10.~r1.data;
  local_168 = mVar10.~r1.tab;
  local_100 = mVar10.~r0.data;
  local_140 = mVar10.~r0.tab;
```

Podemos ir pensandop: "esta función, crea un objeto ingresando un valor" (pues aún no sabemos exactamente qué es) "y lo almacena en una variable, de la cual, se utiliza para darle valores a más variables" (hablando MUY informalmente), si continuamos examinando, nos encontraremos el ¿para qué se utiliza este objeto?

```js
  cipher.data = local_100;
  cipher.tab = local_140;
  mVar11 = crypto/cipher::crypto/cipher.newGCMWithNonceAndTagSize(cipher,0xc,0x10);
  local_120 = mVar11.~r1.data;
  local_168 = mVar11.~r1.tab;
```

¿Qué significa? Pues directamente, la función que prepara la un objeto GCM (que se utilizará para encriptar), si te preguntas qué son los otros 3 argumentos o valores, pues toca leer un poquito de documentación.

Pero para hacer esto un poquito más ameno, el primer argumento, es un objeto que __ya ha sido inicializado utilizando la llave__, el segundo el tamaño del _nonce_ o nuestra _IV_ (que `0xc` indica 12 en decimal), y finalmente el tamaño del `tag` (que es especial en GCM, pero no nos meteremos demasiado)

Entonces, ahora sabemos por documentación que el objeto `cipher` ya fue creado utilizando la llave, ¿pues qué sigue?, irnos atras __cuando fue declarada__ claro, ahora con la seguridad de que examinando el flujo, conseguiremos la llave!.

Para esto, me gusta hacerlo de la forma en que uno aprenda: metiéndose en ensamblador.

_Cuando nosotros llamamos a una subrutina, (llámale función), en ensamblador, esamos indicando una instrucción `CALL` pero, en algunas y como todos los lenguajes de programación, para hacer objetos muchas veces necesitamos ingresar cosas a esa función..._ ¿no?, entonces, ¿cómo lo hacemos en ensamblador?.

Para ello, empezamos a `mov`er los datos necesarios dentro de la pila, esto con el objetivo de que sean ingresables, y esto aplica para cuando igual, se salga de una subrutina, (por un return por ejemplo), las acciones más comunes que verás alrededor de ellas, son los `MOV`


```s
                     main.go:52 (29)
004b72a8 48 8b 84        MOV        param_1,qword ptr [RSP + Stack[0x18]]
         24 10 02 
         00 00
004b72b0 48 8b 9c        MOV        param_2,qword ptr [RSP + Stack[0x20]]
         24 18 02 
         00 00
004b72b8 48 8b 8c        MOV        param_3,qword ptr [RSP + Stack[0x28]]
         24 20 02 
         00 00
004b72c0 e8 db 62        CALL       crypto/aes::crypto/aes.NewCipher                 multireturn{crypto/cipher.Block;
         fc ff
004b72c5 48 85 c9        TEST       param_3,param_3
004b72c8 0f 84 c3        JZ         LAB_004b7391
         00 00 00
004b72ce 48 89 bc        MOV        qword ptr [RSP + local_120],param_4
         24 d8 00 
         00 00
004b72d6 48 89 8c        MOV        qword ptr [RSP + local_168],param_3
         24 90 00 
         00 00
```

Y justo, por eso nos interesa ver qué ingresa al objeto, __porque la llave entra en la función__ para crear al objeto. Entonces finalmente...

¡Debugging! (Por ejemplo `x64dbg`) (_mucho cuidado aquí, si no controlas el flujo el ransomware se va a llevar todos tus txt_)

Abriendo el programa, lo primero que hago, es ver el offset que tengo con `ghidra` con respecto a `x64dbg`; para esto me gusta utilizar los todos poderosos strings:

En `x64dbg`, puedes dar _click derecho > Search for > Current Module > String references_ y buscar algo como... `encrypt` y seleccionar el del mensaje del error `Error writing encrypted file`, ¿por qué?, entre ambas herramienta habrá un pequeño descuadre de las direcciones pero con un poquito de cálculo puedes pasar sin problema. 

Hacemos lo mismo en `ghidra` _Search > For Strings_ y buscar el mismo término

![UTMP]({{ "/images/MalevolentModMaker/ghidrastrings.png" | relative_url }}){: .align-center}

Te diriges a la dirección indicada (la terminación `7778`) y notarás que ambas direcciones son __similares pero no iguales__, en mi caso, sólo es sumar 2 de hexadecimal a mi 5to byte (b -> d), tendrás que hacer el cálculo para tu caso.

![UTMP]({{ "/images/MalevolentModMaker/x64dbgoffset.png" | relative_url }}){: .align-center}

Ya con el offset calculado, en `ghidra` nos dirigimos a la creación del objeto que nos interesa (puede ser cuando hace el call, o incluso cuando dentro de la subrutina) y anotamos la dirección:

![UTMP]({{ "/images/MalevolentModMaker/ghidranewcypher.png" | relative_url }}){: .align-center}

Luego, en el debugger; sólo haría falta agregar un _Break Point_ con `F2` en la misma dirección (aplicando el offset, debería verse exactamente la misma instrucción del assembly).

Ejecutamos en el debugger y...

![UTMP]({{ "/images/MalevolentModMaker/x64dbgnewcipher.png" | relative_url }}){: .align-center}

En el `RAX` veremos el key.

¿Podemos usarlo directamente como decription key?, respuesta corta: No, pero sí que debe aplicarse un paso antes. Si se nos ocurre examinar el `bruh.exe` utilizando `strings`, podrás notar que espera un valor `Hex`

```js
no value specified for "Hex-encoded 32-byte decryption keyflag provided but not defined:
```

Así que sólo tenemos que transformar el string a Hexadecimal.

![UTMP]({{ "/images/MalevolentModMaker/Q10.png" | relative_url }}){: .align-center}


```BASH
Q8: 63 86 61 6e 67 65 12 74 68 69 55 16 70 61 01 73
```

###### Cabe aclarar que incluso, la respuesta puede verse justo antes del CALL dentro de las operaciones de la pila pero aún faltará pasarlo a hex

#### Q11: What is the name of the project in the encrypted .TXT file?

Para ello, sólo tendremos que ejecutar `bruh.exe` (_recomiendo mucho el hacer el propio script para desencriptar, qué sorpresa sería que un artefacto de un atacante no vuelva a infectar el equipo_) y tendremos el archivo (uno de los artefactos) en texto claro.

```
Q11: QA Hack'n Try
```

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.
