---
layout: single
title: "Proyecto CAI - Github"
author_profile: true
published: true
---

__CAI__ o _Cybersecurity IA_ es un proyecto muy interesante propietario de _aliasrobotics_, su [repositorio de Github](https://github.com/aliasrobotics/cai) está muy bien documentado y da muy buenas pautas a lo que son los agentes y cómo este proyecto los utiliza para poder hacer un framework de seguridad con IA bastante sólido. Invito a todos a darle un vistazo.

![UTMP]({{ "/images/CAI/GitHubTitle.png" | relative_url }}){: .align-center}

# Entendiendo CAI

_Cybersecurity AI (CAI) es un marco ligero y de código abierto que permite a los profesionales de la seguridad crear e implementar automatizaciones ofensivas y defensivas basadas en inteligencia artificial. CAI es el marco de facto para la seguridad basada en IA, ya utilizado por miles de usuarios individuales y cientos de organizaciones. Tanto si es investigador de seguridad, hacker ético, profesional de TI o una organización que busca mejorar su postura de seguridad, CAI le proporciona los componentes básicos para crear agentes de IA especializados que pueden ayudar en la mitigación, el descubrimiento de vulnerabilidades, la explotación y la evaluación de la seguridad._

Las principales características del modelo es que utiliza _litellm_ para poder conectarse a modelos de IA según plazca, tiene prompts perviamente formados para ahorrar tiempo, está testeado en competiciones CTF con __muy buenos resultados__ y principalmente, su __arquitectura basada en agentes__.

## Componentes Principales (General)

### Agentes

CAI internamente abstrae todo el comportamiento de ciberseguridad en `Agentes` y en `patrones` del propio agente. Un `agente`, bajo el mismo concepto de la documentación, el agente es _un sistema inteligente que interactúa con algún entorno_ y que de forma más técnica, es cualquier cosa que puede ser vista como un sistema percibiendo el entorno con censores, razonando sobre sus metas y actuando según ese entorno. Y esto CAI lo adapta como una implementación de Razonamiento y Acción.

### Herramientas

Esta es una parte muy buena de CAI, las herramientas permmiten a los agentes tomar acciones proporcionándoles interfaces para ejecutar comandos del sistema, esto incluyendo, realizar escaneos de seguridad, analizar vulenrabilidades e interactuar con los sistemas objetivos, algunas de estas herramientas incluyen la ejecución de comandos (puede llegar a ejecutar `ldapsearch` por ejemplo, o `dirb` si lo cree conveniente), búsquedas web (para realizar tareas de OSINT e incluzo es compatible con la API de `Shodan`), análisis y ejecución dinámica de scripts, SSHTunnels e incluso la implementación con web proxies (Esto como integración de _MCP_ o _Model Context Procol_, por lo que le puedes pedir que envíe cierta petición a `intruder` por ejemplo).

### Handoffs

Los `handoffs` tienen una función interesante que potencia mucho el framework, __permite a un `agente` delegar tareas a otro `agente`__ Esto permite una validación continua sobre toda la cadena de explotación o la tarea, puedes verlo como un agente que se especializa en buscar el flaw, otro agente se especializa en la verificación lo que permite una división de tareas o responsabilidades sobre varias tareas en ciberseguridad.

Existen más componentes y para ello, los invito a leer la documentación, pero en este post, quería hacer un pequeño overview para dar una idea de lo que puede llegar a lograrse con este framework.

## Instalación

Para implementar este proyecto localmente (en mi caso: en un entorno `Debian` (aunque también compatible con __`WSL`__, __`Ubuntu`__ e incluso __`Android`__)), se necesitan pocas cosas, la documentación no la siento muy completa (pues sigue en desarrollo) por sobre el proceso de instalación pero faltan unas cosillas para puntualizar: __python3.12__, __openai==1.99.9__, __litellm[proxy]__, __rich==14.0.1__ una __APIKEY__ (esto puede ser de cualquier modelo o plataforma (para ver los modelos soportados, puedes revisar los [proveedores de litellm](https://docs.litellm.ai/docs/providers)).

De igual manera, si falta algún componente, tendremos fallos que nos ayudaran a tener una pequeña traza.

### Instalación Python 3.12

En el caso en que estés trabajando en un entorno limpio, esto será necesario para tener la vesión actualizada de python3.12 que es donde trabaja el framework:

1. Descarga el tarball de [python3.12](https://www.python.org/downloads/release/python-3120/) según la versión Linux que tengas
2. Descomprime el tarball en tu directorio local `tar -xf <Archivo.tar.xz>` o `tar -xvzf <archivo.tgz>`
3. Ejecuta `./configure --enable-optimizations` (Llega a tardar varios minutos)
4. `sudo make altinstall`

### Montado y preparación del venv

Desde la documentación, se nos sugiere trabajar en un entorno virtual de python, esto ofrece varias ventajas (pero no me meteré mucho en ese tema) por lo que he de aclarar, que CAI sólo será accesible en este entorno.

1. Para crear el entorno ejecutamos `python3.12 -m cai_env`, lo que creará un directorio en el directorio actual con el mismo nombre.
2. Activamos el entorno con `source cai_env/bin/activate`
3. Instalamos `litellm proxy` que nos permitirá conectar nuestra aplicación con el modelo: `pip install 'litellm[proxy]'`
4. Debemos instalar `openai` en su versión más reciente para utilizar correctamente `litellm`, al momento de la escritura _1.99.9_: `pip install --upgrade openai==1.99.9`
5. Y ahora sí, instalamos CAI: `pip install cai-framework`
6. _Aquí es probable que de un aviso sobre las dependencias o incompatibilidades, Revisa el mensaje en rojo indicado en la salida_
7. Si lo indica, instalar `rich` a su versión más reciente: `pip install --upgrade rich`

_Nota: Deja la terminal abierta, la ocuparemos a continuación_

### Archivo .env

Luego de preparar el entorno, es importante que prepares un archivo `.env` que CAI leerá para utilizar sus valores, el formato es el siguiente

```json
OPENAI_API_KEY="<OPENAI KEY>"
SHODAN_API_KEY="<SHODAN KEY>"
ANTHROPIC_API_KEY="<ANTROPIC KEY>"
OLLAMA=""
PROMPT_TOOLKIT_NO_CPR=1
CAI_STREAM=false
```

Todo depende de qué modelo elijas, si no utilizas una plataforma, deja el espacio de las comillas vacío justo como la de `OLLAMA`; en cualquier caso, necesitas levantar tú mismo `litellm` para lograr que funcione el framework, si no, te arrojará problemas relacionados con algo de `error ... /key/generate` o algo parecido. 

![UTMP]({{ "/images/CAI/errorlitellm.jpeg" | relative_url }}){: .align-center}

Entonces:

1. En la misma terminal que tienes abierta si seguiste los pasos, ejecuta: `export OPENAI_API_KEY="<API-KEY>"` (El nombre de la variable cambia por plataforma, revisa [la documentación](https://docs.litellm.ai/docs/providers))
2. Ejecuta lo siguiente cambiando el nombre del modelo que quieras `litellm --model gpt-3.5-turbo` 
3. Un servicio DEBE levantarse en la `0.0.0.0:4000`.
4. En otra terminal, dirigirte al directorio donde está venv que habías creado anteriormente.
5. Inicia el entorno virtual en la terminal `source cai_env/bin/activate`
6. Inicia CAI: `cai`
7. __Lee el menú!__
8. Selecciona __el mismo modelo__ que seleccionaste en `litellm` con `/model gpt-3.5-turbo`
9. E inicializa un agent según la tarea (tal y como dice el menú) con: `/agent ...`

![UTMP]({{ "/images/CAI/agent.jpeg" | relative_url }}){: .align-center}

## Aclaraciones y conclusiones.

El framework es súmamente útil, y se potencia bastante según el modelo usado, openai es buena, pero en mi opinión no lo mejor para esto; eso sí, es interesante dar el intento para ver qué puede llegar a hacer, en mi experiencia, sólo vi cómo gpt-3.5-turbo empezó a enumerar directorios con rockyou.txt para llegar a esta conclusión xd.

Gracias a todo el equipo de _aliasrobotics_ Han creado una herramienta brutal y mejor aún, opensource para la democratización de la IA en ciberseguridad.

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!.
