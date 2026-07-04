---
layout: single
title: "Introducción a Malware Development"
author_profile: true
published: true
toc: true
toc_sticky: true
comments: true
---

El desarrollo de malware (o Maldev) es un tema que personalmente me apasiona, "crear un sólo ejecutable para controlar el mundo entero" suena hasta loco o muy pomposo, pero directamente me encanta hasta como suena el potencial de este mundo y qué mejor, compartir esa pasión. Quizá para introducir a quienes estén interesados en este mundillo.

Claramente, todo esto es con fines éticos y no lo digo sólo para deslindarme de la responsabilidad de lo que hagan con lo que trato de bloggear, sino hacerlo con la mentalidad de que esto tiene un impacto real, y la industria paga muy bien por ello y contribuyes a que el mundo siga avanzando a mejor, y yo por lo menos, trabajo para eso, aunque aún sea mínimo el trabajo que yo haga.

## Maldev

Si llegaste hasta aquí, muy probablemente ya te han llenado de conceptos de lo que es el malware, troyanos, gusanos... un poco quemados en mi opinión porque hay tantísimas variantes que no alcanzan a nombrarlas todas, y más con la IA, pero a nivel de desarrollo de malware, las cosas no parecen que digas, "voy a hacer esta combinación para hacer un rat rabit clásico y llenar su memoria RAM de basura" y son más bien parecidas a como si hicieras un programa normal.

Que voy a hacer un programa que lea ese excel y genere un reporte en word con una plantilla para el reporte mensual... Tú estás programando algo, una solución para un __objetivo__, que en este caso sería un reporte, pero en maldev, claramente este objetivo no es hacer un reporte mensual, ¿no?, sería otra cosa y construyes a partir de ese objetivo. Entonces termina siendo un ciclo de desarrollo de software, como cualquier otro, aunque en mi opinión, más divertido.

## Conceptos básicos

Antes que nada, esta serie la desarrollaré en C++, es uno de los básicos que se recomiendan entender, en primera porque la mayoría de la documentación en Windows está en C++ (o C), lo que le permite hablar "Directamente" con el sistema operativo, lo segundo y un poco más importante, es que tienes control absoluto en bajo nivel, puedes manipular punteros, memoria, __tú controlas cada byte__: Peligroso pero emocionante (Eso sí, nunca se casen con un sólo lenguaje, aprendan las ventajas que pueden ofrecer otros lenguajes)

En esta entrada veremos sólo los conceptos básicos y entraremos en terreno poco a poco.

* Arquitectura de Windows
* Manejo de memoria
* Debuggers (con `x64dbg`)

### Arquitectura de Windows

Por mucho, este tema es el más importante; saber dónde nos estamos moviendo es esencial para cualquier operación, sea ofensiva (El saber qué y dónde atacas) o defensiva (El saber qué y dónde defender). 

Lo primero a saber, el sistema operativo windows, opera en 2 modos o niveles, cómo lo gusten ver: _User Mode_ (Ring 3, User Land) y _Kernel Mode_ (Ring 0).

__Todos los procesos de las aplicaciones se ejecutan en User Mode__, mientras que __Todos los componentes del sistema operativo se ejecutan en Kernel Mode__ pero, para que cualquier aplicación cumpla con una sola tarea, como crear un archivo, no puede sólo hacerlo y ya, el único que puede cumplir la tarea en sí, es el Kernel, entonces tiene que seguir cierto proceso o una serie de llamadas:

![UTMP]({{ "/images/Intro_Maldev_1/KernelSyscall.png" | relative_url }}){: .align-center}

Este es el flujo común en cómo una aplicación (User Land) interactúa con el hardware (el kernel). Para visualizarlo mejor, imaginemos que necesitamos crear un archivo:

1. La aplicación de Usuario solicita crear un archivo, para ello utiliza _CreateFile_.
2. _CreateFile_ la dispone la librería del sistema _Kernel32.dll_.
3. _Kernel32.dll_ llama a su equivalente de la función _CreateFile_ en _ntdll.dll_, el cual es _NtCreateFile_.
4. _NtCreateFile_ como mencionamos, la dispone _ntdll.dll_.
5. _ntdll.dll_ ejecuta una instrucción _syscall_ para transferir la ejecución al kernel.
6. La función del kernel _NtCreateFile_ llama a los drivers y los módulos necesarios para completar la tarea (Crear el archivo).

Una vez el flujo entendido, podemos empezar a tocar cosas más específicas, como por ejemplo, los procesos.

Un proceso por sí mismo, al contrario como nos lo hacen creer, son sólo contenedores de estructuras de datos, no hacen nada en sí... a menos, que tengan un __hilo__ (Thread) de ejecución, el cual es el verdadero responsable de ejecutar las instrucciones que estemos indicando.

Este _hilo_ (Una vez que nuestro codigo pase a código máquina), empieza a ejecutar instrucción por instrucción y __navegar en su espacio de memoria__, hablemos de esto más a fondo:

### Manejo de Memoria

Imaginemos que estamos en los años 90s, tenemos 8 MB de RAM y queremos abrir un programa que pesa 4 MB, otro 3MB y un tercero que pesa 2MB... Sin ciertos mecanismos, el sistema operativo no lo abriría o, colapsaría... Este mecanismo se llama __Memoria Virtual__.

La __Memoria virtual__ a grandes rasgos es una ilusión que hace el sistema operativo para hacerle creer a sus procesos, que tiene todo el espacio disponible para él sólo, y luego, tras bambalinas, el sistema operativo divide en bloques esta memoria virtual y la asigna a un bloque de su memoria física. Esto resuelve 3 problemas:

* Superar las limitaciones físicas: Esto permite que los programas usen más memoria de la que físicamente tenemos disponible.
* Aislamiento y seguridad: Si el proceso A pudiera ver la memoria real, podría por "accidente" leer o escribir en la memoria del proceso B y romperlo (O robarle datos).
* Optimización: No todo el código de un programa se ejecuta al mismo tiempo, ¿para qué tener en la RAM cargada una pantalla que sólo se abre cuando la solicitas?

Pero... ¿cómo se supone que lo hace? ¿No se llena la memoria de esa manera?

Cuando un programa se ejecuta, el sistema operativo empieza a manejar su memoria y la empieza a asignar por _Páginas_, algunas de estas _Páginas_ las asigna a la RAM (La memoria física, El almacenamiento primario, que es muy rápido), mientras que otras, las asigna en el disco (Almacenamiento secundario, mucho más lento que la RAM), entonces, así, lo que no estés ejecutando, visualizando o necesitando en el momento, lo guarda en el disco y empieza a crear su propia tabla: __La Page Table__ (que es un mapeo entre memoria virtual y memoria física).

![UTMP]({{ "/images/Intro_Maldev_1/VirtualMem.png" | relative_url }}){: .align-center}

La __MMU__ (Uno de los componentes de la CPU) se encarga de todo esto pero quédense con la idea de que es el SO hace creer al proceso que tiene el espacio que quiera PERO, por esto mismo, no puede leer el espacio de otros procesos como si nada.

Hagamos un ejercicio básico con el debugger:

### Debugger

Bien, haremos un programa sencillo para ver este manejo de memoria virtual entre cada proceso utilizando `x64dbg` explicaremos sólo las partes esenciales por ahora:

Primero, abrimos nuestra instancia de `Visual Studio` y creamos un proyecto `Console App ++`:

![UTMP]({{ "/images/Intro_Maldev_1/CreateProject.png" | relative_url }}){: .align-center}

Ya con el proyecto listo, puedes copiar el siguiente código:


```c++
#pragma comment(lib, "onecore.lib")

#include <iostream>
#include <windows.h>
#include <memoryapi.h>

int main()
{

    LPVOID lpAddr = NULL;
    SIZE_T dwSize = 1024 * 4;
    DWORD flProtect = 0x04; // PAGE_READWRITE NUNCA PAGE_EXECUTE_READWRITE
    LPVOID retAdd;
    LPCWSTR string2Mem = L"Allocated Here";

    retAdd = VirtualAlloc(lpAddr, dwSize, MEM_COMMIT | MEM_RESERVE, flProtect);

    if (retAdd != NULL)
    {
        std::wcout << TEXT("Memory Allocated at: ") << retAdd << std::endl;
    }
    else
    {
        std::wcout << TEXT("Error allocating memory: ") << GetLastError() << std::endl;
        return 1;
    }

    std::cin.get();

    RtlMoveMemory(retAdd, string2Mem, (wcslen(string2Mem) * sizeof(wchar_t)) + 2); // + 2 para copiar el Null Byte que indica el final de una cadena WSTR 

    std::wcout << TEXT("Memory Content: ") << (wchar_t*)retAdd << std::endl;

    std::cin.get();

    if (VirtualFree(retAdd, 0, MEM_RELEASE))
    {
        std::wcout << TEXT("RELEASED") << std::endl;
    }   
    else
    {
        std::wcout << TEXT("Error Releasing Memory: ") << GetLastError() << std::endl;

    }
    return 0;
}
```

Aquí van 3 funciones de API win32 (Digamos que son las funciones para utilizar las facilidades del sistema operativo):

* [`VirtualAlloc()`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc): Esta función se encarga de reservar, cambiar el estado de una región de memoria de el proceso actual.
* [`RtlMoveMemory()`](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory): Esta función se encarga de copiar un bloque de datos en una región o dirección de memoria.
* [`VirtualFree()`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree): Libera un bloque o región de memoria en el proceso actual.

El `VirtualFree` es __importantísimo__, ya que como dijimos, tú eres administrador de cada byte... y si no lo limpiamos, es información que se queda en memoria como basura, pero extraíble por un defensor.

Entonces, el flujo es el siguiente:

1. Asigna un espacio de memoria dentro de nuestro propio proceso (Del espacio mínimo de 4KB) y lo muestra en consola
2. Copia el string "Allocated Here" en la dirección asignada
3. Libera la región reservada

Hablaremos de los detalles de las funciones más tarde (ya que estemos manejando permisos), por ahora, compilemos el programa y abramos el `x64dbg`.

![UTMP]({{ "/images/Intro_Maldev_1/x64dbg.png" | relative_url }}){: .align-center}

Demos clic en `File` > `Open`

![UTMP]({{ "/images/Intro_Maldev_1/open.png" | relative_url }}){: .align-center}

Y busca tu archivo para preparar la ejecución. Una vez cargado, podemos iniciar con el botón RUN: 

![UTMP]({{ "/images/Intro_Maldev_1/charge.png" | relative_url }}){: .align-center}

Observarás que en en un lado aparecerá la consola, recomiendo que la acomodes a un costado para ver la acción del código:

![UTMP]({{ "/images/Intro_Maldev_1/running.png" | relative_url }}){: .align-center}

Cuando estés listo, da clic otra vez con RUN; y verás que en consola, nos mostrará la dirección reservada para nuestro string (_La dirección de la memoria virtual_), copiamos esa dirección, damos clic izquierdo en el panel inferior izquierdo (_Dump_) y utilizamos `Ctrl + G` para abrir el menú de _Go to_ y pegar la dirección.

![UTMP]({{ "/images/Intro_Maldev_1/allocated.png" | relative_url }}){: .align-center}

Si lo ejecutas varias veces, notarás que el flujo inicia en una dirección alta (00007FF9A9B41000) pero nuestra dirección asignada es mucho más baja (000001E2C1BD0000) así empiezas a ver las diferencias entre la memoria entre nuestro espacio asignado y el espacio de ejecución que tampoco es el mismo.

Pero bueno, verás que no hay nada en esa dirección... pero si presionamos enter en la consola... veremos nuestro string:

![UTMP]({{ "/images/Intro_Maldev_1/string.png" | relative_url }}){: .align-center}

Y si damos otra vez Enter, veremos que se limpiará la dirección asignada:

![UTMP]({{ "/images/Intro_Maldev_1/cleared.png" | relative_url }}){: .align-center}

Con esto podemos entender el manejo de memoria en un nivel básico pero suficiente como para empezar a manejar más cosillas.

###### Agradecimiento

Si lees esto, gracias por llegar hasta aquí!, si existen dudas, comentarios y correcciones (que son más que bienvenidas) contáctame con confianza, que siempre he dicho que la ciberseguridad es esfuerzo conjunto. 

_En caso que no los vea, buenos días, buenas tardes y buenas noches. Happy Hacking!._

