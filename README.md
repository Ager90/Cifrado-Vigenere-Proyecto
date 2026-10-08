# Cifrado Vigenere Proyecto
Script de Python creado para un proyecto en Matemática Discreta sobre el cifrado Vigenère. No solo permite cifrar y descifrar mensajes, sino que incluye herramientas de criptoanálisis para romper el cifrado sin conocer la clave, utilizando estadística y fuerza bruta. Opción para ejecutarlo tanto con interfaz gráfico como desde la terminal.

---
## Qué hay en cada pestaña

* **Cifrar / Descifrar**: `cifrar_vigenere` / `descifrar_vigenere`. Suma (o resta) la clave letra a letra, módulo 26. Los números, espacios y saltos de línea se mantienen; los acentos se quitan y la Ñ pasa a N.
$$C_i \equiv (P_i + K_{i \bmod m}) \pmod{26} \qquad P_i \equiv (C_i - K_{i \bmod m}) \pmod{26}$$
<br>

* **Ataque estadístico**: `ataque_estadistico`. Divide el texto en columnas para cada longitud de clave posible y busca, columna a columna, el desplazamiento cuyo resultado más se parece a las frecuencias del idioma (test χ²). Cada longitud se analiza en un proceso distinto.
$$\chi^2 = \sum_{i=A}^{Z} \frac{(O_i - E_i)^2}{E_i}$$
<br>

* **Fuerza bruta**: `worker_fuerza_bruta`. Prueba todas las claves hasta la longitud elegida (de 1 a 10 letras) y se queda con las de menor χ². El trabajo se reparte entre los procesos en tareas de como mucho $26^4$ claves, con barra de progreso, tiempo restante estimado y botón para cancelar.
$$N = \sum_{l=1}^{L} 26^l$$
<br>

* **Benchmark**: `worker_benchmark`. Mide cuántas claves por segundo prueba tu ordenador con el mismo código que la fuerza bruta y estima cuánto tardaría para cada longitud de clave.
$$T(L) \approx \frac{26^L}{\rho}$$
<br>

Abajo se elige el **idioma** (español o inglés). Cambia a la vez los textos de la aplicación y la tabla de frecuencias con la que comparan los ataques. El cambio es inmediato y no se pierde lo escrito ni los resultados, que se vuelven a mostrar en el idioma nuevo. La elección se recuerda para la próxima vez; la primera vez se usa el idioma del sistema. Los resultados de los ataques incluyen el **histograma de frecuencias** del texto descifrado frente al idioma, como en la 1.0.

## Cómo ejecutarlo

### Opción A: el ejecutable (Windows)

Descarga `Pygenere.exe` de la sección [Releases](https://github.com/Ager90/Cifrado-Vigenere-Proyecto/releases/latest) y haz doble clic. No hace falta tener Python instalado.

### Opción B: desde el código

```bash
pip install -r requirements.txt
python pygenere.py
```

Para usar más o menos procesos en los ataques (por defecto, un cuarto de los núcleos):

```bash
python pygenere.py --procesos 8
```

> En Windows, `pythonw pygenere.py` abre la aplicación sin ventana de consola.

### Opción C: versión de terminal

`pygenere_cli.py` es el script de la 1.0, con el mismo menú de consola, pero con los fallos corregidos (ver abajo). No necesita instalar nada, solo Python 3:

```bash
python pygenere_cli.py
```

### Crear el ejecutable

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name Pygenere --icon pygenere.ico pygenere.py
```

El `.exe` aparece en la carpeta `dist/`.

## Novedades respecto a la 1.0

* Aplicación de escritorio en lugar del menú de consola.
* Interfaz en español y en inglés, que cambia según el idioma elegido.
* Frecuencias del inglés además de las del español.
* La fuerza bruta puntúa cada clave con los conteos por columna en vez de descifrar el texto entero: da el mismo χ², pero es mucho más rápida. Además usa un solo `Pool` para todo, en lugar de crear uno nuevo para cada longitud.
* Fuerza bruta hasta 10 letras, que se puede cancelar en cualquier momento.
* Las claves repetidas (`MATEMATE`) se agrupan con su periodo (`MATE`).

## Fallos de la 1.0 corregidos

Están corregidos tanto en la aplicación como en la versión de terminal (`pygenere_cli.py`).

* **El ataque estadístico solía elegir una clave demasiado larga.** Cuanto más larga es la clave, más se ajusta cada columna a las frecuencias, así que el menor χ² casi siempre era una clave de 15–20 letras sin sentido. Ahora se elige la clave más corta con un χ² cercano al mínimo. Con 60 claves aleatorias por caso:

  | Letras del texto | 1.0 (español) | 2.0 (español) | 1.0 (inglés) | 2.0 (inglés) |
  |---|---|---|---|---|
  | 150 | 8/60 | 52/60 | 0/59 | 53/59 |
  | 300 | 43/60 | 60/60 | 21/60 | 60/60 |

* **Letras fuera de A–Z rompían el ataque estadístico.** `normalizar_texto` dejaba pasar letras como `Ø`, `Æ` o las griegas, y el ataque fallaba con un `KeyError`. Ahora solo se conservan A–Z.
* **El benchmark medía otra cosa.** Medía `descifrar_vigenere` (letra a letra y con normalización Unicode), que es unas 4 veces más lento que el código real de la fuerza bruta, y además contaba el tiempo de arrancar los procesos. Las estimaciones salían bastante más pesimistas de lo real. Ahora mide el mismo código que usa la fuerza bruta, con el `Pool` ya arrancado.
* **Tiempos largos poco legibles.** `formatear_tiempo` nunca pasaba de horas (por ejemplo, "11601.50 horas"). Ahora llega a días y años.
