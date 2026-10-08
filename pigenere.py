"""
Pygenère 2.0 — cifrado Vigenère con interfaz gráfica.

Cifra, descifra y rompe el cifrado sin conocer la clave (ataque estadístico χ²,
fuerza bruta y benchmark). Los ataques usan multiprocessing, como en la 1.0, y la
interfaz es una ventana de escritorio hecha con PySide6 (Qt).

El idioma elegido abajo en la ventana (español o inglés) cambia a la vez los textos
del programa y la tabla de frecuencias con la que comparan los ataques.

Uso:
    pip install pyside6
    python pygenere.py                 abre la aplicación
    python pygenere.py --procesos 4    número de procesos para los ataques
"""
import argparse
import itertools
import multiprocessing
import re
import sys
import threading
import time
import unicodedata

try:
    from PySide6.QtCore import QLocale, QObject, QPointF, QRectF, QSettings, Qt, QTimer, Signal
    from PySide6.QtGui import (
        QColor, QFont, QFontDatabase, QIcon, QLinearGradient, QPainter, QPainterPath, QPalette, QPen, QPixmap,
        QTextOption,
    )
    from PySide6.QtWidgets import (
        QApplication, QButtonGroup, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
        QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSizePolicy, QSpinBox, QToolButton, QToolTip,
        QVBoxLayout, QWidget,
    )
except ImportError:
    sys.exit("Pygenère 2.0 necesita PySide6. Instálalo con:  pip install pyside6")


# CONSTANTES Y CONFIGURACIÓN

VERSION = "2.0"

NUM_PROCESOS = max(1, multiprocessing.cpu_count() // 4)  # Un cuarto de los núcleos (redondeado abajo), mínimo 1
# Se puede cambiar con --procesos N

# Alfabeto estándar de 26 caracteres (sin la Ñ, que se normaliza a N)
ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CLAVE_EJEMPLO = "MATE"
TOP_K = 5  # cuántas claves se muestran en los rankings

# Datos de cada idioma: frecuencias de letras (%) de A a Z y el texto de ejemplo.
# La tabla del español es la misma que en Pygenère 1.0
IDIOMAS = {
    "es": {
        "frecuencias": [
            12.53, 1.42, 4.68, 5.86, 13.68, 0.69, 1.01, 0.70, 6.25, 0.44, 0.02, 4.97, 3.15,
            6.71, 8.68, 2.51, 0.88, 6.87, 7.98, 4.63, 3.93, 0.90, 0.01, 0.22, 0.90, 0.52,
        ],
        "ejemplo": (
            "En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha mucho tiempo que vivía "
            "un hidalgo de los de lanza en astillero, adarga antigua, rocín flaco y galgo corredor. Una olla "
            "de algo más vaca que carnero, salpicón las más noches, duelos y quebrantos los sábados, lentejas "
            "los viernes, algún palomino de añadidura los domingos, consumían las tres partes de su hacienda."
        ),
    },
    "en": {
        "frecuencias": [
            8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
            6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
        ],
        "ejemplo": (
            "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of "
            "foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, "
            "it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had "
            "everything before us, we had nothing before us, we were all going direct to Heaven."
        ),
    },
}

ASCII_ART = r"""
  ____                          __               ____    ___
 |  _ \ _   _  __ _  ___ _ __   \_\ _ __ ___    |___ \  / _ \
 | |_) | | | |/ _` |/ _ \ '_ \ / _ \ '__/ _ \     __) || | | |
 |  __/| |_| | (_| |  __/ | | |  __/ | |  __/    / __/ | |_| |
 |_|    \__, |\__, |\___|_| |_|\___|_|  \___|   |_____(_)___/
        |___/ |___/

               -06ɹǝƃ∀@ ʎB-
"""


# TRADUCCIONES
# Todos los textos de la interfaz, por idioma. Los {campos} se rellenan con t(clave, campo=valor).

TEXTOS = {
    "es": {
        # Nombres de los idiomas (histograma y leyenda)
        "idioma_es": "español",
        "idioma_en": "inglés",

        # Pestañas
        "pestana_cifrar": "Cifrar / Descifrar",
        "pestana_estadistico": "Ataque estadístico",
        "pestana_bruta": "Fuerza bruta",
        "pestana_benchmark": "Benchmark",

        # Comunes
        "texto_cifrado": "Texto cifrado",
        "max_longitud": "Longitud máx. de clave",
        "cargar_ejemplo": "Cargar ejemplo",
        "frecuencias": "Frecuencias de letras",
        "texto_descifrado": "Texto descifrado",
        "col_clave": "Clave",
        "col_longitud": "Longitud",
        "meta_clave": "longitud {longitud} · χ² {chi:.1f}",
        "proceso": "proceso",
        "procesos": "procesos",

        # Cifrar / descifrar
        "texto": "Texto",
        "texto_placeholder": "Escribe un mensaje…",
        "clave": "Clave",
        "clave_placeholder": "p. ej. MATE",
        "cifrar": "Cifrar",
        "descifrar": "Descifrar",
        "copiar": "Copiar",
        "copiado": "¡Copiado!",
        "romper": "Intentar romperlo →",
        "nota_cifrar": (
            "Se cifran las letras A–Z; los números y los espacios se quedan igual. Se quitan los acentos, "
            "la Ñ pasa a N y el resto de símbolos se eliminan."
        ),

        # Ataque estadístico
        "nota_estadistico": (
            "Divide el texto cifrado en columnas para cada longitud de clave y compara cada columna con las "
            "frecuencias de letras del idioma elegido abajo (χ²). Funciona mejor con unos cientos de letras."
        ),
        "lanzar_ataque": "Lanzar ataque",
        "clave_probable": "Clave más probable",
        "hecho_en": (
            "Hecho en {tiempo}. Como en la 1.0, el ranking indica plausibilidad estadística, "
            "no una clave correcta garantizada."
        ),

        # Fuerza bruta
        "nota_bruta": (
            "Prueba todas las claves posibles hasta la longitud elegida (26ᴸ combinaciones) y las ordena por χ². "
            "Cada letra más multiplica el trabajo por 26. El trabajo se reparte entre varios procesos de Python."
        ),
        "aviso_5": "lento", "aviso_6": "minutos", "aviso_7": "horas",
        "aviso_8": "un día", "aviso_9": "semanas", "aviso_10": "años",
        "empezar": "Empezar",
        "cancelar": "Cancelar",
        "empezando": "Empezando…",
        "progreso": "{probadas} / {total} claves · {velocidad} claves/s · {tiempo}{restante}",
        "restante": " · quedan ~{tiempo}",
        "cancelado_tras": "Cancelado tras probar {probadas} de {total} claves en {tiempo}.",
        "probadas": "Probadas {probadas} de {total} claves en {tiempo}.",
        "mejor_hasta_ahora": "Mejor clave hasta ahora",
        "mejor_clave": "Mejor clave",

        # Benchmark
        "nota_benchmark": (
            "Mide cuántas claves por segundo puede probar Python con todos sus procesos y estima cuánto tardaría "
            "un ataque de fuerza bruta para cada longitud de clave."
        ),
        "ejecutar_benchmark": "Ejecutar benchmark",
        "midiendo": "Midiendo durante un segundo…",
        "tu_ordenador": "Tu ordenador",
        "meta_benchmark": "claves por segundo · {n} {procesos} de Python · texto de {letras} letras",
        "col_longitud_clave": "Longitud de clave",
        "col_combinaciones": "Combinaciones",
        "col_tiempo": "Tiempo estimado",

        # Pie
        "idioma": "Idioma",
        "info_motor": "Python {python} · {n} {procesos} · {nucleos} núcleos",
        "nota_idioma": (
            "El idioma cambia los textos del programa y la tabla de frecuencias que usan los ataques, así que "
            "funcionan mejor con textos en español. Con textos en inglés u otros idiomas pueden dar una clave "
            "incorrecta. Cifrar y descifrar funciona con cualquier idioma."
        ),

        # Unidades de tiempo
        "dias": "días",
        "anos": "años",

        # Errores de entrada (ErrorEntrada)
        "error_sin_texto": "Escribe algún texto primero.",
        "error_clave_vacia": "La clave necesita al menos una letra.",
        "error_min_estadistico": "Pega al menos 20 letras de texto cifrado (con unos cientos funciona mejor).",
        "error_min_bruta": "Pega al menos 10 letras de texto cifrado.",
        "error_bruta_en_curso": "Ya hay un ataque de fuerza bruta en marcha.",
        "error_espera_benchmark": "Espera a que termine el benchmark.",
        "error_espera_bruta": "Espera a que termine el ataque de fuerza bruta.",
        "error_benchmark_en_curso": "El benchmark ya está en marcha.",
    },
    "en": {
        "idioma_es": "Spanish",
        "idioma_en": "English",

        "pestana_cifrar": "Encrypt / Decrypt",
        "pestana_estadistico": "Statistical attack",
        "pestana_bruta": "Brute force",
        "pestana_benchmark": "Benchmark",

        "texto_cifrado": "Ciphertext",
        "max_longitud": "Max key length",
        "cargar_ejemplo": "Load example",
        "frecuencias": "Letter frequencies",
        "texto_descifrado": "Decrypted text",
        "col_clave": "Key",
        "col_longitud": "Length",
        "meta_clave": "length {longitud} · χ² {chi:.1f}",
        "proceso": "process",
        "procesos": "processes",

        "texto": "Text",
        "texto_placeholder": "Write a message…",
        "clave": "Key",
        "clave_placeholder": "e.g. MATE",
        "cifrar": "Encrypt",
        "descifrar": "Decrypt",
        "copiar": "Copy",
        "copiado": "Copied!",
        "romper": "Try to crack it →",
        "nota_cifrar": (
            "Letters A–Z are encrypted; numbers and spaces are kept as they are. Accents are removed, "
            "Ñ becomes N, and other symbols are dropped."
        ),

        "nota_estadistico": (
            "Splits the ciphertext into columns for every key length and compares each column with the letter "
            "frequencies of the language chosen below (χ²). Works best with a few hundred letters."
        ),
        "lanzar_ataque": "Run attack",
        "clave_probable": "Most likely key",
        "hecho_en": (
            "Done in {tiempo}. Like in 1.0, the ranking shows statistical plausibility, "
            "not a guaranteed correct key."
        ),

        "nota_bruta": (
            "Tries every possible key up to the chosen length (26ᴸ combinations) and ranks them with χ². "
            "Each extra letter multiplies the work by 26. The work is split across Python processes."
        ),
        "aviso_5": "slow", "aviso_6": "minutes", "aviso_7": "hours",
        "aviso_8": "a day", "aviso_9": "weeks", "aviso_10": "years",
        "empezar": "Start",
        "cancelar": "Cancel",
        "empezando": "Starting…",
        "progreso": "{probadas} / {total} keys · {velocidad} keys/s · {tiempo}{restante}",
        "restante": " · ~{tiempo} left",
        "cancelado_tras": "Cancelled after {probadas} of {total} keys in {tiempo}.",
        "probadas": "Tested {probadas} of {total} keys in {tiempo}.",
        "mejor_hasta_ahora": "Best key so far",
        "mejor_clave": "Best key",

        "nota_benchmark": (
            "Measures how many keys per second Python can test with all its worker processes, then estimates how "
            "long a brute force attack would take for each key length."
        ),
        "ejecutar_benchmark": "Run benchmark",
        "midiendo": "Measuring for about a second…",
        "tu_ordenador": "Your computer",
        "meta_benchmark": "keys per second · {n} Python {procesos} · {letras}-letter text",
        "col_longitud_clave": "Key length",
        "col_combinaciones": "Combinations",
        "col_tiempo": "Estimated time",

        "idioma": "Language",
        "info_motor": "Python {python} · {n} {procesos} · {nucleos} cores",
        "nota_idioma": (
            "The language changes the program's text and the letter frequencies the attacks compare against, so "
            "they work best on English text. Spanish or other languages may give the wrong key. Encrypting and "
            "decrypting work with any language."
        ),

        "dias": "days",
        "anos": "years",

        "error_sin_texto": "Write some text first.",
        "error_clave_vacia": "The key needs at least one letter.",
        "error_min_estadistico": "Paste at least 20 letters of ciphertext (a few hundred work best).",
        "error_min_bruta": "Paste at least 10 letters of ciphertext.",
        "error_bruta_en_curso": "A brute force attack is already running.",
        "error_espera_benchmark": "Wait for the benchmark to finish.",
        "error_espera_bruta": "Wait for the brute force attack to finish.",
        "error_benchmark_en_curso": "The benchmark is already running.",
    },
}

_idioma = "es"  # idioma actual de la interfaz; lo cambia fijar_idioma()

def fijar_idioma(codigo: str):
    global _idioma
    _idioma = codigo

def t(clave: str, **campos) -> str:
    """Texto de la interfaz en el idioma actual, con los {campos} ya rellenados."""
    texto = TEXTOS[_idioma][clave]
    return texto.format(**campos) if campos else texto

def idioma_del_sistema() -> str:
    """Idioma inicial si el usuario aún no ha elegido ninguno: español si el sistema lo está, si no inglés."""
    return "es" if QLocale.system().language() == QLocale.Spanish else "en"


# UTILIDADES

def _sin_acentos(texto: str) -> str:
    """Separa cada letra de su tilde (NFD) y descarta las tildes: 'Á' -> 'A', 'Ñ' -> 'N'."""
    return "".join(c for c in unicodedata.normalize("NFD", texto) if unicodedata.category(c) != "Mn")

def normalizar_texto(texto: str) -> str:
    """Quita acentos (Ñ -> N), pasa a mayúsculas y deja solo A-Z."""
    return re.sub(r"[^A-Z]", "", _sin_acentos(texto).upper())

def preparar_texto(texto: str) -> str:
    """La misma normalización, pero conservando números, espacios y saltos de línea."""
    texto = re.sub(r"[^\S\n]+", " ", _sin_acentos(texto).upper())
    return re.sub(r"[^A-Z0-9 \n]", "", texto)

def a_codigos(texto: str) -> list:
    """Texto -> lista de números 0-25 (A=0 ... Z=25), solo con las letras."""
    return [ord(c) - 65 for c in normalizar_texto(texto)]

def de_codigos(codigos) -> str:
    """Lista de números 0-25 -> texto en mayúsculas."""
    return "".join(ALFABETO[c] for c in codigos)

def periodo_minimo(clave: str) -> str:
    """'MATEMATE' -> 'MATE', para que una clave repetida solo salga una vez."""
    for periodo in range(1, len(clave)):
        if len(clave) % periodo == 0 and clave[:periodo] * (len(clave) // periodo) == clave:
            return clave[:periodo]
    return clave

def _con_separadores(numero: float, decimales: int = 0) -> str:
    """Número con separador de miles: 1,234.5 en inglés y 1.234,5 en español."""
    texto = f"{numero:,.{decimales}f}"
    return texto.translate(str.maketrans(",.", ".,")) if _idioma == "es" else texto

def formatear_tiempo(segundos: float) -> str:
    """Duración legible, desde milisegundos hasta años."""
    if segundos < 1: return f"{max(1, round(segundos * 1000))} ms"
    if segundos < 60: return f"{_con_separadores(segundos, 1)} s"
    if segundos < 3600: return f"{_con_separadores(segundos / 60, 1)} min"
    if segundos < 86400: return f"{_con_separadores(segundos / 3600, 1)} h"
    if segundos < 31557600: return f"{_con_separadores(segundos / 86400, 1)} {t('dias')}"
    return f"{_con_separadores(segundos / 31557600)} {t('anos')}"

def formatear_numero(numero: float) -> str:
    return _con_separadores(numero)


# CIFRADO

def vigenere_texto(texto: str, clave: str, direccion: int) -> str:
    """direccion = 1 cifra, -1 descifra. Solo cambian las letras y la clave avanza
    únicamente con ellas, así los ataques (que solo miran letras) cuadran."""
    desplazamientos = [direccion * c for c in a_codigos(clave)]
    if not desplazamientos:
        raise ValueError("La clave necesita al menos una letra.")
    posicion = itertools.count()

    def sustituir(letra):
        # Cifrado: (P + K) % 26 · Descifrado: (C - K) % 26
        d = desplazamientos[next(posicion) % len(desplazamientos)]
        return ALFABETO[(ord(letra.group()) - 65 + d) % 26]

    return re.sub("[A-Z]", sustituir, preparar_texto(texto))

def cifrar_vigenere(texto: str, clave: str) -> str:
    return vigenere_texto(texto, clave, 1)

def descifrar_vigenere(texto: str, clave: str) -> str:
    return vigenere_texto(texto, clave, -1)

def texto_ejemplo(idioma: str) -> str:
    """Texto de ejemplo del idioma cifrado con CLAVE_EJEMPLO, para probar los ataques."""
    return cifrar_vigenere(IDIOMAS[idioma]["ejemplo"], CLAVE_EJEMPLO)


# ESTADÍSTICA

def esperados(total: int, idioma: str) -> list:
    """Cuántas veces debería salir cada letra en un texto de `total` letras del idioma."""
    return [total * f / 100 for f in IDIOMAS[idioma]["frecuencias"]]

def chi_cuadrado(conteos, esperado) -> float:
    """χ² = Σ (O - E)² / E. Cuanto más bajo, más se parece el texto al idioma."""
    return sum((o - e) ** 2 / e for o, e in zip(conteos, esperado))

def conteos_columnas(codigos, longitud: int) -> list:
    """Reparte el texto en `longitud` columnas (la letra i va a la columna i % longitud)
    y cuenta cuántas veces sale cada letra en cada columna. Cada columna está cifrada
    con una sola letra de la clave, es decir, es un cifrado César."""
    columnas = [[0] * 26 for _ in range(longitud)]
    for i, c in enumerate(codigos):
        columnas[i % longitud][c] += 1
    return columnas

def rotar(conteos, desplazamiento: int) -> list:
    """Conteos de la columna descifrada con esa letra de clave:
    la letra i del texto plano viene de la letra i + desplazamiento del cifrado."""
    return conteos[desplazamiento:] + conteos[:desplazamiento]

def indice_coincidencia(conteos) -> float:
    """Probabilidad de que dos letras al azar de la columna sean iguales
    (≈0,07 en español o inglés, ≈0,038 en un texto aleatorio)."""
    total = sum(conteos)
    if total < 2:
        return 0.0
    return sum(n * (n - 1) for n in conteos) / (total * (total - 1))

def histograma(texto: str, idioma: str) -> list:
    """Frecuencia real de cada letra frente a la teórica del idioma (lo que dibujaba dibujar_histograma)."""
    letras = normalizar_texto(texto)
    total = len(letras) or 1
    return [
        (letra, letras.count(letra) * 100 / total, teorico)
        for letra, teorico in zip(ALFABETO, IDIOMAS[idioma]["frecuencias"])
    ]


# ATAQUE ESTADÍSTICO

def worker_ataque_estadistico(args):
    """Mejor clave para una longitud concreta: en cada columna elige el desplazamiento
    con menor χ². Se ejecuta en un proceso del Pool (una longitud por tarea)."""
    # El ranking no garantiza corrección, solo plausibilidad estadística
    longitud, codigos, idioma = args
    columnas = conteos_columnas(codigos, longitud)
    ajustes = []
    for columna in columnas:
        esperado = esperados(sum(columna), idioma)
        # Probamos los 26 desplazamientos posibles de cada columna (descifrado César)
        ajustes.append(min((chi_cuadrado(rotar(columna, d), esperado), d) for d in range(26)))
    return {
        "clave": de_codigos(d for _, d in ajustes),
        "chi": sum(chi for chi, _ in ajustes) / longitud,
        "ioc": sum(indice_coincidencia(c) for c in columnas) / longitud,
    }

def ataque_estadistico(codigos, max_longitud: int, idioma: str, pool=None):
    """Prueba todas las longitudes de 1 a max_longitud y devuelve (mejor, ranking)."""
    limite = min(max_longitud, len(codigos) // 2)  # con menos de 2 letras por columna no hay estadística
    tareas = [(longitud, codigos, idioma) for longitud in range(1, limite + 1)]
    resultados = pool.map(worker_ataque_estadistico, tareas) if pool else list(map(worker_ataque_estadistico, tareas))

    # Ordena por χ² y quita las claves repetidas (MATEMATE es la misma que MATE)
    ranking, vistas = [], set()
    for resultado in sorted(resultados, key=lambda r: r["chi"]):
        resultado["clave"] = periodo_minimo(resultado["clave"])
        if resultado["clave"] not in vistas:
            vistas.add(resultado["clave"])
            ranking.append(resultado)

    # Las claves largas se sobreajustan y pueden puntuar algo mejor que la real,
    # así que la mejor apuesta es la clave más corta con un χ² cercano al mínimo
    cercanas = [r for r in ranking if r["chi"] <= ranking[0]["chi"] * 1.5]
    mejor = min(cercanas, key=lambda r: len(r["clave"]))
    return mejor, ranking[:TOP_K]


# FUERZA BRUTA

_cancelar = None  # multiprocessing.Event compartido, lo pone iniciar_worker en cada proceso

def iniciar_worker(evento):
    """Inicializador del Pool: guarda en cada proceso el evento para cancelar."""
    global _cancelar
    _cancelar = evento

MAX_LONGITUD_BRUTA = 10
CLAVES_POR_TAREA = 4  # cada tarea prueba como mucho 26^4 claves, así el progreso avanza y cancelar responde

def prefijos(longitud: int):
    """Reparte el trabajo de una longitud en tareas: una por cada prefijo de la clave.
    Es un generador porque con claves largas hay millones de prefijos."""
    letras_prefijo = max(min(2, longitud - 1), longitud - CLAVES_POR_TAREA)
    return itertools.product(range(26), repeat=letras_prefijo)

def claves_totales(max_longitud: int) -> int:
    """N = Σ 26^l para l = 1..max_longitud."""
    return sum(26 ** longitud for longitud in range(1, max_longitud + 1))

def anotar(top: list, chi: float, clave: str):
    """Mete (chi, clave) en el top si entra. MATEMATE y MATE cuentan como la misma clave."""
    if len(top) == TOP_K and chi >= top[-1][0]:
        return
    clave = periodo_minimo(clave)
    for i, (chi_previo, previa) in enumerate(top):
        if previa == clave:
            if chi_previo <= chi:
                return
            del top[i]
            break
    top.append((chi, clave))
    top.sort()
    del top[TOP_K:]

def worker_fuerza_bruta(args):
    """Prueba todas las claves de `longitud` que empiezan por `prefijo`.
    Puntúa con χ² sobre los conteos por columna: da el mismo resultado que
    descifrar el texto entero, pero sin recorrer cada letra con cada clave."""
    prefijo, longitud, columnas, esperado = args
    # Precalcula, para cada columna, sus conteos descifrados con cada una de las 26 letras
    rotaciones = [[rotar(columna, d) for d in range(26)] for columna in columnas]
    inversos = [1 / e for e in esperado]

    # Conteos acumulados de las columnas fijadas por el prefijo
    base = [0] * 26
    for columna, d in enumerate(prefijo):
        base = [a + b for a, b in zip(base, rotaciones[columna][d])]
    ultima = rotaciones[longitud - 1]

    top, probadas = [], 0
    # Recorre las letras del medio; la última se prueba en el bucle interior, que es el más rápido
    for n, medio in enumerate(itertools.product(range(26), repeat=longitud - 1 - len(prefijo))):
        if n % 64 == 0 and _cancelar is not None and _cancelar.is_set():
            break
        parcial = base
        for j, d in enumerate(medio):
            parcial = [a + b for a, b in zip(parcial, rotaciones[len(prefijo) + j][d])]
        diferencia = [p - e for p, e in zip(parcial, esperado)]

        for d in range(26):
            chi = 0.0
            for a, q, inv in zip(diferencia, ultima[d], inversos):
                x = a + q
                chi += x * x * inv
            if len(top) < TOP_K or chi < top[-1][0]:
                anotar(top, chi, de_codigos(prefijo + medio + (d,)))
        probadas += 26
    return probadas, top


# BENCHMARK

def worker_benchmark(args):
    """Puntúa claves de 4 letras durante `segundos` con el mismo código que la fuerza bruta."""
    columnas, esperado, segundos = args
    fin = time.perf_counter() + segundos
    probadas = 0
    for prefijo in itertools.cycle(prefijos(4)):
        probadas += worker_fuerza_bruta((prefijo, 4, columnas, esperado))[0]
        if time.perf_counter() >= fin:
            return probadas


# MOTOR (multiprocessing, sin nada de interfaz)

class ErrorEntrada(ValueError):
    """Error causado por lo que ha escrito el usuario. Lleva la clave del mensaje en TEXTOS
    para que la interfaz lo muestre en el idioma elegido."""

    def __init__(self, clave: str):
        super().__init__(clave)
        self.clave = clave

def mensaje_error(error: Exception) -> str:
    """Texto que se enseña al usuario para un error."""
    return t(error.clave) if isinstance(error, ErrorEntrada) else str(error)


class Motor:
    """Guarda el Pool de procesos y hace todo el trabajo pesado. La interfaz solo lo llama."""

    def __init__(self, procesos: int):
        self.procesos = procesos
        self.cancelar = multiprocessing.Event()
        self.pool = multiprocessing.Pool(procesos, initializer=iniciar_worker, initargs=(self.cancelar,))
        self.cerrojo = threading.Lock()            # protege self.bruta (lo leen la interfaz y el hilo de trabajo)
        self.cerrojo_benchmark = threading.Lock()  # solo un benchmark a la vez
        self.bruta = None                          # estado de la última fuerza bruta

    def cerrar(self):
        self.cancelar.set()
        self.pool.terminate()

    def bruta_activa(self):
        return self.bruta is not None and self.bruta["activo"]

    @staticmethod
    def detalle(texto, clave, idioma):
        """Vista previa e histograma del texto descifrado con la mejor clave."""
        plano = descifrar_vigenere(texto, clave)
        return {
            "vista_previa": plano if len(plano) <= 280 else plano[:280] + "…",
            "histograma": histograma(plano, idioma),
            "idioma": idioma,
        }

    # Opción 1 y 2: cifrar / descifrar
    def cifrar(self, texto, clave, direccion):
        if not preparar_texto(texto).strip():
            raise ErrorEntrada("error_sin_texto")
        if not a_codigos(clave):
            raise ErrorEntrada("error_clave_vacia")
        return vigenere_texto(texto, clave, direccion)

    # Opción 3: ataque estadístico
    def estadistico(self, texto, max_longitud, idioma):
        codigos = a_codigos(texto)
        if len(codigos) < 20:
            raise ErrorEntrada("error_min_estadistico")
        # Si la fuerza bruta tiene ocupado el Pool, se calcula aquí mismo (son milisegundos)
        pool = None if self.bruta_activa() else self.pool
        inicio = time.perf_counter()
        mejor, ranking = ataque_estadistico(codigos, max_longitud, idioma, pool)
        return {
            "mejor": mejor,
            "detalle": self.detalle(texto, mejor["clave"], idioma),
            "ranking": ranking,
            "segundos": time.perf_counter() - inicio,
        }

    # Opción 4: fuerza bruta (en un hilo; la interfaz consulta el progreso)
    def iniciar_fuerza_bruta(self, texto, max_longitud, idioma):
        codigos = a_codigos(texto)
        if len(codigos) < 10:
            raise ErrorEntrada("error_min_bruta")
        with self.cerrojo:
            if self.bruta_activa():
                raise ErrorEntrada("error_bruta_en_curso")
            if self.cerrojo_benchmark.locked():
                raise ErrorEntrada("error_espera_benchmark")
            self.cancelar.clear()
            self.bruta = {
                "activo": True, "probadas": 0, "total": claves_totales(max_longitud),
                "inicio": time.perf_counter(), "segundos": 0.0, "top": [],
                "texto": texto, "idioma": idioma, "error": None,
            }
        threading.Thread(target=self._fuerza_bruta, args=(self.bruta, codigos, max_longitud), daemon=True).start()

    def _fuerza_bruta(self, trabajo, codigos, max_longitud):
        """Hilo que reparte las tareas entre el Pool y va juntando el progreso y el top."""
        esperado = esperados(len(codigos), trabajo["idioma"])
        try:
            for longitud in range(1, max_longitud + 1):
                columnas = conteos_columnas(codigos, longitud)
                pendientes = prefijos(longitud)
                # Se envían por lotes: con claves largas no caben todas las tareas en memoria
                while not self.cancelar.is_set():
                    lote = [(p, longitud, columnas, esperado) for p in itertools.islice(pendientes, 64 * self.procesos)]
                    if not lote:
                        break
                    for probadas, top in self.pool.imap_unordered(worker_fuerza_bruta, lote):
                        with self.cerrojo:
                            trabajo["probadas"] += probadas
                            for chi, clave in top:
                                anotar(trabajo["top"], chi, clave)
                if self.cancelar.is_set():
                    break
        except Exception as error:
            trabajo["error"] = str(error)
        finally:
            with self.cerrojo:
                trabajo["segundos"] = time.perf_counter() - trabajo["inicio"]
                trabajo["activo"] = False

    def cancelar_fuerza_bruta(self):
        self.cancelar.set()

    def estado_fuerza_bruta(self):
        """Copia del estado actual para la interfaz (se llama cada 200 ms)."""
        with self.cerrojo:
            trabajo = self.bruta
            estado = {
                "activo": trabajo["activo"],
                "probadas": trabajo["probadas"],
                "total": trabajo["total"],
                "segundos": time.perf_counter() - trabajo["inicio"] if trabajo["activo"] else trabajo["segundos"],
                "cancelado": trabajo["probadas"] < trabajo["total"],
                "error": trabajo["error"],
                "top": list(trabajo["top"]),
            }
        if not estado["activo"] and estado["top"]:
            estado["detalle"] = self.detalle(trabajo["texto"], estado["top"][0][1], trabajo["idioma"])
        return estado

    # Opción 5: benchmark
    def benchmark(self, idioma):
        if self.bruta_activa():
            raise ErrorEntrada("error_espera_bruta")
        if not self.cerrojo_benchmark.acquire(blocking=False):
            raise ErrorEntrada("error_benchmark_en_curso")
        try:
            self.cancelar.clear()  # puede seguir activo si se canceló la última fuerza bruta
            codigos = a_codigos(texto_ejemplo(idioma))
            tarea = (conteos_columnas(codigos, 4), esperados(len(codigos), idioma), 1.0)
            inicio = time.perf_counter()
            probadas = sum(self.pool.map(worker_benchmark, [tarea] * self.procesos))
            velocidad = probadas / (time.perf_counter() - inicio)
        finally:
            self.cerrojo_benchmark.release()
        return {"velocidad": velocidad, "letras": len(codigos)}


# INTERFAZ: ESTILO

ACENTO = "#5b6ee1"
TEXTO = "#1c1c22"
TEXTO_SUAVE = "#6b6b78"
FONDO = "#f6f6fa"
HUNDIDO = "#f1f1f5"
NARANJA = "#c2410c"

def hoja_de_estilo(mono: str) -> str:
    """Hoja de estilo Qt (parecida a CSS). Los widgets se seleccionan por su propiedad "clase"."""
    return f"""
    QWidget {{ color: {TEXTO}; font-size: 14px; }}
    QWidget#contenido {{ background: {FONDO}; }}
    QScrollArea {{ border: none; background: {FONDO}; }}

    QScrollBar:vertical {{ width: 10px; background: transparent; }}
    QScrollBar::handle:vertical {{ background: rgba(0, 0, 0, 45); border-radius: 3px; min-height: 30px; margin: 2px; }}
    QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ height: 0; background: none; }}

    QFrame#segmentado, QFrame#segmentadoPeq {{ background: rgba(0, 0, 0, 15); border-radius: 10px; }}
    QFrame#segmentado QPushButton {{
        border: none; border-radius: 8px; padding: 6px 10px; background: transparent;
        color: {TEXTO_SUAVE}; font-size: 13px; font-weight: 500;
    }}
    QFrame#segmentado QPushButton:checked {{ background: white; color: {TEXTO}; }}
    QFrame#segmentadoPeq QPushButton {{
        border: none; border-radius: 8px; padding: 3px 12px; background: transparent;
        color: {TEXTO_SUAVE}; font-size: 13px; font-weight: 500;
    }}
    QFrame#segmentadoPeq QPushButton:checked {{ background: {ACENTO}; color: white; }}

    QLabel[clase="campo"] {{ color: {TEXTO_SUAVE}; font-size: 13px; font-weight: 600; }}
    QLabel[clase="nota"] {{ color: {TEXTO_SUAVE}; font-size: 13px; }}
    QLabel[clase="error"] {{ color: {NARANJA}; font-size: 13px; }}
    QLabel[clase="motor"] {{ color: {TEXTO_SUAVE}; font-size: 12px; }}

    QPlainTextEdit, QLineEdit, QSpinBox, QComboBox {{
        background: white; border: 1px solid rgba(0, 0, 0, 36); border-radius: 8px; padding: 6px 9px;
        font-family: "{mono}"; font-size: 14px; selection-background-color: {ACENTO};
    }}
    QPlainTextEdit:focus, QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
        border: 2px solid {ACENTO}; padding: 5px 8px;
    }}
    QComboBox::drop-down, QSpinBox::up-button, QSpinBox::down-button {{ border: none; width: 18px; }}
    QComboBox QAbstractItemView {{ background: white; selection-background-color: {ACENTO}; font-family: "{mono}"; }}

    QPushButton[clase="btn"] {{
        background: white; border: 1px solid rgba(0, 0, 0, 36); border-radius: 8px;
        padding: 7px 14px; font-size: 14px; font-weight: 600;
    }}
    QPushButton[clase="btn"]:hover {{ background: #f3f3f7; }}
    QPushButton[clase="btn"]:disabled {{ color: #a9a9b3; }}
    QPushButton[clase="primario"] {{
        background: {ACENTO}; border: 1px solid {ACENTO}; border-radius: 8px; color: white;
        padding: 7px 14px; font-size: 14px; font-weight: 600;
    }}
    QPushButton[clase="primario"]:hover {{ background: #6c7de6; border-color: #6c7de6; }}
    QPushButton[clase="primario"]:disabled {{ background: #adb6f0; border-color: #adb6f0; }}
    QPushButton[pequeno="si"] {{ padding: 4px 10px; font-size: 13px; }}

    QFrame[clase="tarjeta"], QFrame[clase="tabla"] {{
        background: white; border: 1px solid rgba(0, 0, 0, 20); border-radius: 10px;
    }}
    QFrame[clase="tarjeta"] QLabel {{ background: transparent; border: none; }}
    QLabel[clase="etiqueta"] {{ color: {TEXTO_SUAVE}; font-size: 12px; font-weight: 600; }}
    QLabel[clase="clave"] {{ color: {ACENTO}; font-family: "{mono}"; font-size: 26px; font-weight: 700; }}
    QLabel[clase="meta"] {{ color: {TEXTO_SUAVE}; font-size: 13px; }}
    QPlainTextEdit[clase="vista"], QPlainTextEdit[clase="resultado"] {{
        background: {HUNDIDO}; border: none; border-radius: 8px; padding: 6px; font-size: 13px;
    }}
    QPlainTextEdit[clase="resultado"] {{ background: white; padding: 0; }}
    QToolButton[clase="desplegar"] {{
        border: none; background: transparent; color: {ACENTO}; font-size: 13px; font-weight: 600; padding: 0;
    }}

    QFrame[clase="tabla"] QLabel {{ padding: 7px 10px; font-size: 13px; border-bottom: 1px solid rgba(0, 0, 0, 20); }}
    QFrame[clase="tabla"] QLabel[th="si"] {{
        background: {HUNDIDO}; color: {TEXTO_SUAVE}; font-size: 11px; font-weight: 600;
    }}
    QFrame[clase="tabla"] QLabel[th="si"][pos="izq"] {{ border-top-left-radius: 9px; }}
    QFrame[clase="tabla"] QLabel[th="si"][pos="der"] {{ border-top-right-radius: 9px; }}
    QFrame[clase="tabla"] QLabel[mono="si"] {{ font-family: "{mono}"; font-weight: 600; }}
    QFrame[clase="tabla"] QLabel[ultima="si"] {{ border-bottom: none; }}

    QProgressBar {{ background: rgba(0, 0, 0, 20); border: none; border-radius: 3px; max-height: 6px; min-height: 6px; }}
    QProgressBar::chunk {{ background: {ACENTO}; border-radius: 3px; }}

    QFrame#separador {{ background: rgba(0, 0, 0, 20); max-height: 1px; min-height: 1px; border: none; }}
    """

def fuente_mono() -> str:
    """Primera fuente monoespaciada instalada de la lista, o la del sistema."""
    disponibles = set(QFontDatabase.families())
    for familia in ("Cascadia Code", "Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "Courier New"):
        if familia in disponibles:
            return familia
    return QFontDatabase.systemFont(QFontDatabase.FixedFont).family()

def icono_app() -> QIcon:
    """Candado blanco sobre un cuadrado morado, dibujado aquí para no depender de archivos."""
    icono = QIcon()
    for lado in (16, 32, 64, 256):
        pixmap = QPixmap(lado, lado)
        pixmap.fill(Qt.transparent)
        p = QPainter(pixmap)
        p.setRenderHint(QPainter.Antialiasing)
        degradado = QLinearGradient(0, 0, lado, lado)
        degradado.setColorAt(0, QColor("#a78bfa"))
        degradado.setColorAt(1, QColor("#6d28d9"))
        p.setPen(Qt.NoPen)
        p.setBrush(degradado)
        p.drawRoundedRect(QRectF(0, 0, lado, lado), lado * 0.24, lado * 0.24)
        u = lado / 24  # unidad: el dibujo está pensado en una rejilla de 24x24
        p.setPen(QPen(Qt.white, max(1.5, 2 * u), Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        p.setBrush(Qt.NoBrush)
        p.drawRoundedRect(QRectF(5 * u, 11 * u, 14 * u, 9 * u), 1.6 * u, 1.6 * u)  # cuerpo del candado
        arco = QPainterPath(QPointF(8 * u, 11 * u))  # asa del candado
        arco.lineTo(8 * u, 8.5 * u)
        arco.arcTo(QRectF(8 * u, 4.5 * u, 8 * u, 8 * u), 180, -180)
        arco.lineTo(16 * u, 11 * u)
        p.drawPath(arco)
        p.end()
        icono.addPixmap(pixmap)
    return icono


# INTERFAZ: PIEZAS

def etiqueta(texto, clase, ajustar=False) -> QLabel:
    label = QLabel(texto)
    label.setProperty("clase", clase)
    label.setWordWrap(ajustar)
    return label

def boton(texto, primario=False, pequeno=False) -> QPushButton:
    b = QPushButton(texto)
    b.setProperty("clase", "primario" if primario else "btn")
    if pequeno:
        b.setProperty("pequeno", "si")
    b.setCursor(Qt.PointingHandCursor)
    return b

def fila(*widgets, estirar=None) -> QHBoxLayout:
    """Widgets en horizontal. `estirar` ocupa el espacio libre; si no hay, queda un hueco al final."""
    layout = QHBoxLayout()
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)
    for w in widgets:
        layout.addWidget(w, 1 if w is estirar else 0)
    if estirar is None:
        layout.addStretch(1)
    return layout

def area_texto(alto=104) -> QPlainTextEdit:
    texto = QPlainTextEdit()
    texto.setFixedHeight(alto)
    texto.setTabChangesFocus(True)
    return texto

def solo_lectura(texto, clase, alto) -> QPlainTextEdit:
    vista = QPlainTextEdit(texto)
    vista.setProperty("clase", clase)
    vista.setReadOnly(True)
    vista.setWordWrapMode(QTextOption.WrapAnywhere)
    vista.setFixedHeight(alto)
    return vista

def tabla(cabeceras, filas, columna_mono=None) -> QFrame:
    """Tabla sencilla hecha con QLabels en una rejilla."""
    marco = QFrame()
    marco.setProperty("clase", "tabla")
    rejilla = QGridLayout(marco)
    rejilla.setContentsMargins(0, 0, 0, 0)
    rejilla.setSpacing(0)
    for c, texto in enumerate(cabeceras):
        th = QLabel(texto.upper())
        th.setProperty("th", "si")
        th.setProperty("pos", "izq" if c == 0 else "der" if c == len(cabeceras) - 1 else "")
        rejilla.addWidget(th, 0, c)
        rejilla.setColumnStretch(c, 1)
    for r, valores in enumerate(filas, 1):
        for c, valor in enumerate(valores):
            td = QLabel(str(valor))
            td.setTextFormat(Qt.PlainText)
            td.setProperty("mono", "si" if c == columna_mono else "")
            td.setProperty("ultima", "si" if r == len(filas) else "")
            rejilla.addWidget(td, r, c)
    return marco


class Segmentado(QFrame):
    """Selector de opciones en fila (las pestañas y el idioma)."""
    cambiado = Signal(str)

    def __init__(self, opciones, pequeno=False):
        super().__init__()
        self.setObjectName("segmentadoPeq" if pequeno else "segmentado")
        self.pequeno = pequeno
        self.textos = dict(opciones)
        self.botones = {}
        layout = QHBoxLayout(self)
        margen = 2 if pequeno else 3
        layout.setContentsMargins(margen, margen, margen, margen)
        layout.setSpacing(2)
        grupo = QButtonGroup(self)
        for clave, texto in opciones:
            b = QPushButton(texto)
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _=False, c=clave: self.seleccionar(c, emitir=True))
            grupo.addButton(b)
            layout.addWidget(b, 0 if pequeno else 1)
            self.botones[clave] = b
        if pequeno:
            self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

    def seleccionar(self, clave, emitir=False):
        for c, b in self.botones.items():
            b.setChecked(c == clave)
            if self.pequeno:
                b.setText(("✓ " if c == clave else "") + self.textos[c])
        if emitir:
            self.cambiado.emit(clave)


class Histograma(QWidget):
    """Barras: frecuencia de cada letra en el texto descifrado. Línea: frecuencia del idioma."""

    def __init__(self, filas, nombre_idioma, mono):
        super().__init__()
        self.filas, self.nombre_idioma, self.mono = filas, nombre_idioma, mono
        self.setMinimumHeight(108)
        self.setMouseTracking(True)

    def _ancho_columna(self):
        return (self.width() - 3 * 25) / 26  # 26 columnas con 3 px de separación

    def paintEvent(self, evento):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        ancho = self._ancho_columna()
        alto = self.height() - 20  # deja sitio abajo para las letras
        escala = max(max(real, teorico) for _, real, teorico in self.filas) * 1.1 or 1
        fuente = QFont(self.mono)
        fuente.setPixelSize(11)
        fuente.setWeight(QFont.DemiBold)
        p.setFont(fuente)
        barra = QColor(ACENTO)
        barra.setAlpha(217)
        for i, (letra, real, teorico) in enumerate(self.filas):
            x = i * (ancho + 3)
            # Fondo de la columna
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(HUNDIDO))
            p.drawRoundedRect(QRectF(x, 0, ancho, alto), 4, 4)
            # Barra: frecuencia real
            h = real / escala * alto
            p.setBrush(barra)
            p.drawRoundedRect(QRectF(x + ancho * 0.15, alto - h, ancho * 0.7, h), 2, 2)
            # Raya: frecuencia teórica del idioma
            y = alto - teorico / escala * alto
            p.setBrush(QColor(NARANJA))
            p.drawRoundedRect(QRectF(x, y - 1, ancho, 2), 1, 1)
            p.setPen(QColor(TEXTO_SUAVE))
            p.drawText(QRectF(x, alto + 4, ancho, 16), Qt.AlignCenter, letra)
        p.end()

    def mouseMoveEvent(self, evento):
        i = min(25, max(0, int(evento.position().x() // (self._ancho_columna() + 3))))
        letra, real, teorico = self.filas[i]
        QToolTip.showText(
            evento.globalPosition().toPoint(), f"{letra}: {real:.2f}% ({self.nombre_idioma} {teorico:.2f}%)", self
        )


class Resultados(QWidget):
    """Zona donde se pintan los resultados de cada pestaña."""

    def __init__(self):
        super().__init__()
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(0, 0, 0, 0)
        self.layout_.setSpacing(12)
        self.hide()

    def mostrar(self, *widgets):
        while self.layout_.count():
            self.layout_.takeAt(0).widget().deleteLater()
        for w in widgets:
            self.layout_.addWidget(w)
        self.setVisible(bool(widgets))


class Puente(QObject):
    """Lleva al hilo de la interfaz lo que terminan los hilos de trabajo."""
    hecho = Signal(object)

# INTERFAZ: VENTANA
#
# Cambio de idioma: en lugar de guardar cada widget para retraducirlo, la ventana entera
# se vuelve a construir con los textos nuevos (_construir). Antes se guarda lo que había
# escrito el usuario, y cada resultado se pinta con una función guardada en self.vistas,
# así se puede volver a pintar en el idioma nuevo sin repetir el cálculo.

class Ventana(QMainWindow):
    def __init__(self, motor: Motor, mono: str):
        super().__init__()
        self.motor, self.mono = motor, mono
        self.ajustes = QSettings("Ager90", "Pygenere")
        self.idioma = self.ajustes.value("idioma", idioma_del_sistema())
        if self.idioma not in IDIOMAS:
            self.idioma = "es"
        self.pestana = "cifrar"
        self.vistas = {}       # pestaña -> función que crea los widgets de su último resultado
        self.ocupado = set()   # tareas en segundo plano sin terminar ("estadistico", "benchmark")
        self.puente = Puente()
        self.puente.hecho.connect(self._en_interfaz)
        self.temporizador = QTimer(self)  # consulta el progreso de la fuerza bruta
        self.temporizador.setInterval(200)
        self.temporizador.timeout.connect(self._sondear_bruta)

        self.setWindowTitle(f"Pygenère {VERSION}")
        self.setWindowIcon(icono_app())
        self.resize(760, 680)
        self.setMinimumHeight(480)  # el ancho mínimo se calcula en _construir
        self._construir()

    # Construcción y cambio de idioma
    def _construir(self):
        """Crea todo el contenido de la ventana con los textos del idioma actual.
        Si ya existía (cambio de idioma), conserva lo escrito y los resultados."""
        campos = self._leer_campos() if self.centralWidget() else None
        fijar_idioma(self.idioma)

        contenido = QWidget()
        contenido.setObjectName("contenido")
        raiz = QVBoxLayout(contenido)
        raiz.setContentsMargins(20, 18, 20, 18)
        raiz.setSpacing(14)

        self.pestanas = Segmentado([
            (nombre, t(f"pestana_{nombre}")) for nombre in ("cifrar", "estadistico", "bruta", "benchmark")
        ])
        self.pestanas.cambiado.connect(self.mostrar_pestana)
        raiz.addWidget(self.pestanas)

        self.resultados = {}  # pestaña -> su zona de Resultados (las crea cada _pagina_*)
        self.paginas = {
            "cifrar": self._pagina_cifrar(),
            "estadistico": self._pagina_estadistico(),
            "bruta": self._pagina_bruta(),
            "benchmark": self._pagina_benchmark(),
        }
        for pagina in self.paginas.values():
            raiz.addWidget(pagina)
        raiz.addStretch(1)
        raiz.addWidget(self._pie())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(contenido)
        self.setCentralWidget(scroll)  # Qt borra (con deleteLater) el contenido anterior
        # El ancho mínimo depende de los textos (en español son más largos), así nunca se cortan los botones
        ancho_minimo = contenido.minimumSizeHint().width() + scroll.verticalScrollBar().sizeHint().width()
        self.setMinimumWidth(ancho_minimo)
        if self.width() < ancho_minimo:
            self.resize(ancho_minimo, self.height())

        # Restaura el estado: lo escrito, la pestaña, los resultados y las tareas en marcha
        if campos:
            self._escribir_campos(campos)
        self.mostrar_pestana(self.pestana)
        self.selector_idioma.seleccionar(self.idioma)
        for pestana, crear in self.vistas.items():
            self.resultados[pestana].mostrar(*crear())
        self.boton_estadistico.setEnabled("estadistico" not in self.ocupado)
        self.boton_benchmark.setEnabled("benchmark" not in self.ocupado)
        self._bruta_en_marcha(self.motor.bruta_activa())

    def _leer_campos(self):
        """Lo que ha escrito o elegido el usuario, para no perderlo al reconstruir."""
        return {
            "texto": self.texto.toPlainText(),
            "clave": self.clave.text(),
            "texto_estadistico": self.texto_estadistico.toPlainText(),
            "texto_bruta": self.texto_bruta.toPlainText(),
            "max_estadistico": self.max_estadistico.value(),
            "max_bruta": self.max_bruta.currentIndex(),
        }

    def _escribir_campos(self, campos):
        self.texto.setPlainText(campos["texto"])
        self.clave.setText(campos["clave"])
        self.texto_estadistico.setPlainText(campos["texto_estadistico"])
        self.texto_bruta.setPlainText(campos["texto_bruta"])
        self.max_estadistico.setValue(campos["max_estadistico"])
        self.max_bruta.setCurrentIndex(campos["max_bruta"])

    def cambiar_idioma(self, codigo):
        """Cambia a la vez el idioma de la interfaz y el de los ataques, y lo recuerda para la próxima vez."""
        if codigo == self.idioma:
            return
        self.idioma = codigo
        self.ajustes.setValue("idioma", codigo)
        self._construir()

    # Utilidades
    @staticmethod
    def _pagina():
        pagina = QWidget()
        layout = QVBoxLayout(pagina)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        return pagina, layout

    @staticmethod
    def _campo(texto, widget):
        """Etiqueta encima de un widget."""
        layout = QVBoxLayout()
        layout.setSpacing(4)
        layout.addWidget(etiqueta(texto, "campo"))
        layout.addWidget(widget)
        return layout

    def _zona_resultados(self, pestana, layout):
        self.resultados[pestana] = Resultados()
        layout.addWidget(self.resultados[pestana])

    def _mostrar(self, pestana, crear):
        """Pinta el resultado de una pestaña. `crear` devuelve la lista de widgets; se guarda
        para volver a pintarlo si se cambia de idioma."""
        self.vistas[pestana] = crear
        self.resultados[pestana].mostrar(*crear())

    def _mostrar_error(self, pestana, error):
        self._mostrar(pestana, lambda: [etiqueta(mensaje_error(error), "error", ajustar=True)])

    def _en_segundo_plano(self, trabajo, al_terminar):
        """Ejecuta trabajo() en un hilo y luego al_terminar(resultado, error) en la interfaz."""
        def correr():
            try:
                resultado = trabajo()
                respuesta = lambda: al_terminar(resultado, None)
            except Exception as error:
                respuesta = lambda error=error: al_terminar(None, error)
            self.puente.hecho.emit(respuesta)
        threading.Thread(target=correr, daemon=True).start()

    def _en_interfaz(self, funcion):
        funcion()

    def mostrar_pestana(self, nombre):
        self.pestana = nombre
        self.pestanas.seleccionar(nombre)
        for clave, pagina in self.paginas.items():
            pagina.setVisible(clave == nombre)

    def cargar_cifrado(self, texto):
        """Pone el texto en las dos pestañas de ataque."""
        self.texto_estadistico.setPlainText(texto)
        self.texto_bruta.setPlainText(texto)

    def cargar_ejemplo(self):
        self.cargar_cifrado(texto_ejemplo(self.idioma))

    def tarjeta_clave(self, titulo, clave, meta, detalle=None) -> QFrame:
        """Tarjeta con una clave grande y, si hay detalle, la vista previa y el histograma desplegable."""
        tarjeta = QFrame()
        tarjeta.setProperty("clase", "tarjeta")
        layout = QVBoxLayout(tarjeta)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(2)
        layout.addWidget(etiqueta(titulo.upper(), "etiqueta"))
        label_clave = etiqueta(clave, "clave")
        label_clave.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(label_clave)
        layout.addWidget(etiqueta(meta, "meta"))
        if detalle:
            # Idioma con el que se hizo el ataque (puede no ser el actual si se cambió después)
            nombre_idioma = t(f"idioma_{detalle['idioma']}")
            layout.addSpacing(8)
            layout.addWidget(solo_lectura(detalle["vista_previa"], "vista", 112))
            layout.addSpacing(8)
            desplegar = QToolButton()
            desplegar.setProperty("clase", "desplegar")
            desplegar.setText("▸  " + t("frecuencias"))
            desplegar.setCursor(Qt.PointingHandCursor)
            grafico = Histograma(detalle["histograma"], nombre_idioma, self.mono)
            leyenda = etiqueta(
                f"<span style='color:{ACENTO}'>■</span>&nbsp; {t('texto_descifrado')} &nbsp;&nbsp;&nbsp; "
                f"<span style='color:{NARANJA}'>━</span>&nbsp; {nombre_idioma}", "meta"
            )
            grafico.hide()
            leyenda.hide()

            def alternar():
                abierto = not grafico.isVisible()
                grafico.setVisible(abierto)
                leyenda.setVisible(abierto)
                desplegar.setText(("▾" if abierto else "▸") + "  " + t("frecuencias"))

            desplegar.clicked.connect(alternar)
            layout.addWidget(desplegar, 0, Qt.AlignLeft)
            layout.addSpacing(4)
            layout.addWidget(grafico)
            layout.addWidget(leyenda)
        return tarjeta

    @staticmethod
    def ranking(filas) -> QFrame:
        """Tabla con las mejores claves: filas = [(clave, chi), ...]."""
        return tabla(
            ["#", t("col_clave"), t("col_longitud"), "χ²"],
            [(i, clave, len(clave), f"{chi:.1f}") for i, (clave, chi) in enumerate(filas, 1)],
            columna_mono=1,
        )

    # Pestaña: cifrar / descifrar
    def _pagina_cifrar(self):
        pagina, layout = self._pagina()
        self.texto = area_texto()
        self.texto.setPlaceholderText(t("texto_placeholder"))
        layout.addLayout(self._campo(t("texto"), self.texto))

        self.clave = QLineEdit()
        self.clave.setPlaceholderText(t("clave_placeholder"))
        # Intro cifra; Mayús + Intro descifra
        self.clave.returnPressed.connect(
            lambda: self.ejecutar_cifrado(-1 if QApplication.keyboardModifiers() & Qt.ShiftModifier else 1)
        )
        cifrar, descifrar = boton(t("cifrar"), primario=True), boton(t("descifrar"))
        cifrar.clicked.connect(lambda: self.ejecutar_cifrado(1))
        descifrar.clicked.connect(lambda: self.ejecutar_cifrado(-1))
        layout.addLayout(fila(etiqueta(t("clave"), "campo"), self.clave, cifrar, descifrar, estirar=self.clave))

        self._zona_resultados("cifrar", layout)
        layout.addWidget(etiqueta(t("nota_cifrar"), "nota", ajustar=True))
        return pagina

    def ejecutar_cifrado(self, direccion):
        try:
            salida = self.motor.cifrar(self.texto.toPlainText(), self.clave.text(), direccion)
        except ErrorEntrada as error:
            return self._mostrar_error("cifrar", error)
        self._mostrar("cifrar", lambda: [self._tarjeta_salida(salida)])

    def _tarjeta_salida(self, salida) -> QFrame:
        """Texto cifrado/descifrado con los botones de copiar y de pasarlo a los ataques."""
        tarjeta = QFrame()
        tarjeta.setProperty("clase", "tarjeta")
        layout = QVBoxLayout(tarjeta)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        copiar = boton(t("copiar"), pequeno=True)
        copiar.clicked.connect(lambda: self._copiar(salida, copiar))
        romper = boton(t("romper"), pequeno=True)
        romper.clicked.connect(lambda: (self.cargar_cifrado(salida), self.mostrar_pestana("estadistico")))
        layout.addWidget(solo_lectura(salida, "resultado", 96))
        layout.addLayout(fila(copiar, romper))
        return tarjeta

    @staticmethod
    def _copiar(texto, boton_copiar):
        QApplication.clipboard().setText(texto)
        boton_copiar.setText(t("copiado"))

        def restaurar():
            try:
                boton_copiar.setText(t("copiar"))
            except RuntimeError:  # el botón ya no existe (se cambió de idioma mientras tanto)
                pass

        QTimer.singleShot(1200, restaurar)

    # Pestaña: ataque estadístico
    def _pagina_estadistico(self):
        pagina, layout = self._pagina()
        layout.addWidget(etiqueta(t("nota_estadistico"), "nota", ajustar=True))
        self.texto_estadistico = area_texto()
        layout.addLayout(self._campo(t("texto_cifrado"), self.texto_estadistico))

        self.max_estadistico = QSpinBox()
        self.max_estadistico.setRange(1, 30)
        self.max_estadistico.setValue(20)
        self.max_estadistico.setFixedWidth(84)
        self.boton_estadistico = boton(t("lanzar_ataque"), primario=True)
        self.boton_estadistico.clicked.connect(self.ejecutar_estadistico)
        ejemplo = boton(t("cargar_ejemplo"))
        ejemplo.clicked.connect(self.cargar_ejemplo)
        layout.addLayout(fila(etiqueta(t("max_longitud"), "campo"), self.max_estadistico, self.boton_estadistico, ejemplo))

        self._zona_resultados("estadistico", layout)
        return pagina

    def ejecutar_estadistico(self):
        texto, maximo, idioma = self.texto_estadistico.toPlainText(), self.max_estadistico.value(), self.idioma
        self.ocupado.add("estadistico")
        self.boton_estadistico.setEnabled(False)

        def al_terminar(r, error):
            # self.boton_estadistico se busca ahora: si se cambió de idioma, ya es el botón nuevo
            self.ocupado.discard("estadistico")
            self.boton_estadistico.setEnabled(True)
            if error:
                return self._mostrar_error("estadistico", error)
            self._mostrar("estadistico", lambda: self._vista_estadistico(r))

        self._en_segundo_plano(lambda: self.motor.estadistico(texto, maximo, idioma), al_terminar)

    def _vista_estadistico(self, r):
        mejor = r["mejor"]
        return [
            self.tarjeta_clave(
                t("clave_probable"), mejor["clave"],
                t("meta_clave", longitud=len(mejor["clave"]), chi=mejor["chi"]) + f" · IoC {mejor['ioc']:.3f}",
                r["detalle"],
            ),
            self.ranking([(f["clave"], f["chi"]) for f in r["ranking"]]),
            etiqueta(t("hecho_en", tiempo=formatear_tiempo(r["segundos"])), "nota", ajustar=True),
        ]

    # Pestaña: fuerza bruta
    def _pagina_bruta(self):
        pagina, layout = self._pagina()
        layout.addWidget(etiqueta(t("nota_bruta"), "nota", ajustar=True))
        self.texto_bruta = area_texto()
        layout.addLayout(self._campo(t("texto_cifrado"), self.texto_bruta))

        # Las longitudes largas llevan un aviso de cuánto pueden tardar
        self.max_bruta = QComboBox()
        for valor in range(1, MAX_LONGITUD_BRUTA + 1):
            aviso = f" ({t(f'aviso_{valor}')})" if f"aviso_{valor}" in TEXTOS[_idioma] else ""
            self.max_bruta.addItem(f"{valor}{aviso}", valor)
        self.max_bruta.setCurrentIndex(3)
        self.boton_bruta = boton(t("empezar"), primario=True)
        self.boton_bruta.clicked.connect(self.ejecutar_bruta)
        self.boton_cancelar = boton(t("cancelar"))
        self.boton_cancelar.clicked.connect(self.cancelar_bruta)
        self.boton_cancelar.hide()
        ejemplo = boton(t("cargar_ejemplo"))
        ejemplo.clicked.connect(self.cargar_ejemplo)
        layout.addLayout(fila(etiqueta(t("max_longitud"), "campo"), self.max_bruta, self.boton_bruta,
                              self.boton_cancelar, ejemplo))

        self._zona_resultados("bruta", layout)
        return pagina

    def _bruta_en_marcha(self, activa):
        self.boton_bruta.setEnabled(not activa)
        self.boton_cancelar.setVisible(activa)
        self.boton_cancelar.setEnabled(True)

    def ejecutar_bruta(self):
        try:
            self.motor.iniciar_fuerza_bruta(self.texto_bruta.toPlainText(), self.max_bruta.currentData(), self.idioma)
        except ErrorEntrada as error:
            return self._mostrar_error("bruta", error)
        self._mostrar("bruta", self._vista_progreso)
        self._bruta_en_marcha(True)
        self.temporizador.start()

    def _vista_progreso(self):
        """Barra y texto de progreso; _sondear_bruta los actualiza."""
        self.barra = QProgressBar()
        self.barra.setRange(0, 1000)
        self.barra.setTextVisible(False)
        self.progreso = etiqueta(t("empezando"), "nota")
        return [self.barra, self.progreso]

    def cancelar_bruta(self):
        self.boton_cancelar.setEnabled(False)
        self.motor.cancelar_fuerza_bruta()

    def _sondear_bruta(self):
        """Cada 200 ms: actualiza el progreso o, si ya terminó, enseña el resultado."""
        estado = self.motor.estado_fuerza_bruta()
        if estado["activo"]:
            velocidad = estado["probadas"] / estado["segundos"] if estado["segundos"] > 0 else 0
            self.barra.setValue(int(estado["probadas"] / estado["total"] * 1000))
            restante = ""
            if velocidad:
                restante = t("restante", tiempo=formatear_tiempo((estado["total"] - estado["probadas"]) / velocidad))
            self.progreso.setText(t(
                "progreso", probadas=formatear_numero(estado["probadas"]), total=formatear_numero(estado["total"]),
                velocidad=formatear_numero(velocidad), tiempo=formatear_tiempo(estado["segundos"]), restante=restante,
            ))
            return

        self.temporizador.stop()
        self._bruta_en_marcha(False)
        if estado["error"]:
            return self._mostrar_error("bruta", RuntimeError(estado["error"]))
        self._mostrar("bruta", lambda: self._vista_bruta(estado))

    def _vista_bruta(self, estado):
        resumen = etiqueta(t(
            "cancelado_tras" if estado["cancelado"] else "probadas",
            probadas=formatear_numero(estado["probadas"]), total=formatear_numero(estado["total"]),
            tiempo=formatear_tiempo(estado["segundos"]),
        ), "nota", ajustar=True)
        if not estado["top"]:
            return [resumen]
        chi, clave = estado["top"][0]
        return [
            self.tarjeta_clave(
                t("mejor_hasta_ahora" if estado["cancelado"] else "mejor_clave"), clave,
                t("meta_clave", longitud=len(clave), chi=chi), estado["detalle"],
            ),
            self.ranking([(k, c) for c, k in estado["top"]]),
            resumen,
        ]

    # Pestaña: benchmark
    def _pagina_benchmark(self):
        pagina, layout = self._pagina()
        layout.addWidget(etiqueta(t("nota_benchmark"), "nota", ajustar=True))
        self.boton_benchmark = boton(t("ejecutar_benchmark"), primario=True)
        self.boton_benchmark.clicked.connect(self.ejecutar_benchmark)
        layout.addLayout(fila(self.boton_benchmark))
        self._zona_resultados("benchmark", layout)
        return pagina

    def ejecutar_benchmark(self):
        self.ocupado.add("benchmark")
        self.boton_benchmark.setEnabled(False)
        self._mostrar("benchmark", lambda: [etiqueta(t("midiendo"), "nota")])

        def al_terminar(r, error):
            self.ocupado.discard("benchmark")
            self.boton_benchmark.setEnabled(True)
            if error:
                return self._mostrar_error("benchmark", error)
            self._mostrar("benchmark", lambda: self._vista_benchmark(r))

        self._en_segundo_plano(lambda: self.motor.benchmark(self.idioma), al_terminar)

    def _vista_benchmark(self, r):
        procesos = self.motor.procesos
        return [
            self.tarjeta_clave(
                t("tu_ordenador"), formatear_numero(r["velocidad"]),
                t("meta_benchmark", n=procesos, procesos=t("proceso" if procesos == 1 else "procesos"),
                  letras=r["letras"]),
            ),
            tabla(
                [t("col_longitud_clave"), t("col_combinaciones"), t("col_tiempo")],
                [(l, formatear_numero(26 ** l), formatear_tiempo(26 ** l / r["velocidad"]))
                 for l in range(1, MAX_LONGITUD_BRUTA + 1)],
            ),
        ]

    # Pie: idioma (de la interfaz y de los ataques)
    def _pie(self):
        pie = QWidget()
        layout = QVBoxLayout(pie)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        separador = QFrame()
        separador.setObjectName("separador")
        layout.addWidget(separador)
        layout.addSpacing(2)

        # Los nombres de los idiomas van siempre en su propio idioma, para encontrarlos aunque no se entienda el otro
        self.selector_idioma = Segmentado([("es", "Español"), ("en", "English")], pequeno=True)
        self.selector_idioma.cambiado.connect(self.cambiar_idioma)
        procesos = self.motor.procesos
        motor = etiqueta(t(
            "info_motor", python=sys.version.split()[0], n=procesos,
            procesos=t("proceso" if procesos == 1 else "procesos"), nucleos=multiprocessing.cpu_count(),
        ), "motor")
        fila_idioma = fila(etiqueta(t("idioma"), "campo"), self.selector_idioma)
        fila_idioma.addWidget(motor)
        layout.addLayout(fila_idioma)

        layout.addWidget(etiqueta(t("nota_idioma"), "nota", ajustar=True))
        return pie

    def closeEvent(self, evento):
        self.temporizador.stop()
        self.motor.cerrar()
        super().closeEvent(evento)


# MAIN

def main():
    multiprocessing.freeze_support()  # necesario para que multiprocessing funcione en el .exe
    parser = argparse.ArgumentParser(description="Pygenère 2.0 — cifrado Vigenère con interfaz gráfica")
    parser.add_argument("--procesos", type=int, default=NUM_PROCESOS, help=f"procesos para los ataques (por defecto {NUM_PROCESOS})")
    args = parser.parse_args()
    procesos = max(1, args.procesos)

    # Con pythonw no hay consola, así que solo se escribe si existe
    if sys.stdout:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="replace")
        print(ASCII_ART)
        print(f"[*] Se han detectado {multiprocessing.cpu_count()} núcleos.")
        print(f"[*] Se usarán {procesos} procesos.")

    if sys.platform == "win32":
        # Para que la barra de tareas muestre el icono de Pygenère y no el de Python
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Ager90.Pygenere.2")

    app = QApplication(sys.argv)
    app.setApplicationName("Pygenère")
    app.setStyle("Fusion")
    # Paleta clara fija, para que el modo oscuro del sistema no mezcle colores
    paleta = app.palette()
    paleta.setColor(QPalette.Window, QColor(FONDO))
    paleta.setColor(QPalette.Base, QColor("white"))
    paleta.setColor(QPalette.Text, QColor(TEXTO))
    paleta.setColor(QPalette.WindowText, QColor(TEXTO))
    paleta.setColor(QPalette.ButtonText, QColor(TEXTO))
    paleta.setColor(QPalette.Highlight, QColor(ACENTO))
    paleta.setColor(QPalette.PlaceholderText, QColor("#9a9aa6"))
    app.setPalette(paleta)
    mono = fuente_mono()
    app.setStyleSheet(hoja_de_estilo(mono))

    motor = Motor(procesos)
    ventana = Ventana(motor, mono)
    ventana.show()
    codigo = app.exec()
    motor.cerrar()
    sys.exit(codigo)


if __name__ == "__main__":
    main()

