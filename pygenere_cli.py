"""
Pygenère (versión de terminal) — cifrado Vigenère con menú de consola.

Es el script de Pygenère 1.0 con los fallos corregidos en la 2.0. Solo usa la
librería estándar de Python, así que no hace falta instalar nada.

Uso:
    python pygenere_cli.py
"""
import itertools
import multiprocessing
import sys
import time
import unicodedata
from typing import List, Tuple


# CONSTANTES Y CONFIGURACIÓN

NUM_PROCESOS = max(1, multiprocessing.cpu_count() // 4)  # Usa un cuarto de los núcleos (redondeado abajo), siendo el número mínimo 1
# Se puede sustituir max(1, multiprocessing.cpu_count() // 4) por el número de núcleos que se quiera usar

# Frecuencias estándar del español (sin Ñ propia, se normaliza a N)
FRECUENCIAS_ESP = {
    'A': 12.53, 'B': 1.42, 'C': 4.68, 'D': 5.86, 'E': 13.68, 'F': 0.69,
    'G': 1.01, 'H': 0.70, 'I': 6.25, 'J': 0.44, 'K': 0.02, 'L': 4.97,
    'M': 3.15, 'N': 6.71, 'O': 8.68, 'P': 2.51, 'Q': 0.88, 'R': 6.87,
    'S': 7.98, 'T': 4.63, 'U': 3.93, 'V': 0.90, 'W': 0.01, 'X': 0.22,
    'Y': 0.90, 'Z': 0.52
}

# Alfabeto estándar de 26 caracteres (sin la Ñ por compatibilidad)
ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LEN_ALFA = len(ALFABETO)
CHAR_TO_IDX = {c: i for i, c in enumerate(ALFABETO)}

MIN_LETRAS_ESTADISTICO = 20
MIN_LETRAS_FUERZA_BRUTA = 10

ASCII_ART = r"""
  ____                          __
 |  _ \ _   _  __ _  ___ _ __   \_\ _ __ ___
 | |_) | | | |/ _` |/ _ \ '_ \ / _ \ '__/ _ \
 |  __/| |_| | (_| |  __/ | | |  __/ | |  __/
 |_|    \__, |\__, |\___|_| |_|\___|_|  \___|
        |___/ |___/

               -06ɹǝƃ∀@ ʎB-
"""


# UTILIDADES

def normalizar_texto(texto: str) -> str:
    """
    Elimina acentos y diacríticos (Ñ -> N), convierte a mayúsculas y deja solo A-Z.
    Las letras que no tienen equivalente en A-Z (Ø, Æ, griegas...) se descartan.
    """
    if not texto: return ""
    texto_normalizado = unicodedata.normalize('NFD', texto)
    sin_acentos = "".join(c for c in texto_normalizado if unicodedata.category(c) != 'Mn')
    return "".join(c for c in sin_acentos.upper() if c in CHAR_TO_IDX)

def formatear_tiempo(segundos: float) -> str:
    if segundos < 60: return f"{segundos:.4f} seg"
    if segundos < 3600: return f"{segundos / 60:.2f} min"
    if segundos < 86400: return f"{segundos / 3600:.2f} horas"
    if segundos < 31557600: return f"{segundos / 86400:.2f} días"
    return f"{segundos / 31557600:,.0f} años"

def calcular_chi_cuadrado(texto: str) -> float:
    # Calcula la estadística Chi-Cuadrado para comparar el histograma del texto con las frecuencias teóricas del español.
    longitud = len(texto)
    if longitud == 0: return float('inf')

    # Conteo rápido de caracteres
    conteo = {letra: 0 for letra in ALFABETO}
    for char in texto:
        if char in conteo:
            conteo[char] += 1

    chi_sq = 0.0
    for letra in ALFABETO:
        observado = conteo[letra]
        esperado = (FRECUENCIAS_ESP[letra] / 100) * longitud
        if esperado > 0:
            chi_sq += ((observado - esperado) ** 2) / esperado
        elif observado > 0:
            # Si la letra aparece pero teóricamente no debería (freq=0) sumamos una penalización alta para descartar esta clave
            chi_sq += 100.0
    return chi_sq


# CRIPTOGRAFÍA Y LÓGICA

def worker_ataque_estadistico(args: Tuple[int, str]):
    # El ranking no garantiza corrección, solo plausibilidad estadística
    # Analiza una longitud específica de clave usando aritmética módulo 26.
    longitud, texto_cifrado = args
    # Solo caracteres válidos A-Z
    texto_limpio = normalizar_texto(texto_cifrado)

    clave_construida = ""
    chi_columnas = []

    # Análisis por columnas (aritmética modular)
    for i in range(longitud):
        columna = texto_limpio[i::longitud]
        if not columna: return None

        # Convertimos la columna a índices (0-25)
        columna_idx = [CHAR_TO_IDX[c] for c in columna]
        mejor_chi = float('inf')
        mejor_letra = 'A'

        # Probamos los 26 desplazamientos posibles
        for k in range(LEN_ALFA):
            # Descifrado César para la columna: (Cipher - Key) % 26
            texto_descifrado_indices = [(c - k) % LEN_ALFA for c in columna_idx]
            # Reconstruimos texto para el Chi-Cuadrado
            txt_dec = "".join([ALFABETO[idx] for idx in texto_descifrado_indices])

            score = calcular_chi_cuadrado(txt_dec)
            if score < mejor_chi:
                mejor_chi = score
                mejor_letra = ALFABETO[k]

        clave_construida += mejor_letra
        chi_columnas.append(mejor_chi)

    # Score de la clave: media del Chi-Cuadrado de sus columnas, para poder comparar claves de distinta longitud
    score_medio = sum(chi_columnas) / longitud
    texto_cand = descifrar_vigenere(texto_limpio, clave_construida)
    return (score_medio, clave_construida, texto_cand)

def descifrar_y_puntuar(texto_ints: List[int], clave_ints: List[int]) -> Tuple[float, str]:
    # Descifra el texto con una clave candidata y lo puntúa. Es lo que hace la fuerza bruta con cada clave
    # y lo que mide el benchmark, así las estimaciones del benchmark corresponden al ataque real.
    longitud = len(clave_ints)
    dec_chars = []
    for i in range(len(texto_ints)):
        val = (texto_ints[i] - clave_ints[i % longitud]) % 26
        dec_chars.append(ALFABETO[val])

    texto_plano = "".join(dec_chars)
    return calcular_chi_cuadrado(texto_plano), texto_plano

def worker_fuerza_bruta(args: Tuple[str, int, str]) -> List[Tuple[float, str, str]]:

    # Evita cargar todas las combinaciones en memoria.
    letras_inicio, longitud, texto_cifrado_raw = args
    texto_cifrado_norm = normalizar_texto(texto_cifrado_raw)

    mejores_locales = []
    TOP_K = 10

    # Pre-cálculo a enteros para velocidad
    texto_ints = [ord(c) - 65 for c in texto_cifrado_norm]

    # Iteramos sobre el prefijo asignado a este proceso
    for letra_inicial in letras_inicio:
        if longitud == 1:
            iterador_resto = [("",)]
        else:
            iterador_resto = itertools.product(ALFABETO, repeat=longitud - 1)

        for resto in iterador_resto:
            clave_intento = letra_inicial + "".join(resto)

            # Conversión rápida de clave a ints
            clave_ints = [ord(c) - 65 for c in clave_intento]
            score, texto_plano = descifrar_y_puntuar(texto_ints, clave_ints)

            # Mantenimiento de la lista de mejores resultados
            if len(mejores_locales) < TOP_K:
                mejores_locales.append((score, clave_intento, texto_plano))
                mejores_locales.sort(key=lambda x: x[0])
            elif score < mejores_locales[-1][0]:
                mejores_locales.pop()
                mejores_locales.append((score, clave_intento, texto_plano))
                mejores_locales.sort(key=lambda x: x[0])

    return mejores_locales

TEXTO_BENCHMARK = (
    "ESTO ES UN TEXTO DE PRUEBA PARA MEDIR LA VELOCIDAD DE TU PROCESADOR AL DESCIFRAR TEXTOS "
    "CIFRADOS CON EL CIFRADO SIMÉTRICO VIGENÈRE, EL CUAL YA ESTÁ OBSOLETO"
)

def worker_benchmark(segundos: float) -> int:
    # Prueba claves durante 'segundos' con el mismo código que la fuerza bruta y devuelve cuántas ha probado.
    # El tiempo se cuenta dentro del proceso, así no se mide lo que tarda en arrancar.
    texto_ints = [ord(c) - 65 for c in normalizar_texto(TEXTO_BENCHMARK)]
    probadas = 0
    fin = time.perf_counter() + segundos
    for clave in itertools.cycle(itertools.product(range(LEN_ALFA), repeat=4)):
        descifrar_y_puntuar(texto_ints, list(clave))
        probadas += 1
        if probadas % 64 == 0 and time.perf_counter() >= fin:
            return probadas


# MULTIPROCESSING

def ataque_estadistico_multiproceso(texto_cifrado: str, max_len_clave: int = 20):
    print(f"\n[*] [MULTIPROCESO] Analizando frecuencias con {NUM_PROCESOS} procesos...")
    inicio = time.time()

    # Con menos de 2 letras por columna no hay estadística posible
    limite = min(max_len_clave, len(normalizar_texto(texto_cifrado)) // 2)
    tareas = [(i, texto_cifrado) for i in range(1, limite + 1)]

    with multiprocessing.Pool(processes=NUM_PROCESOS) as pool:
        resultados = pool.map(worker_ataque_estadistico, tareas)

    candidatos = [r for r in resultados if r is not None]
    candidatos.sort(key=lambda x: x[0])
    print(f"[*] Completado en {formatear_tiempo(time.time() - inicio)}.")
    if not candidatos:
        return None, []

    # Las claves largas se ajustan mejor a las frecuencias aunque no tengan sentido (cada columna tiene menos letras),
    # así que el menor score no basta: la mejor apuesta es la clave más corta con un score cercano al mínimo
    cercanos = [c for c in candidatos if c[0] <= candidatos[0][0] * 1.5]
    mejor = min(cercanos, key=lambda c: len(c[1]))
    return mejor, candidatos

def ataque_fuerza_bruta_multiproceso(texto_cifrado: str, longitud_maxima: int):
    print(f"\n[*] [FUERZA BRUTA MULTINÚCLEO] Iniciando con {NUM_PROCESOS} procesos...")
    inicio_total = time.time()

    mejores_globales = []

    for longitud_actual in range(1, longitud_maxima + 1):
        print(f" > Probando claves de longitud {longitud_actual}...", end="", flush=True)
        inicio_nivel = time.time()

        # Repartimos las 26 letras iniciales entre los procesos disponibles
        letras_split = [ALFABETO[i::NUM_PROCESOS] for i in range(NUM_PROCESOS)]

        tareas = []
        for lote_letras in letras_split:
            tareas.append((lote_letras, longitud_actual, texto_cifrado))

        with multiprocessing.Pool(processes=NUM_PROCESOS) as pool:
            resultados_listas = pool.map(worker_fuerza_bruta, tareas)

        todos_candidatos = []
        for lista in resultados_listas:
            todos_candidatos.extend(lista)

        todos_candidatos.sort(key=lambda x: x[0])
        mejores_globales.extend(todos_candidatos[:10])
        mejores_globales.sort(key=lambda x: x[0])
        mejores_globales = mejores_globales[:10]

        print(f" [Hecho en {formatear_tiempo(time.time() - inicio_nivel)}]")

    print(f"[*] Fuerza bruta terminada en {formatear_tiempo(time.time() - inicio_total)}")
    return mejores_globales

def ejecutar_benchmark_multiproceso():
    print("\n==========================================")
    print(f"   BENCHMARK MULTIPROCESO ({NUM_PROCESOS} núcleos)")
    print("==========================================")

    segundos = 2.0
    letras = len(normalizar_texto(TEXTO_BENCHMARK))
    print(f"[Running] Probando claves durante {segundos:.0f} segundos (texto de {letras} letras)...")

    with multiprocessing.Pool(processes=NUM_PROCESOS) as pool:
        claves_probadas = sum(pool.map(worker_benchmark, [segundos] * NUM_PROCESOS))

    velocidad = claves_probadas / segundos

    print("\n--- RESULTADOS DEL BENCHMARK ---")
    print(f"[*] Claves probadas: {claves_probadas:,}")
    print(f"[*] Velocidad: {velocidad:,.0f} claves/seg")

    print("\n--- PROYECCIÓN (Fuerza Bruta Multinúcleo) ---")
    print(f"{'LARGO':<5} | {'COMBINACIONES':<15} | {'TIEMPO ESTIMADO'}")
    print("-" * 65)

    for l in range(1, 9):
        total = 26 ** l
        est = total / velocidad
        print(f" {l:<4} | {total:<15,} | {formatear_tiempo(est)}")
    print("-" * 65)
    print("[*] El tiempo real crece con la longitud del texto: aquí se mide con uno de "
          f"{letras} letras.")
    input("\nENTER para volver...")


# PARTE VISUAL Y LÓGICA DE USUARIO

def dibujar_histograma(texto: str):
    texto = normalizar_texto(texto)
    total = len(texto)
    if total == 0: return

    print("\n" + "▒" * 60)
    print(f" VISUALIZACIÓN DE FRECUENCIAS (Total: {total} letras)")
    print("▒" * 60)
    print(f"{'LETRA':<5} | {'REAL':<8} | {'TEÓRICO':<8} | GRÁFICO (█=Real, |=Español)")
    print("-" * 60)

    for letra in ALFABETO:
        count = texto.count(letra)
        real_pct = (count / total) * 100
        esp_pct = FRECUENCIAS_ESP.get(letra, 0)
        len_bar = int(real_pct * 1.5)
        barra = "█" * len_bar
        len_marker = int(esp_pct * 1.5)
        if len_marker > len_bar:
            barra = barra + " " * (len_marker - len_bar - 1) + "|"
        elif len_marker < len_bar:
            barra = barra[:len_marker] + "|" + barra[len_marker + 1:]
        print(f"  {letra}   | {real_pct:5.2f}%  | {esp_pct:5.2f}%  | {barra}")
    print("-" * 60 + "\n")

def cifrar_vigenere(texto: str, clave: str) -> str:
    clave_limpia = normalizar_texto(clave)
    if not clave_limpia: return texto

    indices_clave = [CHAR_TO_IDX[c] for c in clave_limpia]
    resultado = []
    indice_clave_actual = 0

    for car in texto:
        car_norm = normalizar_texto(car)
        if car_norm and car_norm in CHAR_TO_IDX:
            idx_texto_plano = CHAR_TO_IDX[car_norm]
            desplazamiento = indices_clave[indice_clave_actual % len(indices_clave)]

            # Cifrado: (P + K) % 26
            idx_cifrado = (idx_texto_plano + desplazamiento) % LEN_ALFA

            nuevo_caracter = ALFABETO[idx_cifrado]

            if car.isupper():
                resultado.append(nuevo_caracter)
            else:
                resultado.append(nuevo_caracter.lower())

            indice_clave_actual += 1
        else:
            resultado.append(car)

    return "".join(resultado)

def descifrar_vigenere(texto: str, clave: str) -> str:
    clave_limpia = normalizar_texto(clave)
    if not clave_limpia: return texto

    indices_clave = [CHAR_TO_IDX[c] for c in clave_limpia]
    resultado = []
    indice_clave_actual = 0

    for car in texto:
        car_norm = normalizar_texto(car)
        if car_norm and car_norm in CHAR_TO_IDX:
            idx_cifrado = CHAR_TO_IDX[car_norm]
            desplazamiento = indices_clave[indice_clave_actual % len(indices_clave)]

            # Descifrado: (C - K) % 26
            idx_plano = (idx_cifrado - desplazamiento) % LEN_ALFA

            nuevo_caracter = ALFABETO[idx_plano]

            if car.isupper():
                resultado.append(nuevo_caracter)
            else:
                resultado.append(nuevo_caracter.lower())

            indice_clave_actual += 1
        else:
            resultado.append(car)

    return "".join(resultado)


# MAIN

def main():
    multiprocessing.freeze_support()
    # Si la consola no admite algún carácter del dibujo (█, ▒, ʎ...), se sustituye en vez de dar error
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    print(ASCII_ART)
    print(f"[*] Se han detectado {multiprocessing.cpu_count()} núcleos.")
    print(f"[*] Se usarán {NUM_PROCESOS} núcleos.")
    print("[*] Trabajando con alfabeto estándar (26 letras, Ñ->N).")

    while True:
        print("\n==========================================")
        print("   VIGENÈRE DIDACTIC TOOL")
        print("==========================================")
        print("1. Cifrar mensaje")
        print("2. Descifrar")
        print("3. Ataque estadístico")
        print("4. Ataque fuerza bruta")
        print("5. Benchmark")
        print("6. Salir")
        print("==========================================")

        opcion = input("Opción: ").strip()

        if opcion == "1":
            mensaje_usuario = input("Texto a cifrar:\n ")
            clave_usuario = input("\nClave: ")
            if not normalizar_texto(clave_usuario):
                print("[!] La clave necesita al menos una letra.")
                continue
            print(f"Resultado: {cifrar_vigenere(mensaje_usuario, clave_usuario)}")

        elif opcion == "2":
            msg = input("Cifrado:\n ")
            key = input("\nClave: ")
            if not normalizar_texto(key):
                print("[!] La clave necesita al menos una letra.")
                continue
            print(f"Resultado: {descifrar_vigenere(msg, key)}")

        elif opcion == "3":
            print("[*] Es probable que el ataque falle si el texto es corto o no tiene la frecuencia estándar del español")
            msg = input("Texto cifrado: ")
            if len(normalizar_texto(msg)) < MIN_LETRAS_ESTADISTICO:
                print(f"[!] Texto muy corto para análisis estadístico (mínimo {MIN_LETRAS_ESTADISTICO} letras).")
                continue
            mejor, ranking = ataque_estadistico_multiproceso(msg)

            if not ranking:
                print("[!] No se encontraron candidatos.")
            else:
                print(f"\n[+] Clave más probable: {mejor[1]} (score {mejor[0]:.2f})")
                print(f"[+] Texto: {mejor[2][:70]}...")

                print(f"\n{'SCORE':<10} | {'CLAVE':<20} | {'TEXTO'}")
                print("-" * 75)
                for s, k, t in ranking[:5]:
                    print(f"{s:<10.2f} | {k:<20} | {t[:40]}...")
                print("[*] Las claves largas puntúan algo mejor aunque no tengan sentido;")
                print("    por eso se elige la más corta con un score cercano al mínimo.")

                print("\n[+] Histograma de la clave más probable:")
                dibujar_histograma(mejor[2])
            input("ENTER para volver...")

        elif opcion == "4":
            msg = input("Texto cifrado: ")
            if len(normalizar_texto(msg)) < MIN_LETRAS_FUERZA_BRUTA:
                print(f"[!] Texto muy corto (mínimo {MIN_LETRAS_FUERZA_BRUTA} letras).")
                continue
            try:
                entrada = input("Longitud máxima a probar (cuidado con >5): ")
                l_max = int(entrada) if entrada else 4
                if l_max < 1: raise ValueError
            except ValueError:
                print("[!] Entrada inválida. Usando valor por defecto: 4")
                l_max = 4

            ranking = ataque_fuerza_bruta_multiproceso(msg, l_max)

            print(f"\n{'SCORE':<10} | {'CLAVE':<10} | {'TEXTO'}")
            print("-" * 60)
            for s, k, t in ranking[:5]:
                print(f"{s:<10.2f} | {k:<10} | {t[:40]}...")

            if ranking:
                print("\n[+] Histograma del MEJOR resultado:")
                dibujar_histograma(ranking[0][2])
            input("ENTER para volver...")

        elif opcion == "5":
            ejecutar_benchmark_multiproceso()

        elif opcion == "6":
            break

        else:
            print("[!] Opción no válida.")

if __name__ == "__main__":
    main()
