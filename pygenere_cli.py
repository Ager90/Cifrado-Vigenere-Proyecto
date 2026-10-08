import itertools
import time
import unicodedata
import multiprocessing
from typing import List, Tuple


# CONSTANTES Y CONFIGURACIÓN 

NUM_PROCESOS = max(1, multiprocessing.cpu_count() // 4) # Usa un cuarto de los núcleos (redondeado abajo), siendo el número mínimo 1
# Se puede sustituir max(1, multiprocessing.cpu_count() // 4) con el número de nucleos que se quiere usar

# Frecuencias estándar del español (Sin Ñ propia, normalizada dentro de N o ignorada)
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
    Elimina acentos, diacríticos y caracteres no alfabéticos.
    Convierte todo a mayúsculas y maneja unicode (ej: Ñ -> N).
    """
    if not texto: return ""
    texto_normalizado = unicodedata.normalize('NFD', texto)
    res = "".join(c for c in texto_normalizado if unicodedata.category(c) != 'Mn' and c.isalpha())
    return res.upper()

def formatear_tiempo(segundos: float) -> str:
    if segundos < 60: return f"{segundos:.4f} seg"
    if segundos < 3600: return f"{segundos / 60:.2f} min"
    return f"{segundos / 3600:.2f} horas"

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
    # Analiza una longitud específica de clave usando aritmética Módulo 26.
    longitud, texto_cifrado = args
    # Solo caracteres válidos A-Z
    texto_limpio = [c for c in normalizar_texto(texto_cifrado)] 
    
    clave_construida = ""
    
# Análisis por columnas (aritmética modular)
    for i in range(longitud):
        columna = texto_limpio[i::longitud]
        if not columna: break
        
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

    if len(clave_construida) == longitud:
        try:
            # Validación final del candidato
            # Desciframos con la clave encontrada para ver el score global
            idx_clave = [CHAR_TO_IDX[c] for c in clave_construida]
            idx_texto = [CHAR_TO_IDX[c] for c in texto_limpio]
            
            res_idx = []
            for j, val_c in enumerate(idx_texto):
                val_k = idx_clave[j % len(idx_clave)]
                res_idx.append((val_c - val_k) % LEN_ALFA)
            
            texto_cand = "".join([ALFABETO[x] for x in res_idx])
            
            score_final = calcular_chi_cuadrado(texto_cand)
            return (score_final, clave_construida, texto_cand)
        except Exception:
            return None
    return None

def worker_fuerza_bruta(args: Tuple[str, int, str]) -> List[Tuple[float, str, str]]:

    # Evita cargar todas las combinaciones en memoria.
    letras_inicio, longitud, texto_cifrado_raw = args
    texto_cifrado_norm = normalizar_texto(texto_cifrado_raw) 
    
    mejores_locales = []
    TOP_K = 10
    
    # Pre-cálculo a enteros para velocidad
    texto_ints = [ord(c) - 65 for c in texto_cifrado_norm]
    len_txt = len(texto_ints)
    
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
            
            # Descifrado INLINE optimizado
            dec_chars = []
            for i in range(len_txt):
                val = (texto_ints[i] - clave_ints[i % longitud]) % 26
                dec_chars.append(ALFABETO[val])
            
            texto_plano = "".join(dec_chars)
            score = calcular_chi_cuadrado(texto_plano)
            
            # Mantenimiento del heap/lista de mejores resultados
            if len(mejores_locales) < TOP_K:
                mejores_locales.append((score, clave_intento, texto_plano))
                mejores_locales.sort(key=lambda x: x[0])
            elif score < mejores_locales[-1][0]:
                mejores_locales.pop()
                mejores_locales.append((score, clave_intento, texto_plano))
                mejores_locales.sort(key=lambda x: x[0])
                
    return mejores_locales
    
def worker_benchmark(iteraciones):
    # Realiza un bucle de descifrado 'iteraciones' veces con carga realista.
    texto_dummy = "ESTO ES UN TEXTO DE PRUEBA PARA MEDIR LA VELOCIDAD DE TU PROCESADOR PARA DESCIFRAR TEXTOS CIFRADOS CON EN EL CIFRADO SIMÉTRICO VIGENÈRE, EL CUAL YA ESTA OBSOLETO"
    clave = "TEST"
    for _ in range(iteraciones):
        descifrar_vigenere(texto_dummy, clave)
    return iteraciones



# MULTIPROCESING

def ataque_estadistico_multiproceso(texto_cifrado: str, max_len_clave: int = 20):
    print(f"\n[*] [MULTIPROCESO] Analizando frecuencias con {NUM_PROCESOS} procesos...")
    inicio = time.time()
    
    tareas = [(i, texto_cifrado) for i in range(1, max_len_clave + 1)]
    
    with multiprocessing.Pool(processes=NUM_PROCESOS) as pool:
        resultados = pool.map(worker_ataque_estadistico, tareas)
    
    candidatos = [r for r in resultados if r is not None]
    candidatos.sort(key=lambda x: x[0])
    
    print(f"[*] Completado en {time.time() - inicio:.4f} segundos.")
    return candidatos

def ataque_fuerza_bruta_multiproceso(texto_cifrado: str, longitud_maxima: int):
    print(f"\n[*] [FUERZA BRUTA MULTI-CORE] Iniciando con {NUM_PROCESOS} procesos...")
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
        
        print(f" [Hecho en {time.time() - inicio_nivel:.2f}s]")

    print(f"[*] Fuerza bruta terminada en {formatear_tiempo(time.time() - inicio_total)}")
    return mejores_globales

def ejecutar_benchmark_multiproceso():
    print("\n==========================================")
    print(f"   BENCHMARK MULTIPROCESO ({NUM_PROCESOS} nucleos)      ")
    print("==========================================")
    
    carga_total = 400000 
    carga_por_proceso = carga_total // NUM_PROCESOS
    
    print(f"[Running] Ejecutando {carga_total:,} ciclos cifrado...")
    
    inicio = time.time()
    with multiprocessing.Pool(processes=NUM_PROCESOS) as pool:
        pool.map(worker_benchmark, [carga_por_proceso] * NUM_PROCESOS)
    fin = time.time()
    
    tiempo_total = fin - inicio
    if tiempo_total == 0: tiempo_total = 0.0001
    velocidad = carga_total / tiempo_total
    
    print("\n--- RESULTADOS DEL BENCHMARK ---")
    print(f"[*] Tiempo total: {tiempo_total:.4f} s")
    print(f"[*] Velocidad relativa: {velocidad:,.0f} ops/seg")

    print("\n--- PROYECCIÓN (Fuerza Bruta Multi-Core) ---")
    print(f"{'LARGO':<5} | {'COMBINACIONES':<15} | {'TIEMPO ESTIMADO'}")
    print("-" * 65)
    
    for l in range(1, 9):
        total = 26 ** l
        est = total / velocidad
        print(f" {l:<4} | {total:<15,} | {formatear_tiempo(est)}")
    print("-" * 65)
    input("\nENTER para volver...")



# PARTE VISUAL Y LÓGICA DE USUARIO

def dibujar_histograma(texto: str):
    texto = normalizar_texto(texto)
    total = len(texto)
    if total == 0: return

    print("\n" + "▒" * 60)
    print(f" VISUALIZACIÓN DE FRECUENCIAS (Total: {total} chars)")
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
        elif len_marker < len_bar and len_marker < len(barra):
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
    
    print(ASCII_ART)
    print(f"[*] Se han detectado {multiprocessing.cpu_count()} núcleos.")
    print(f"[*] Se usaran {NUM_PROCESOS} núcleos.")
    print(f"[*] Trabajando con alfabeto estándar (26 letras, Ñ->N).")

    while True:
        print("\n==========================================")
        print("   VIGENÈRE DIDACTIC TOOL    ")
        print("==========================================")
        print("1. Cifrar Mensaje ")
        print("2. Descifrar ")
        print(f"3.  Ataque Estadístico  ")
        print(f"4.  Ataque Fuerza Bruta ")
        print(f"5. Benchmark ")
        print("6. Salir")
        print("==========================================")
        
        opcion = input("Opción: ")

        if opcion == "1":
            try:
                mensaje_usuario = input("Texto a cifrar:\n ")
                clave_usuario = input("\nClave: ")
                print(f"Resultado: {cifrar_vigenere(mensaje_usuario, clave_usuario)}")
            except Exception as e: print(e)

        elif opcion == "2":
            try:
                msg = input("Cifrado:\n ")
                key = input("\nClave: ")
                print(f"Resultado: {descifrar_vigenere(msg, key)}")
            except Exception as e: print(e)

        elif opcion == "3":
            print("[*] Es probable que el ataque falle si el texto es corto o no tiene la frecuencia estandar del español")
            msg = input("Texto cifrado: ")
            if len(msg) < 15:
                print("[!] Texto muy corto para análisis estadístico.")
                continue
            ranking = ataque_estadistico_multiproceso(msg)

            if not ranking:
                print("[!] No se encontraron candidatos.")
            else:
                print(f"\n{'SCORE':<10} | {'CLAVE':<15} | {'TEXTO'}")
                print("-" * 70)
                for s, k, t in ranking[:5]:
                    print(f"{s:<10.2f} | {k:<15} | {t[:50]}...")
                
                print("\n[+] Histograma del MEJOR resultado:")
                dibujar_histograma(ranking[0][2])
            input("ENTER para volver...")

        elif opcion == "4":
            msg = input("Texto cifrado: ")
            try:
                entrada = input("Longitud máxima a probar (cuidado con >5): ")
                l_max = int(entrada) if entrada else 4
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

if __name__ == "__main__":
    main()
