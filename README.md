# Cifrado Vigenere Proyecto
Script de Python creado para un proyecto en Matematica Discreta sobre el cifrado Vigenère. No solo permite cifrar y descifrar mensajes, sino que incluye herramientas de criptoanálisis para romper el cifrado sin conocer la clave, utilizando estadística y fuerza bruta. 

---
## Explicación básica de las 5 opciones

* **Opción 1: Cifrar Mensaje**
* `cifrar_vigenere` Toma el mensaje y la clave, limpia ambos de caracteres raros y realiza la suma matemática (Módulo 26) para ocultar el texto.
$$C_i \equiv (P_i + K_{i \mod m}) \pmod{26}$$
<br><br>

* **Opción 2: Descifrar**
* `descifrar_vigenere` Realiza la operación inversa a la opción 1. Resta la clave al mensaje cifrado para recuperar el original. Requiere que se conozca la clave correcta de antemano.
$$P_i \equiv (C_i - K_{i \mod m}) \pmod{26}$$
<br><br>

* **Opción 3: Ataque Estadístico**
* `ataque_estadistico_multiproceso` En vez de probar claves al azar. Divide el texto en columnas y usa estadística para deducir cuál es la clave más probable ( Al ser multiproceso y multinucleo, analiza varias longitudes de clave posibles al mismo tiempo.).
* Para esto el script utiliza el Test de Chi-Cuadrado ($\chi^2$). Compara la distribución de frecuencias del texto descifrado con una clave candidata frente a las frecuencias teóricas del idioma español.

$$\chi^2 = \sum_{i=A}^{Z} \frac{(O_i - E_i)^2}{E_i}$$
<br><br>

* **Opción 4: Ataque Fuerza Bruta**
* `ataque_fuerza_bruta_multiproceso` Prueba todas las combinaciones posibles (AAAA, AAAB...) de la longitud que el usuario indique y le marca al usuario las claves mas probables. Divide el abecedario entre los nucleos seleccionados.
* El número total de claves a verificar ($N$) crece exponencialmente y es lo que define la complejidad del ataque.
$$N = 26^L$$
<br><br>

* **Opción 5: Benchmark**
* `ejecutar_benchmark_multiproceso` Pone a todos los núcleos indicados de la CPU a descifrar textos de prueba simultáneamente para medir cuántas operaciones por segundo es capaz de realizar el ordenador. Da una estimación de cuánto tardarías en romper un texto cifrado con este algoritmo segun la longitud de la clave.
* El tiempo necesario $T$ para romper una clave crece exponencialmente respecto a su longitud $L$. Calculando la velocidad de la CPU ($\rho$), estimamos:
$$T(L) \approx \frac{26^L}{\rho}$$
