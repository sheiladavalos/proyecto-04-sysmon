# Proyecto 04: Detección y análisis de actividad con Sysmon

## 1. Introducción

El presente proyecto tiene como objetivo implementar y utilizar Sysmon (System Monitor), una herramienta de Microsoft Sysinternals que permite registrar información detallada sobre diferentes actividades realizadas en un sistema Windows.

Desde una perspectiva de seguridad informática, el monitoreo de eventos resulta fundamental para identificar comportamientos inusuales, investigar posibles incidentes y recopilar información útil para los equipos SOC (Security Operations Center).

Durante este laboratorio se instaló y configuró Sysmon en un equipo con Windows 10 Pro de 64 bits. Posteriormente, se generaron actividades controladas para observar cómo quedan registradas en los eventos del sistema y analizar la información obtenida.

El trabajo se orientó a la práctica de tareas propias de un perfil SOC / Blue Team, con especial atención a la identificación de procesos, conexiones de red, creación de archivos y modificaciones del Registro de Windows.

Además, se aplicaron procedimientos básicos de preservación de evidencias digitales mediante la exportación de registros y el cálculo de hashes SHA-256.

## 2. Objetivos

- Instalar y configurar Sysmon en Windows.
- Comprender la utilidad de los registros de eventos para la supervisión de seguridad.
- Identificar y analizar eventos específicos mediante sus identificadores (Event ID).
- Generar actividades controladas para observar el comportamiento de Sysmon.
- Registrar y organizar evidencias de las actividades realizadas.
- Calcular y verificar hashes SHA-256 para comprobar la integridad de los archivos recopilados.
- Interpretar los resultados desde una perspectiva de monitoreo y respuesta ante incidentes.

## 3. Entorno y herramientas utilizadas

- Sistema operativo: Windows 10 Pro de 64 bits.
- Herramienta de monitoreo: Sysmon 15.22.
- Esquema de configuración: 4.91.
- Configuración: archivo XML personalizado.
- Consola: Windows PowerShell.
- Visor de eventos: Event Viewer.
- Algoritmo de integridad: SHA-256.

La configuración de Sysmon habilitó el registro de eventos relacionados con creación de procesos, conexiones de red, creación de archivos y actividad del Registro de Windows.

Se utilizó una configuración de laboratorio sin filtros de exclusión para los tipos de eventos seleccionados. Por este motivo, también pueden registrarse actividades normales del sistema operativo y de las aplicaciones.

## 4. Desarrollo del laboratorio

Se instaló Sysmon utilizando el ejecutable `Sysmon64.exe` y el archivo de configuración `sysmon-config.xml`.

Posteriormente, se verificó el funcionamiento del servicio y se consultaron los registros desde la siguiente ubicación:

`Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`

Se trabajó con cuatro tipos de eventos principales: Event ID 1, Event ID 3, Event ID 11 y Event ID 13.

Para algunos eventos fue necesario generar nuevas actividades controladas, ya que los registros anteriores no se encontraban disponibles en el registro activo de Sysmon. Los archivos exportados previamente se conservaron y no fueron sobrescritos.

### 4.1. Event ID 1 – Process Create

Se ejecutó el Bloc de notas (`notepad.exe`) desde PowerShell para generar un evento de creación de proceso.

La evidencia permitió identificar:

- Nombre y ruta del proceso ejecutado.
- Usuario asociado.
- Proceso padre.
- Línea de comandos utilizada.
- Fecha y hora del evento.
- Hash SHA-256 del ejecutable registrado por Sysmon.

**Análisis:**

Este evento permite conocer qué procesos se ejecutan en el equipo y cuál fue el proceso que los inició. En una investigación de seguridad puede ayudar a identificar ejecuciones sospechosas, procesos inesperados o cadenas de ejecución relacionadas con malware.

En este laboratorio, la ejecución de Notepad fue una actividad legítima y controlada.

Se conservaron dos exportaciones:

- `evento_01_notepad.txt`
- `evento_01_notepad_nuevo.txt`

La segunda corresponde a una nueva ejecución de Notepad realizada durante la recuperación de evidencia.

**Captura:** `capturas_publicas/01_evento_proceso.jpeg`

### 4.2. Event ID 3 – Network Connect

Se realizaron pruebas de conectividad de red mediante PowerShell utilizando el comando `Test-NetConnection example.com -Port 443`.

La evidencia inicial permitió observar una conexión TCP hacia el puerto 443, asociada al proceso PowerShell.

Posteriormente, se generó una nueva actividad de red y Sysmon registró conexiones iniciadas por Google Chrome (`chrome.exe`). Entre ellas se identificó tráfico UDP hacia el puerto 443 y tráfico local relacionado con DNS, hacia el puerto 53.

Los registros permitieron identificar:

- Proceso que inició la comunicación.
- Dirección IP de origen y destino.
- Puerto de origen y destino.
- Protocolo utilizado.
- Usuario asociado.
- Indicador de conexión iniciada.

**Análisis:**

Este evento es útil para investigar comunicaciones de red originadas en el equipo. En un entorno SOC permite detectar conexiones hacia destinos inesperados, comunicaciones inusuales y posibles indicadores de actividad maliciosa.

Es importante diferenciar las conexiones observadas: una conexión TCP hacia el puerto 443 y una conexión UDP hacia el mismo puerto no representan necesariamente el mismo tipo de tráfico. Asimismo, el tráfico UDP/443 puede estar relacionado con QUIC, utilizado por navegadores modernos.

Las conexiones registradas durante este laboratorio fueron actividades de prueba y no constituyen por sí solas evidencia de actividad maliciosa.

Se conservaron dos exportaciones:

- `evento_03_red.txt`
- `evento_03_red_nuevo.txt`

**Captura:** `capturas_publicas/02_evento_red.jpeg`

### 4.3. Event ID 11 – File Create

Se crearon dos archivos de prueba dentro de la carpeta de evidencias del proyecto:

- `archivo_prueba.txt`
- `archivo_prueba_02.txt`

La segunda creación se realizó para generar un nuevo evento identificable en el registro activo de Sysmon.

Los eventos permitieron identificar:

- Proceso responsable de la creación.
- Usuario asociado.
- Ruta del archivo creado.
- Fecha y hora de la actividad.

**Análisis:**

Este evento permite monitorear la creación de archivos en el sistema. Puede resultar útil para investigar descargas sospechosas, archivos temporales, posibles herramientas maliciosas o modificaciones inesperadas en directorios sensibles.

En este caso, la creación de ambos archivos fue intencional y se realizó con fines educativos.

Se conservaron dos exportaciones:

- `evento_11_archivo.txt`
- `evento_11_archivo_nuevo.txt`

**Captura:** `capturas_publicas/03_evento_archivo.jpeg`

### 4.4. Event ID 13 – Registry Value Set

Se creó una clave de prueba dentro del Registro del usuario actual:

`HKCU\Software\SysmonLab`

Dentro de ella se estableció el valor `PruebaSysmon`. En la primera actividad se utilizó el contenido `Actividad de laboratorio` y, posteriormente, se actualizó a `Actividad de laboratorio 2` para generar un nuevo evento identificable.

Sysmon registró las modificaciones realizadas sobre el valor del Registro.

**Análisis:**

Este evento es relevante porque determinadas amenazas pueden modificar el Registro de Windows para establecer mecanismos de persistencia, alterar configuraciones o modificar el comportamiento del sistema.

La modificación observada fue controlada y se realizó dentro de una clave creada específicamente para el laboratorio, sin modificar configuraciones críticas de Windows.

Se conservaron dos exportaciones:

- `evento_13_registro.txt`
- `evento_13_registro_nuevo.txt`

**Captura:** `capturas_publicas/04_evento_registro.jpeg`

## 5. Recolecci�n e integridad de evidencias

Los registros obtenidos mediante Sysmon se exportaron a archivos de texto y se conservaron en la carpeta `evidencias` del entorno de trabajo original.

En total, se conservaron ocho exportaciones correspondientes a los eventos ID 1, 3, 11 y 13.

Para su publicaci�n, se prepararon copias anonimizadas de los ocho registros en la carpeta `evidencias_publicas`. Se reemplazaron datos identificatorios como el nombre de usuario, el nombre del equipo, las rutas personales y la direcci�n IP p�blica.

Los archivos originales se conservaron sin modificaciones y por separado, junto con sus respectivos hashes SHA-256, en el entorno local.

Para las copias destinadas a publicaci�n se gener� un manifiesto independiente, ubicado en `evidencias_publicas/hashes_publicas.sha256`.

Los ocho archivos p�blicos fueron verificados individualmente mediante SHA-256 y todos obtuvieron el resultado CORRECTA.

Los hashes permiten detectar modificaciones posteriores respecto del momento de su c�lculo. Sin embargo, no demuestran por s� solos la autenticidad del origen de los registros.

De esta manera, se preservaron los archivos originales y se prepar� un conjunto de evidencias anonimizadas, verificables y aptas para su publicaci�n.

## 6. Aplicación en un entorno SOC / Blue Team

Sysmon proporciona información que puede complementar los registros nativos de Windows y las herramientas de monitoreo de seguridad.

Los eventos analizados tienen aplicaciones concretas:

- **Event ID 1:** seguimiento de procesos y detección de ejecuciones inusuales.
- **Event ID 3:** monitoreo de conexiones de red.
- **Event ID 11:** supervisión de creación de archivos.
- **Event ID 13:** seguimiento de modificaciones en valores del Registro.

En un entorno profesional, estos eventos pueden correlacionarse con otras fuentes de información, como Windows Security Logs, antivirus, EDR y registros de firewall.

La detección de un evento no implica automáticamente la existencia de un incidente. Es necesario analizar el contexto, el usuario, el proceso, el destino de red, la frecuencia y otros indicadores relacionados.

Por ejemplo, una conexión HTTPS puede ser legítima, pero si se origina desde un proceso inesperado o hacia un destino sospechoso, puede requerir una investigación adicional.

## 7. Limitaciones del laboratorio

Las actividades se realizaron en un entorno controlado y con fines educativos.

La configuración utilizada registra los tipos de eventos seleccionados sin aplicar filtros de exclusión específicos, por lo que puede generar un volumen considerable de información.

Además, se trabajó con actividades puntuales y no con un escenario real de compromiso del sistema. Por lo tanto, los resultados permiten demostrar el funcionamiento básico de Sysmon, pero no representan una investigación completa de un incidente de seguridad.

También debe considerarse que los registros activos pueden dejar de contener eventos anteriores. Por este motivo, las exportaciones realizadas durante el laboratorio permitieron conservar información que posteriormente no estaba disponible en el registro activo.

Para proteger la privacidad, las evidencias destinadas a publicación fueron anonimizadas mediante el reemplazo de nombres de usuario, nombre del equipo, rutas personales y dirección IP pública. Los archivos originales se conservaron por separado y no forman parte del conjunto de evidencias públicas.

## 8. Evidencias visuales

Se recopilaron cuatro capturas de pantalla que documentan los principales eventos analizados:

1. `capturas_publicas/01_evento_proceso.jpeg` – Creación de proceso.
2. `capturas_publicas/02_evento_red.jpeg` – Conexión de red.
3. `capturas_publicas/03_evento_archivo.jpeg` – Creación de archivo.
4. `capturas_publicas/04_evento_registro.jpeg` – Modificación del Registro de Windows.

Estas imágenes complementan las exportaciones de eventos y permiten visualizar los registros obtenidos durante las actividades controladas.

## 9. Conclusión

El laboratorio permitió instalar, configurar y utilizar Sysmon para registrar diferentes actividades de un equipo Windows.

A través de los eventos analizados se comprobó cómo es posible obtener información sobre la ejecución de procesos, las conexiones de red, la creación de archivos y las modificaciones del Registro.

También se aplicaron procedimientos básicos de preservación de evidencias mediante la exportación de registros, el cálculo de hashes SHA-256 y su posterior verificación.

La práctica permitió reforzar conocimientos relacionados con monitoreo de endpoints, análisis de eventos, identificación de actividades relevantes y preservación de evidencias digitales.

Estas competencias son importantes para funciones iniciales en SOC, Blue Team y DFIR, donde resulta fundamental recopilar información, interpretar eventos y distinguir entre actividades legítimas y comportamientos que requieren una investigación más profunda.
