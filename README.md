<div align="center">

<img src="images/_i.png" width=400>

<h1>SJF-Server</h1>

**Servidor propio y protocolo reconstruido por ingeniería inversa para Sonic Jump Fever**

</div>

---

**SJF-Server** es un servidor comunitario y una reconstrucción del protocolo de red de **Sonic Jump Fever** (Sega, 2014), el juego móvil descontinuado cuyos servidores oficiales cerraron en **2018**.

Este proyecto nace de la ingeniería inversa del tráfico original y tiene como objetivo **revivir la experiencia online** del juego, permitiendo a los jugadores volver a conectarse a un servidor funcional.

<img src="images/tryToConnectingServer" height=20>

Anteriormente **Sonic Jump Fever** debía conetarse con a un servidor privativo de SEGA la cual se sincronizaba con el juego para actualizar rondas y cambios de ZONA (como `green_hill_zone`, `jungle_zone`, `blue_sky_zone` y `mechanical_zone`) en un tiempo determinado y recibir recompensas a traves de logros.

<img src="images/currentZone" height=20>
<img src="images/nextZone" height=20>

La comunicación entre **SJF-Server** y el juego está hecha en Node.js y esto se logró parcheando el archivo `sonicjumpfever.so` del APK original ubicado en `lib/arm64-v8a`, `lib/armeabi`, `armeabi-v7a` (según la arquitectura), y se cambió la dirección URL del servidor (anteriormente era `https://prod.server.sjf.hla.sega.co.uk:8443/SJF23`) por una dirección a una IP local del PC para ver el tráfico y peticiones que hacía en la red.

> El parche del `.so` fue realizada con la ultima versión del juego lanzado el 31 de marzo de 2017, la cual fué la `1.6.1`.

En la carpeta `_tools/` encontrarán scripts de automatización que facilitaron la descompilación y modificación de los archivos del juego, entre las más importantes:

- `patch_so.py`: cambia la URL del servidor original en el `.so` por una diferente que indiques a la que se comunicará con el juego.
- `sla.py`: Extrae contenido en los archivos `.sla`, y en `settings.sla` extrae archivos `.json` y `.xml`. Este `settings.sla` es la configuración predeterminada de valores globales del juego.
- `apk_build.py`: Reempaqueta la aplicación con los cambios aplicados.
- `a64xref.py`: Ver referencias en los binarios `.so`.
- `a64func.py`: Buscador de cadenas específicas en el binario.

## ¿Cómo funciona el servidor?

El servidor está escrito en **Node.js** con **Express** y actúa como reemplazo del backend original de SEGA. Al iniciar carga su configuración desde `config.json` y queda escuchando en el puerto **8443**, bajo la ruta base **`/SJF23`** (la misma que usaba el juego original).

La comunicación es **JSON plano**: tanto las peticiones como las respuestas son objetos JSON en la raíz, sin ningún envoltorio. El flujo que sigue el juego es:

1. **`Handshake.json`** — Autenticación por reto-respuesta.
2. **`Connect.json`** — Inicio de sesión del jugador.
3. **`GetSettings.json`** — Obtención de la configuración y la zona activa.
4. **`GetProfile.json`** — Sincronización del progreso del jugador.

### Handshake (reto-respuesta HMAC-SHA256)

El juego envía `{ version, cid }`, donde `cid` es un entero de 64 bits. El servidor:

- Genera un valor aleatorio `R` de 64 bits.
- Calcula `M = (R * MULT mod 2^64) XOR cid`.
- Construye `challenge = HMAC-SHA256(clave, u64le(cid) ‖ u64le(M)) ‖ u64le(R) ‖ relleno` (42 bytes en total) y lo devuelve en Base64 junto a un `challengeToken`.

El cliente recalcula el HMAC y lo compara con los primeros 32 bytes del reto. La clave y la constante `MULT` (`0xBDC70E445308C215`) se obtuvieron del binario `sonicjumpfever.so` (ver `test-handshake.js`).

### Endpoints

| Endpoint | Función |
|---|---|
| `POST /Handshake.json` | Reto-respuesta inicial |
| `POST /Connect.json` | Login y entrega de `accessToken`, `serverSettings`, etc. |
| `POST /GetSettings.json` | Configuración del servidor y zona activa |
| `POST /GetProfile.json` | Estado sincronizado del jugador |
| `POST /PushProfile.json` | Subida de progreso |
| `POST /GetScores.json` / `PostScore.json` | Tablas de puntuación |
| `POST /GetFriends.json` / `InviteFriend.json` | Amigos |
| `POST /GetMessages.json` / `DeleteMessages.json` | Mensajes |
| `POST /SendGift.json` / `RequestEnergy.json` | Regalos y energía |
| `POST /LogIAP.json` / `AwardRequestItem.json` | Compras y recompensas |

Los endpoints de progreso, puntuaciones, amigos, mensajes, regalos, energía y compras son por ahora **marcadores de posición**: responden `{ "status": 0 }` junto al `accessToken` configurado, a la espera de implementar su lógica completa.

### Sistema de rondas y zonas

El objeto `serverSettings` es el que decide **qué zona está activa**. Incluye `serverTime`, `currentZone`, `nextZone`, `previousZone`, `expiryTime` y los IDs de ronda.

- Cada ronda dura **5 minutos**.
- Al expirar, el servidor rota automáticamente entre las zonas: `mechanical_zone → blue_sky_zone → green_hill_zone → jungle_zone`.
- El estado se mantiene coherente entre peticiones y el tiempo de inicio se avanza en múltiplos exactos para no acumular desfase.

### Configuración

`config.json` se lee al arrancar y controla:

- `port` y `host`: dónde escucha el servidor.
- `apiBase`: ruta base (`/SJF23`).
- `currentZone`, `nextZone`, `previousZone`: zonas iniciales.
- `currentRoundId`, `nextRoundId`, `previousRoundId`: IDs de ronda.
- `accessToken`: token devuelto a los clientes.
- `settingsUri`: URI de configuración (si está vacía se usa `apiBase + /GetSettings.json`).

### Puesta en marcha

```bash
npm install
node server.js
```

Para comprobar el funcionamiento:

```bash
node test-handshake.js   # valida el algoritmo HMAC
node test-client.js      # simula la secuencia completa del juego
```

<div align="center">
  <img src="images/Screenshot_01.jpg" height=420>
</div>
