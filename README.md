<div align="center">

<img src="images/_i.png" width=400>

<h1>SJF-Server</h1>

**Servidor propio y protocolo reconstruido por ingeniería inversa para Sonic Jump Fever**

</div>

---

**SJF-Server** es un servidor comunitario y una reconstrucción del protocolo de red de **Sonic Jump Fever** (Sega, 2014), el juego móvil descontinuado cuyos servidores oficiales cerraron en **2018**.

Este proyecto nace de la ingeniería inversa del tráfico original y tiene como objetivo **revivir la experiencia online** del juego, permitiendo a los jugadores volver a conectarse a un servidor funcional.

Anteriormente **Sonic Jump Fever** debía conetarse con a un servidor privativo de SEGA la cual se sincronizaba con el juego para actualizar rondas y cambios de ZONA (como `green_hill_zone`, `jungle_zone`, `blue_sky_zone` y `mechanical_zone`) en un tiempo determinado y recibir recompensas a traves de logros.

La comunicación entre **SJF-Server** y el juego está hecha en Node.js y esto se logró parcheando el archivo `sonicjumpfever.so` del APK original ubicado en `lib/arm64-v8a`, `lib/armeabi`, `armeabi-v7a` (según la arquitectura), y se cambió la dirección URL del servidor (anteriormente era `https://prod.server.sjf.hla.sega.co.uk:8443/SJF23`) por una dirección a una IP local del PC para ver el tráfico y peticiones que hacía en la red.

> El parche del `.so` fue realizada con la ultima versión del juego lanzado el 31 de marzo de 2017, la cual fué la `1.6.1`.

En la carpeta `_tools/` encontrarán scripts de automatización que facilitaron la descompilación y modificación de los archivos del juego, entre esos archivos incluyendo la que parcheó el `.so`, algunas importantes:

- `patch_so.py`: modificar la dirección del servidor original en el `.so` por una diferente a la que se comunicará con el juego.
- `sla.py`: extrae contenido en los archivos `.sla`, y JSON en `settings.sla` (que es uilizado para configurar valores globales del juego).
- `apk_build.py`: reempaqueta la aplicación con los cambios aplicados.
