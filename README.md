<div align="center">

![logo](images/_i.png)

# SJF-Server

**Servidor propio y protocolo reconstruido por ingeniería inversa para Sonic Jump Fever**

</div>

---

**SJF-Server** es un servidor comunitario y una reconstrucción del protocolo de red de **Sonic Jump Fever** (Sega, 2014), el juego móvil descontinuado cuyos servidores oficiales cerraron en **2018**.

Este proyecto nace de la ingeniería inversa del tráfico original y tiene como objetivo **revivir la experiencia online** del juego, permitiendo a los jugadores volver a conectarse a un servidor funcional.

Anteriormente **Sonic Jump Fever** debía conetarse con a un servidor privativo de SEGA la cual se sincronizaba con el juego para actualizar rondas y cambios de ZONA en un tiempo determinado y recibir recompensas a traves de logros.

La comunicación entre **SJF-Server** y el juego está hecha en Node.js y esto se logró parcheando el archivo `sonicjumpfever.so` del APK original ubicado en `lib/arm64-v8a`, `lib/armeabi`, `armeabi-v7a` (según la arquitectura), y se cambió la dirección URl del servidor (anteriormente era `https://prod.server.sjf.hla.sega.co.uk:8443/SJF23`) por una dirección a una IP local del PC para ver el tráfico de red.
