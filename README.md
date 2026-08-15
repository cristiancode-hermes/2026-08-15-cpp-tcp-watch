# TCP Watch — Monitor de conexiones TCP de Linux (C++23)

`tcp-watch` es un monitor de conexiones TCP del sistema escrito en **C++23** sin dependencias externas. Lee la tabla de sockets del kernel desde `/proc/net/tcp` y `/proc/net/tcp6`, decodifica direcciones IPv4/IPv6 (incluido IPv4-mapped `::ffff:`), resuelve cada socket a su **PID y proceso** escaneando `/proc/*/fd`, y presenta listeners, conexiones activas, puertos más usados y tasas por segundo en modo watch.

## Características

- **Parseo robusto de `/proc/net/tcp` y `/proc/net/tcp6`**: líneas malformadas o cortas se saltan sin romper el resto; tolera los campos extra de kernels modernos (4.1+).
- **Decodificación de direcciones**: IPv4 little-endian (`0100007F` → `127.0.0.1`), IPv6 con compresión `::` y detección de IPv4-mapped (`::ffff:a.b.c.d`), verificado contra `/proc/net/tcp6` real.
- **13 estados TCP** decodificados: LISTEN, ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1/2, TIME_WAIT, CLOSE, CLOSE_WAIT, LAST_ACK, CLOSING, NEW_SYN_RECV.
- **Resolución inode → PID → proceso**: escanea los symlinks `socket:[inode]` en `/proc/*/fd` y lee `/proc/<pid>/comm` (desactivable con `--no-resolve`).
- **Tabla de listeners + conexiones activas** top-N por colas TX+RX (`--top N`), con colores por estado (LISTEN cian, ESTAB verde, TIME_WAIT dim, inestables amarillo, CLOSING rojo).
- **`--ports`**: top-N puertos locales por número de conexiones con desglose por estado.
- **`--state NOMBRE`**: filtra por estado (acepta abreviaturas: ESTAB, TW, LISTEN…).
- **Modo watch en vivo** (`--watch N`): tasas delta por estado (conexiones/s), tiempo transcurrido, limpieza de pantalla y flush (la salida completa sobrevive a timeout/kill).
- **`--demo`**: muestra sintética embebida (listeners, navegadores, curl, sshd, IPv6 real) para contenedores/VMs donde `/proc` está enmascarado — con tasas crecientes en watch.
- **`--json`**: salida completa para scripting (`connections`, `by_state`, `connections_list`, `summary`).
- **`--selftest`**: 33 checks de auto-verificación (decodificación IPv4/IPv6, estados, parseo sintético, agregación, deltas, JSON, demo y smoke test condicional contra el `/proc` real).
- **Cero dependencias**: compilación directa con `g++ -std=c++23`.

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o tcp-watch
```

## Uso

```bash
./tcp-watch                     # snapshot: listeners + top 15 activas + resumen
./tcp-watch --top 8             # top 8 conexiones activas por colas
./tcp-watch --watch 2           # modo live cada 2s con tasas delta por estado
./tcp-watch --ports             # top puertos locales por conexiones
./tcp-watch --state TIME_WAIT   # solo conexiones en TIME_WAIT
./tcp-watch --state ESTAB       # abreviaturas aceptadas
./tcp-watch --json              # JSON completo para scripting
./tcp-watch --demo --top 6      # datos sintéticos (sin /proc real)
./tcp-watch --no-resolve        # sin resolución de procesos (más rápido)
./tcp-watch --no-color          # sin ANSI (pipes/logs)
./tcp-watch --selftest          # 33 auto-checks
```

### Ejemplo de salida

```
TCP WATCH — /proc/net/tcp + tcp6
------------------------------------------------------------------------------
LISTENERS (8)
LOCAL                          STATE        UID    PID  PROCESS       INODE
0.0.0.0:22                     LISTEN        0      812   sshd          3E8B
[::]:22                        LISTEN        0      812   sshd          3E8C
0.0.0.0:80                     LISTEN        0      1042  nginx         3F0A
127.0.0.1:3000                 LISTEN        1000   5123  node          401F
0.0.0.0:5432                   LISTEN        111    918   postgres      3D2C

ACTIVE CONNECTIONS  (top 6 of 19 by queue bytes)
LOCAL                          REMOTE                         STATE        UID    PID  PROCESS       TX/RX
10.0.0.5:51234                 142.250.184.46:443              ESTAB         1000   4821  chrome        64.0k:20.2k
[2001:db8::5]:51000            [2606:4700::6810]:443          ESTAB         1000   7777  curl          27.3k:59.8k
10.0.0.5:59000                 93.184.216.34:443              TIME_WAIT     1000   -1    -             59.1k:45.5k
------------------------------------------------------------------------------
SUMMARY  total 27  ipv4 23  ipv6 4   LISTEN 8   ESTAB 13   SYN_SENT 1   TIME_WAIT 4   CLOSE_WAIT 1
```

### JSON

```json
{
  "timestamp": 1755220138,
  "connections": {
    "total": 27,
    "ipv4": 23,
    "ipv6": 4,
    "by_state": {"CLOSE_WAIT": 1, "ESTABLISHED": 13, "LISTEN": 8, "SYN_SENT": 1, "TIME_WAIT": 4}
  },
  "connections_list": [
    {"local": "0.0.0.0:22", "remote": "*", "state": "LISTEN", "uid": 0, "pid": 812,
     "proc": "sshd", "tx": 0, "rx": 0, "inode": "3E8B", "family": "ipv4"}
  ],
  "summary": {"established": 13, "listeners": 8, "time_wait": 4, "close_wait": 1,
              "syn_sent": 1, "others": 0}
}
```

## Cómo funciona

- `/proc/net/tcp` (y `tcp6`) lista cada socket TCP como una línea: dirección local, remota, estado (hex), colas TX/RX, UID e inode.
- Las direcciones IPv4 son uint32 little-endian; las IPv6 son 4 palabras uint32 cuyo *byte-swap* es la palabra de red (el kernel las imprime con `%08X` en host little-endian) — el decodificador las revierte y formatea con compresión `::`.
- La resolución de procesos escanea `/proc/[0-9]*/fd` una vez por snapshot, hace `readlink` de cada fd buscando `socket:[inode]` y asocia inode → PID → nombre (vía `/proc/<pid>/comm`).
- El modo watch calcula deltas entre snapshots: `(count_t1 - count_t0) / dt` por estado, mostrando `+N/s` o `-N/s`.

## Tests

```bash
./tcp-watch --selftest
# 33 passed, 0 failed
```

## Licencia

MIT — SPDX-License-Identifier: MIT
