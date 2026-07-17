### TCP SYN Flood y CVE-2019-11477 (SACK Panic): entendimiento, detección y mitigación

Este documento explica **cómo funcionan conceptualmente los ataques de agotamiento de conexiones TCP** (SYN flood) y la vulnerabilidad **CVE-2019-11477 ("SACK Panic")**, cómo **detectarlos** y cómo **mitigarlos** en servidores y equipos de red reales. Incluye también una guía para montar un **laboratorio controlado y aislado** en el que practicar la detección y defensa de forma segura y legal.

---

### TCP SYN Flood

El *three-way handshake* de TCP establece una conexión en tres pasos:

```
Cliente                     Servidor
   │  ── SYN ──────────────►   │   (1) Cliente solicita conexión
   │  ◄──────────── SYN-ACK ── │   (2) Servidor reserva recursos y responde
   │  ── ACK ──────────────►   │   (3) Cliente confirma; conexión ESTABLISHED
```

Cuando el servidor recibe un `SYN`, reserva una entrada en una estructura de memoria llamada **cola de conexiones semiabiertas** (o *backlog* de `SYN_RECV`) y espera el `ACK` final. Un **SYN flood** consiste en enviar un gran volumen de paquetes `SYN` (a menudo con IP origen falsificada/*spoofed*) **sin completar nunca el tercer paso**. El servidor termina con su cola de conexiones semiabiertas llena de entradas que nunca se completan, y deja de poder aceptar conexiones legítimas nuevas.

### 1.1 Variantes relacionadas presentes en este tipo de toolkits

| Técnica | Capa | Efecto |
|---|---|---|
| SYN flood clásico | Red/Transporte (L3/L4) | Agota la cola de conexiones semiabiertas (`SYN_RECV`) |
| SYN flood con IP spoofing | Red/Transporte | Igual que el anterior, pero dificulta el bloqueo por IP origen y oculta al atacante real |
| ACK/RST flood | Transporte | Fuerza al servidor a procesar y descartar paquetes fuera de estado |
| Ataques sobre TLS (handshake SSL) | Aplicación | Agota CPU forzando negociaciones criptográficas repetidas |
| DoS de amplificación vía HTTP incompleto | Aplicación | Agota workers (relacionado con Slowloris, ver README específico) |

### 1.2 ¿Qué es CVE-2019-11477 ("SACK Panic")?

Es una vulnerabilidad del kernel Linux (afecta a versiones desde 2.6.29 hasta parches de 2019) relacionada con el procesamiento de **SACK (Selective Acknowledgment)**, una extensión de TCP que permite confirmar de forma selectiva qué segmentos se han recibido. Un atacante que envíe secuencias de segmentos TCP y opciones SACK cuidadosamente construidas puede provocar una **fragmentación excesiva de la cola de retransmisión** del kernel, generando un **kernel panic** (caída total del sistema) o consumo extremo de CPU, sin necesidad de mucho ancho de banda.

A nivel conceptual (sin detalles de explotación):

- El kernel mantiene una lista de segmentos pendientes de confirmación por SACK.
- Con secuencias de MSS (*Maximum Segment Size*) muy pequeño combinadas con bloques SACK específicos, esa lista puede fragmentarse en miles de entradas.
- Recorrer esa lista fragmentada satura la CPU o provoca un fallo del kernel.

**Fue corregida** en actualizaciones del kernel de junio de 2019 (parches oficiales de `net/ipv4/tcp_input.c`) y en releases de todas las distribuciones principales.

### 1.3 Por qué siguen siendo relevantes en 2026

Aunque CVE-2019-11477 está parcheada desde hace años, sigue siendo un buen caso de estudio porque:

- Ilustra cómo un fallo de bajo nivel en la pila TCP puede tener impacto de disponibilidad total (no solo degradación).
- Sistemas embebidos, dispositivos IoT o electrodomésticos con kernels antiguos y sin actualizar pueden seguir siendo vulnerables.
- Refuerza la importancia de mantener el kernel y la pila de red actualizados como parte de cualquier hardening.

---

### 2. Detección

### 2.1 Indicadores de un SYN flood en curso

- Crecimiento súbito de conexiones en estado **`SYN_RECV`** en la salida de `netstat`/`ss`.
- La cola de backlog (`net.ipv4.tcp_max_syn_backlog`) cerca de su límite.
- Contador de `TCPSynRetrans` o `ListenDrops` creciendo rápidamente en `nstat`/`netstat -s`.
- Tráfico entrante compuesto casi exclusivamente por paquetes `SYN` sin el correspondiente `ACK` final (visible con `tcpdump`).
- IPs origen dispersas o claramente falsificadas (rangos no enrutables, por ejemplo).

### 2.2 Comandos de monitorización

```bash
# Contar conexiones semiabiertas
netstat -n -p | grep SYN_RECV | wc -l

# Ver el top de IPs origen con conexiones semiabiertas
netstat -n -p | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr

# Estadísticas agregadas de la pila TCP (útil para detectar SYN floods y retransmisiones)
netstat -s | grep -i syn
nstat -az | grep -i syn

# Capturar tráfico SYN para análisis forense
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' -n
```

### 2.3 Herramientas de monitorización recomendadas

| Herramienta | Qué aporta |
|---|---|
| `ss -s` / `netstat -s` | Resumen de conexiones por estado y estadísticas TCP agregadas |
| `nstat` | Contadores detallados del kernel (`TcpExtSyncookiesSent`, `ListenDrops`, etc.) |
| `tcpdump`/Wireshark | Análisis de patrones de paquetes SYN/ACK/RST |
| Prometheus `node_exporter` (`node_netstat_*`) + Grafana | Dashboards y alertas sobre backlog SYN |
| IDS/IPS (Suricata/Snort) | Firmas para flood de SYN y anomalías de handshake |
| `conntrack -L` (si usas netfilter/conntrack) | Visualiza el estado de las conexiones rastreadas por el firewall |

---

### 3. Mitigación

### 3.1 A nivel de kernel Linux (host)

**SYN cookies** es el mecanismo estándar: en lugar de reservar memoria para cada `SYN` recibido, el kernel codifica la información de la conexión en el propio número de secuencia del `SYN-ACK`, sin necesidad de guardar estado hasta que llega el `ACK` final.

```bash
# Habilitar SYN cookies (activación automática bajo carga)
sysctl -w net.ipv4.tcp_syncookies=1

# Aumentar el backlog de conexiones semiabiertas
sysctl -w net.ipv4.tcp_max_syn_backlog=4096

# Reducir reintentos de SYN-ACK (menos tiempo reservando recursos por conexión falsa)
sysctl -w net.ipv4.tcp_synack_retries=2

# Reducir el timeout de FIN-WAIT (libera recursos más rápido en ataques mixtos)
sysctl -w net.ipv4.tcp_fin_timeout=15
```

Para persistir estos cambios: añadirlos a `/etc/sysctl.conf` o `/etc/sysctl.d/99-syn-hardening.conf` y aplicar con `sysctl -p`.

### 3.2 A nivel de firewall (iptables/nftables) — SYNPROXY

`SYNPROXY` permite que el propio firewall gestione el handshake TCP y solo reenvíe al backend las conexiones que se completan de verdad, actuando como un filtro delante del servidor real.

```bash
# iptables (ejemplo simplificado)
iptables -t raw -A PREROUTING -p tcp -m tcp --dport 80 --syn -j CT --notrack
iptables -A INPUT -p tcp -m tcp --dport 80 -m state --state INVALID,UNTRACKED \
  -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -A INPUT -m state --state INVALID -j DROP
```

```bash
# Limitar tasa de nuevos SYN por IP origen
iptables -A INPUT -p tcp --syn -m limit --limit 10/second --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
```

### 3.3 A nivel de sistema/parcheo (CVE-2019-11477 y similares)

| Acción | Detalle |
|---|---|
| Actualizar el kernel | Aplicar los parches disponibles desde junio de 2019 en adelante (todas las distros mayores los incluyen desde entonces) |
| Revisar dispositivos embebidos/IoT | Firmware desactualizado es el principal vector residual de esta CVE hoy en día |
| Mitigación temporal sin reinicio | Ajustar `net.ipv4.tcp_sack=0` deshabilita SACK como mitigación de emergencia (impacta el rendimiento en redes con pérdida de paquetes) |
| Monitorizar CVEs de la pila TCP | Suscribirse a advisories del kernel (kernel.org, distro-specific security feeds) |

```bash
# Mitigación de emergencia sin parchear (impacto en rendimiento, solo como último recurso)
sysctl -w net.ipv4.tcp_sack=0
```

### 3.4 A nivel de perímetro (routers, balanceadores, WAF/CDN, anti-DDoS)

| Solución | Cómo mitiga |
|---|---|
| Cloudflare / AWS Shield / Akamai | Absorben el flood en el edge, muy lejos del servidor real; usan sus propios mecanismos de SYN cookies a gran escala |
| Router/firewall perimetral con *rate limiting* | Limita nuevas conexiones SYN por segundo antes de que lleguen al servidor |
| Balanceador de carga (F5, HAProxy, ALB) | Termina la conexión TCP y solo reenvía tráfico ya establecido y válido al backend |
| ACLs de *ingress filtering* (BCP38) | Descarta en el borde de red paquetes con IP origen falsificada que no corresponde al rango del enlace |
| Blackholing / *scrubbing centers* de proveedor ISP | Para ataques volumétricos que superan la capacidad local |

### 3.5 Tabla comparativa de mitigaciones

| Capa | Mecanismo | Dónde se aplica | Coste de implementación | Eficacia frente a SYN flood volumétrico |
|---|---|---|---|---|
| Kernel | SYN cookies | Host servidor | Bajo | Alta |
| Kernel | Ajuste de backlog/timeouts | Host servidor | Bajo | Media |
| Firewall | SYNPROXY (iptables/nftables) | Host o firewall dedicado | Medio | Alta |
| Firewall | Rate limiting por IP | Host o firewall dedicado | Bajo | Media |
| Red | Ingress filtering (BCP38) | Router de borde / ISP | Medio (requiere control del ISP) | Alta contra spoofing |
| Perímetro | CDN/WAF/Anti-DDoS gestionado | Proveedor externo | Medio-Alto (coste económico) | Muy alta |
| Sistema | Parcheo de kernel (CVE-2019-11477) | Host servidor | Bajo | Elimina el vector específico |

### 3.6 Checklist rápido de hardening

| # | Medida | Prioridad |
|---|---|---|
| 1 | Habilitar `tcp_syncookies` | Alta |
| 2 | Mantener el kernel actualizado (parches de seguridad TCP/IP) | Alta |
| 3 | Configurar `SYNPROXY` o rate limiting en el firewall perimetral | Alta |
| 4 | Desplegar protección anti-DDoS gestionada para servicios públicos críticos | Media-Alta |
| 5 | Monitorizar `SYN_RECV`, `ListenDrops` y `TCPSynRetrans` con alertas | Media |
| 6 | Aplicar ingress filtering (BCP38) si administras el borde de red | Media |
| 7 | Revisar dispositivos IoT/embebidos con kernels antiguos | Media |

---

## 4. Laboratorio controlado de aprendizaje

Entorno **aislado y propio** (sin conectividad hacia Internet ni redes de terceros) para estudiar el efecto de un SYN flood desde el punto de vista defensivo, practicar su detección y validar mitigaciones.

### 4.1 Objetivos de aprendizaje

- Observar el efecto de la saturación de la cola `SYN_RECV` sobre un servidor de prueba.
- Practicar el uso de `netstat`, `ss`, `nstat` y `tcpdump` para identificar el patrón de ataque.
- Configurar y validar `tcp_syncookies`, ajustes de backlog y `SYNPROXY`, comparando el comportamiento antes/después.
- Comprender por qué mantener el kernel actualizado es una medida de hardening básica (contexto de CVE-2019-11477).

### 4.2 Topología recomendada

```
┌────────────────────────────┐        red interna aislada (host-only / NAT interno)
│  Máquina "generador" (VM)   │──────────────┐
│  - Generador de tráfico de  │              │
│    pruebas (hping3 en modo  │              ▼
│    benigno / iperf3)        │   ┌────────────────────────────┐
└────────────────────────────┘   │   Máquina "servidor" (VM)   │
                                  │   - Kernel Linux actualizado│
┌────────────────────────────┐   │     o vulnerable (según fase)│
│  Máquina "monitor" (VM)     │◄──┤   - Firewall con SYNPROXY   │
│  - Grafana/Prometheus       │   │   - Logs y contadores TCP   │
│  - Dashboards de SYN_RECV   │   └────────────────────────────┘
└────────────────────────────┘
```

Recomendaciones:

- Red virtual interna sin salida a Internet (host-only, NAT interno, o red `internal` de Docker).
- VMs claramente etiquetadas (`lab-generador`, `lab-servidor`, `lab-monitor`).
- Ningún puerto expuesto hacia la red doméstica/corporativa.
- Si se usa una VM con un kernel deliberadamente antiguo para estudiar CVE-2019-11477 en un entorno de laboratorio, debe permanecer **completamente aislada** (sin red compartida ni acceso a Internet) durante toda la práctica.

### 4.3 Preparar el servidor de pruebas

```bash
# Estado inicial: valores por defecto conservadores para observar comportamiento
sysctl net.ipv4.tcp_syncookies
sysctl net.ipv4.tcp_max_syn_backlog

# Servicio de prueba simple para tener un puerto que monitorizar
docker network create --internal lab-tcpsyn-net
docker run -d --name lab-servidor --network lab-tcpsyn-net -p 127.0.0.1:8080:80 httpd:2.4
```

Instala herramientas de observación:

```bash
apt-get install -y net-tools iproute2 tcpdump nstat
```

### 4.4 Fases de la práctica

| Fase | Objetivo | Qué observar |
|---|---|---|
| 1. Línea base | Medir capacidad normal de aceptación de conexiones | `ss -s`, `netstat -s \| grep -i syn` en reposo |
| 2. Generación de carga de conexión (benigna) | Usar herramientas legítimas de *benchmarking* (`iperf3`, `ab`, `wrk`) para generar concurrencia realista, no un flood malicioso | Nº de conexiones `ESTABLISHED` vs. capacidad configurada |
| 3. Simulación de saturación de backlog en laboratorio aislado | Ajustar deliberadamente `tcp_max_syn_backlog` a un valor muy bajo para observar cómo se comporta la cola bajo presión, dentro del propio laboratorio | Crecimiento de `SYN_RECV`, `ListenDrops` en `netstat -s` |
| 4. Mitigación | Activar `tcp_syncookies`, ajustar backlog y probar `SYNPROXY` | Comparar `ListenDrops` y disponibilidad antes/después |
| 5. Validación | Confirmar que un cliente legítimo simulado sigue conectando con la mitigación activa | Latencia y tasa de éxito de conexión |
| 6. Estudio de CVE-2019-11477 (teórico) | Repasar el advisory oficial y el commit de parcheo del kernel, sin ejecutar el exploit | Entender el mecanismo de la vulnerabilidad y su corrección |

### 4.5 Buenas prácticas legales y éticas

- Realiza estas pruebas **únicamente** en máquinas y redes de tu propiedad o con autorización explícita y por escrito.
- Nunca dirijas herramientas de generación de tráfico SYN, spoofing o el exploit de una CVE contra sistemas que no controles.
- Para el estudio de CVE-2019-11477, se recomienda limitarse al **análisis del advisory y del parche** en lugar de reproducir el exploit, salvo en un laboratorio de investigación de vulnerabilidades debidamente aislado y autorizado.
- Documenta alcance, fechas y responsable de cada práctica, como en un pentest real.

---

## 5. Referencias

- RFC 793 / RFC 9293 — Transmission Control Protocol
- NVD — CVE-2019-11477 (SACK Panic)
- Linux kernel — documentación de `sysctl` de red (`Documentation/networking/ip-sysctl.txt`)
- Netfilter — documentación de `SYNPROXY`
- BCP38 / RFC 2827 — Network Ingress Filtering

---


#

### Instalacion:

apt-get install nmap

git clone https://github.com/hackingyseguridad/tcpsyn

sh instalar.sh

### Uso:

./tcpsyn <IP puerto>

./tcpsyn6 <IPv6 puerto>

# Para ver las conexiones TCP activas establecidas

./conexiones <puerto_TCP>

netstat -na

netstat -an | grep :80 | sort

netstat -n -p|grep SYN_REC | wc -l

netstat -n -p | grep SYN_REC | sort -u

netstat -n -p | grep SYN_REC | awk ‘{print $5}’ | awk -F: ‘{print $1}’

netstat -ntu | awk ‘{print $5}’ | cut -d: -f1 | sort | uniq -c | sort -n

netstat -anp |grep ‘tcp|udp’ | awk ‘{print $5}’ | cut -d: -f1 | sort | uniq -c | sort -n

netstat -ntu | grep ESTAB | awk ‘{print $5}’ | cut -d: -f1 | sort | uniq -c | sort -nr

netstat -plan|grep :80 | awk {'print $5'} | cut -d: -f 1 | sort | uniq -c

netstat -plan|grep :80|awk {‘print $5’}|cut -d: -f 1|sort|uniq -c|sort -nk 1

#
http://www.hackingyseguridad.com/
#



