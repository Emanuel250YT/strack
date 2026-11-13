# Propuesta normativa: órdenes judiciales de bloqueo en vivo

**Objetivo.** Que un stream pirata de un evento en vivo se pueda cortar en minutos, con control judicial previo, sin dañar sitios legítimos y llegando a todos los proveedores de internet, no solo a los grandes. Lo que sigue es lo que una ley o una resolución conjunta (Poder Judicial, ENACOM, Ministerio Público) debería establecer para que la plataforma funcione.

## 1. Orden marco por evento

- El titular de derechos (o la fiscalía) pide, antes del evento, una **orden marco** para ese partido: qué señal se protege, sus marcas de agua y los licenciatarios autorizados con sus dominios.
- Durante el partido, cada stream detectado se convierte en un **expediente** que el **juez de turno** aprueba o rechaza con su firma digital. Nadie firma en nombre del juez: la firma requiere que el juez haya ingresado con su credencial.
- **Por qué:** hoy todo depende de una fiscalía y un juzgado. El turno judicial con firma digital da el control previo que exige el debido proceso, con la velocidad que exige un evento de dos horas.

## 2. Estándar mínimo de prueba

El expediente debe contener, como mínimo: (a) la marca de agua extraída y su coincidencia con el evento, descartando licenciatarios en sus propios dominios; (b) el servidor que entrega el video (host, IP y sistema autónomo), no solo la página del reproductor; (c) los dominios que comparten esa IP; (d) hashes de la captura y sellos de tiempo, registrados en un **registro de auditoría encadenado** que impida alteraciones posteriores.

## 3. Registro federal de proveedores

- **Inscripción obligatoria** de todo proveedor de acceso a internet en un registro público de ENACOM, con un **punto de contacto técnico por API** y los tipos de bloqueo que puede aplicar (IP, dominio).
- Los proveedores chicos pueden adherir a través de sus cámaras (CABASE, CAPPI) o de un proveedor mayorista, pero la orden les llega a todos por el mismo canal estándar.
- **Por qué:** en 2025 la orden llegó a través de las cámaras porque no había un registro actualizado; sin registro no hay cobertura.

## 4. Plazos de aplicación y confirmación

- Aplicación en **15 minutos** para proveedores grandes y **30 minutos** para pequeños, contados desde la recepción.
- Confirmación obligatoria por API (recibida, aplicada, fallida). Una orden fallida se reenvía automáticamente con un nuevo número; si el juez que la firmó dejó el turno, la refirma el juez entrante.

## 5. Control del daño colateral

- **Regla de proporcionalidad técnica:** si la IP es compartida (CDN, hosting compartido o con dominios de terceros), **se bloquea por dominio, nunca por IP**. Se bloquea por IP solo cuando la IP está dedicada al sitio pirata.
- **Vencimiento automático:** los bloqueos por IP vencen al terminar el evento. Toda extensión requiere una nueva orden.
- **Costos:** los costos de implementación de la API se compensan con un fondo a cargo de los titulares de derechos que usan el sistema, proporcional a las órdenes emitidas.

## 6. Reclamos de sitios afectados

- Canal de reclamo abierto, por API y por web, que llega al **juez de turno**.
- Plazo máximo de resolución de **30 minutos durante el evento**. Si el reclamo es verificado, el juez levanta la orden con su firma y, si corresponde, la reemplaza por un bloqueo más preciso (por dominio).
- Responsabilidad del solicitante por los daños de bloqueos pedidos con prueba insuficiente.

## 7. Transparencia y control posterior

- **Registro público** de cada bloqueo: qué se bloqueó, cuándo, por orden de qué juez y hasta cuándo, y su levantamiento.
- Publicación periódica del hash de cabecera del registro de auditoría, para que cualquiera pueda verificar que no se alteró.
- Informe anual al Congreso con cantidad de órdenes, tiempos, reclamos y errores.

*Propuesta de trabajo del equipo para el Hackathon Argentina Space 2026. No es asesoramiento legal.*
