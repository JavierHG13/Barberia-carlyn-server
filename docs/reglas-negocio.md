# Reglas de negocio - Barberia Carlyn

Este documento resume las reglas operativas aplicadas por el sistema web para la gestion de citas, pagos y seguimiento administrativo.

## Citas y agenda

| Regla | Descripcion | Aplicacion |
| --- | --- | --- |
| Duracion fija de cita | Cada cita dura 30 minutos. | Al crear o modificar una cita se valida que la hora final coincida con la duracion esperada. |
| Descanso entre citas | Deben existir 10 minutos de descanso entre una cita y otra del mismo barbero. | El backend rechaza horarios traslapados o sin descanso suficiente. |
| Barbero activo | Solo se puede agendar con barberos activos. | Antes de crear o modificar una cita se valida el barbero. |
| Sucursal del barbero | La cita debe quedar asociada a la sucursal del barbero seleccionado. | Si se envia una sucursal distinta, el backend rechaza la operacion. |
| Horarios disponibles | Solo se muestran horarios dentro del horario activo del barbero. | La consulta de horarios disponibles revisa `horarios_barbero`. |
| Horario ocupado | Una cita pendiente, confirmada o completada bloquea el horario. | Las citas canceladas y no asistidas liberan el horario. |
| Limite diario por cliente | Un cliente puede tener hasta 2 citas activas en el mismo dia. | La cantidad se puede ajustar con `MAX_CITAS_CLIENTE_POR_DIA`. |
| Limite diario por barbero | Se puede configurar un limite maximo de citas activas por barbero al dia. | Se activa con `MAX_CITAS_BARBERO_POR_DIA`. |

## Estados de cita

| Estado | Uso en el sistema | Impacto |
| --- | --- | --- |
| Agendada | Cita creada, normalmente sin pago o pendiente de confirmacion. | Bloquea horario. |
| Confirmada | Cita confirmada por pago o revision administrativa. | Bloquea horario. |
| Completada | Servicio realizado. | Pasa a historial y puede formar parte de reportes. |
| Cancelada | Cita cancelada por cliente o administrador. | Libera horario. |
| No_asistio | El cliente no asistio al servicio. | Libera horario y queda como evidencia historica. |

## Pagos

| Caso | Regla |
| --- | --- |
| Reservar sin pagar | La cita se guarda como pendiente y el monto pagado queda en 0 o vacio. |
| Pagar cita en linea | Mercado Pago genera la preferencia de pago para la cita. |
| Pago registrado | El monto pagado queda asociado a la cita en `monto_pagado`. |
| Cliente paga y no asiste | La cita se marca como `No_asistio`, se conserva el monto pagado y no se realiza reembolso automatico. Queda para seguimiento administrativo. |
| Ventas POS | Para ventas internas se aceptan metodos: efectivo, transferencia y tarjeta. |
| Facturacion electronica | No esta implementada como modulo funcional. Si se requiere, debe agregarse como alcance futuro. |

## Seguimiento administrativo

| Regla | Descripcion |
| --- | --- |
| Citas proximas | Solo muestran citas pendientes o confirmadas que aun no han ocurrido. |
| Historial | Muestra citas pasadas, completadas, canceladas o no asistidas. |
| No asistencia | Las citas abiertas anteriores a la fecha limite pueden marcarse automaticamente como `No_asistio`. |
| Pago en no asistencia | Si la cita tenia pago, el sistema conserva el monto y registra la observacion: `No asistencia con pago registrado; pago retenido para seguimiento administrativo.` |

## Reglas configurables

| Variable | Valor por defecto | Descripcion |
| --- | --- | --- |
| `MAX_CITAS_CLIENTE_POR_DIA` | `2` | Limite de citas activas que puede tener un cliente por dia. |
| `MAX_CITAS_BARBERO_POR_DIA` | Sin limite | Limite opcional de citas activas de un barbero por dia. |
