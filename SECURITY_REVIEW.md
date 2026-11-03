# Revisión de seguridad — Iglesia Renacer

## Qué corrige esta rama

- Los cinco roles disponibles se comprueban por pertenencia explícita: Admin, Pastor, Líder, Servidor y Hermano. Los roles Lectura y Escritura fueron retirados.
- La interfaz administrativa permite seleccionar varios roles explícitos.
- La función Edge de notificaciones solo autoriza a Admin o Pastor.
- La migración 012 elimina el límite heredado de dos roles, normaliza roles explícitos y configura una fila de nota por miembro y líder.
- La migración 013 elimina un índice redundante cuando la clave primaria ya cubre `(miembro_id, lider_id)` y ajusta las políticas RLS para evaluar `auth.uid()` una sola vez por consulta.
- La migración 015 elimina Lectura y Escritura, migra asignaciones antiguas (Escritura → Pastor; Lectura → Hermano) y otorga a Pastor los permisos de gestión del directorio, anuncios y peticiones de oración.
- En el proyecto actual, `notas_lideres` ya tenía `lider_id NOT NULL` y clave primaria compuesta; no había notas cargadas al aplicar los cambios.

## Importante sobre visibilidad del directorio

La matriz de roles es independiente. Tener Pastor, Líder o Servidor no concede acceso al directorio. Pastor tiene acceso de lectura y gestión del directorio, además de sus notas pastorales. Líder no recibe acceso general al directorio por su rol; el botón de nota de líder solo aparece para miembros que puede consultar según RLS.

## Estado de despliegue y pruebas

- Migraciones 012, 013 y 015 aplicadas en el proyecto Supabase conectado.
- Edge Function `send-announcement-push` desplegada, versión 4, con JWT requerido.
- RLS comprobado con un usuario autenticado de rol Hermano: solo ve su propio registro de miembro y no ve notas de líderes.
- `anon` no tiene permiso de lectura en `notas_lideres`.
- Pendiente una prueba de aislamiento entre dos cuentas Líder distintas y pruebas funcionales de las siete combinaciones de roles.
- No se generó un backup externo desde las herramientas disponibles en esta sesión.

## Límites de esta revisión

La validación estática y las comprobaciones SQL se ejecutaron, pero no equivalen a una auditoría completa. Se requieren pruebas funcionales con cuentas separadas de Líder y otros roles antes de considerar el modelo totalmente verificado.
