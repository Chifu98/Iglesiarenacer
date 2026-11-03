# Revisión de seguridad — Iglesia Renacer

## Qué corrige esta rama

- Los siete roles se comprueban por pertenencia explícita; Pastor, Líder y Servidor ya no se convierten en Escritura.
- La interfaz administrativa permite seleccionar varios roles explícitos.
- La función Edge de notificaciones solo autoriza a Admin o Escritura.
- La migración 012 elimina el límite heredado de dos roles, normaliza roles explícitos y configura una fila de nota por miembro y líder.
- La migración 013 elimina un índice redundante cuando la clave primaria ya cubre `(miembro_id, lider_id)` y ajusta las políticas RLS para evaluar `auth.uid()` una sola vez por consulta.
- En el proyecto actual, `notas_lideres` ya tenía `lider_id NOT NULL` y clave primaria compuesta; no había notas cargadas al aplicar los cambios.

## Importante sobre visibilidad del directorio

La matriz de roles es independiente. Tener Pastor, Líder o Servidor no concede acceso al directorio. Si un Pastor o Líder necesita consultar el directorio para trabajar con notas, el administrador debe asignarle también el rol Lectura explícitamente. El botón de nota de líder solo aparece para miembros visibles según RLS; no se concede acceso general por ser Líder. Escritura concede edición del directorio solo cuando ese rol está asignado.

## Estado de despliegue y pruebas

- Migraciones 012 y 013 aplicadas en el proyecto Supabase conectado.
- Edge Function `send-announcement-push` desplegada, versión 4, con JWT requerido.
- RLS comprobado con un usuario autenticado de rol Hermano: solo ve su propio registro de miembro y no ve notas de líderes.
- `anon` no tiene permiso de lectura en `notas_lideres`.
- Pendiente una prueba de aislamiento entre dos cuentas Líder distintas y pruebas funcionales de las siete combinaciones de roles.
- No se generó un backup externo desde las herramientas disponibles en esta sesión.

## Límites de esta revisión

La validación estática y las comprobaciones SQL se ejecutaron, pero no equivalen a una auditoría completa. Se requieren pruebas funcionales con cuentas separadas de Líder y otros roles antes de considerar el modelo totalmente verificado.
