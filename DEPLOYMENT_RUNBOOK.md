# Iglesia Renacer — despliegue seguro de roles

## Estado verificado (2026-11-03)

- Migraciones 012, 013, 014, 015 y 016 aplicadas en Supabase `oanmwvpvqcmdmdsmflie`.
- Migración 015: catálogo reducido a cinco roles explícitos: Admin, Pastor, Líder, Servidor y Hermano. Escritura se convierte a Pastor; Lectura se convierte a Hermano.
- Migración 015: Pastor asume los permisos de gestión del directorio, anuncios y peticiones de oración, y conserva acceso a notas pastorales y supervisión de notas de líderes.
- Migración 016: nombres de políticas de anuncios actualizados para reflejar Admin/Pastor.
- Perfiles actuales verificados: un Admin y un Pastor. No hay perfiles asignados a Lectura ni Escritura.
- Validación SQL: Admin/Pastor aceptados; Escritura/Lectura rechazados; roles duplicados rechazados.
- Prueba RLS con el perfil Pastor: `app_tiene_rol_exacto('pastor') = true`, puede gestionar anuncios y ve los 2 registros de miembros y las 2 peticiones de oración existentes.
- RLS de Hermano se mantiene limitado a su propio registro; no ve notas de líderes.
- Las cuatro políticas de `notas_lideres` siguen activas y `anon` no tiene SELECT.
- Edge Function `send-announcement-push` desplegada en versión 5 con `verify_jwt=true`; autoriza Admin o Pastor.
- GitHub: cambios preparados en la rama `change/pastor-replaces-escritura-lectura`; pendiente PR y CI.
- Vercel producción continúa sujeta al límite Hobby `api-deployments-young-hobby-team-24h` registrado previamente. No se debe eludir el límite ni cambiar el plan sin autorización.
- No se generó un backup externo desde las herramientas disponibles en esta sesión.
- Sigue pendiente probar aislamiento entre dos cuentas Líder distintas.

## Matriz de roles

| Rol | Acceso |
|---|---|
| Admin | Administración completa, usuarios, roles y supervisión. |
| Pastor | Mismos permisos de gestión que Escritura tenía: crear, consultar, editar y eliminar miembros, gestionar anuncios y peticiones de oración; además, notas pastorales y supervisión de notas de líderes. |
| Líder | Sus propias notas de seguimiento; sin acceso general al directorio por el solo hecho de ser Líder. |
| Servidor | Acceso limitado según políticas específicas; no recibe permisos administrativos ni de gestión del directorio. |
| Hermano | Solo su propio registro y sus propias peticiones; no ve información privada de otros hermanos. |

## Reglas de publicación y verificación

1. Mantener backup externo de Supabase antes de cambios estructurales futuros.
2. Ejecutar las pruebas funcionales con cuentas separadas: Admin, Pastor, Líder, Servidor y Hermano.
3. Probar que Pastor puede crear, modificar y eliminar miembros, gestionar anuncios y peticiones, y conservar acceso a notas pastorales.
4. Probar que Líder A no puede leer, actualizar ni borrar las notas de Líder B.
5. Confirmar que Hermano solo ve su propio registro.
6. Confirmar el deployment de producción y repetir pruebas de humo después de publicar.

## Límite de Vercel

La cuenta Hobby alcanzó el límite `api-deployments-young-hobby-team-24h`. No intentar eludirlo cambiando de equipo o cuenta. Un preview permite revisar la interfaz, pero no certifica que producción esté actualizada.
