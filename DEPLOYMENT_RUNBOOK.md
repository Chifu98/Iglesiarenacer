# Iglesia Renacer — despliegue seguro de roles independientes

## Estado verificado (2026-11-03)
- Migración 012 aplicada correctamente en Supabase `oanmwvpvqcmdmdsmflie`.
- Migración 013 aplicada: optimiza las políticas RLS de notas y elimina el índice duplicado cuando la PK ya cubre `(miembro_id, lider_id)`.
- Validación de datos: cero perfiles con roles inválidos, cero notas duplicadas y cero notas sin líder; las cuatro políticas de notas están activas y `anon` no tiene SELECT.
- Prueba RLS con rol `authenticated`: un perfil Hermano solo ve su propio registro de miembro (1 fila); no ve notas de líderes.
- Edge Function `send-announcement-push` desplegada en versión 4 con `verify_jwt=true`; autoriza solo Admin o Escritura.
- Migración 014 aplicada: revoca la ejecución directa por clientes de una función que solo debe ejecutarse como trigger.
- GitHub Actions `Security contract`: pendiente de completar para el último commit de esta rama.
- Vercel Preview del commit `f5056f7`: `READY`. URL verificada: https://iglesiarenacer-git-fix-roles-independient-d470ed-iglesiarenacer.vercel.app
- PR #12 fusionado en `main` (merge commit `11635d0`).
- Vercel todavía no ha desplegado el merge a producción: el plan Hobby devolvió `api-deployments-young-hobby-team-24h` (bloqueo de 24 horas). El último deployment de producción verificado sigue en el commit anterior `51b29e5`.
- No se pudo crear un backup descargable desde las herramientas disponibles; se debe conservar un backup externo del proyecto.
- No hay dos cuentas de Líder de prueba, por lo que el aislamiento entre dos autores aún requiere una prueba funcional con cuentas reales.

## Orden de publicación

1. Crear un backup de Supabase desde el Dashboard y comprobar que esté disponible.
2. Conectar la integración Supabase a ChatGPT o abrir el proyecto en Supabase Dashboard.
3. Confirmar que el proyecto sea el correcto: `oanmwvpvqcmdmdsmflie`.
4. Revisar la migración `supabase/migrations/202611030012_roles_independientes_notas_lideres.sql`.
5. Aplicar la migración primero en un entorno de pruebas. Si solo existe producción, no ejecutarla hasta tener backup comprobado y revisar el estado actual de `notas_lideres` y los triggers.
6. Ejecutar `supabase/verification/202611030012_postflight.sql`. Investigar cualquier resultado inesperado.
7. Desplegar `supabase/functions/send-announcement-push/index.ts` con el mecanismo de despliegue de Supabase.
8. Probar cuentas separadas: Admin, Escritura, Lectura, Pastor, Líder, Servidor y Hermano. Verificar también combinaciones explícitas.
9. Probar aislamiento entre dos líderes: Líder A no puede leer, actualizar ni borrar la nota de Líder B.
10. Probar que Pastor/Líder/Servidor sin Escritura no puedan modificar miembros ni anuncios; sin Lectura tampoco deben ver el directorio.
11. Cuando todas las pruebas pasen, aprobar y fusionar el PR #12. Después esperar el límite de Vercel o resolverlo con el administrador del equipo.
12. Confirmar el despliegue de producción y repetir pruebas de humo.

## Límite de Vercel
La cuenta Hobby alcanzó el límite `api-deployments-young-hobby-team-24h`. Vercel indicó esperar 24 horas. No se debe intentar eludir el límite cambiando de equipo o de cuenta. El preview ya compilado sirve para revisar la interfaz, no para certificar el backend.

## Reglas funcionales
- Los siete roles son independientes.
- Ningún rol especializado hereda Escritura, Lectura ni Hermano.
- El acceso al directorio requiere Admin, Escritura o Lectura explícitos.
- Cada líder gestiona exclusivamente sus notas.
- Admin y Pastor supervisan notas de líderes y notas pastorales.
