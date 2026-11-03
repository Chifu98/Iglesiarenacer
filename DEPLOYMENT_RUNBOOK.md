# Iglesia Renacer — despliegue seguro de roles independientes

## Estado verificado
- GitHub Actions `Security contract`: aprobado.
- Pull Request #12: abierto como borrador; no fusionado.
- Preview Vercel de la rama: hay una compilación `READY` para el código de interfaz, pero no corresponde al último SHA del PR.
- Producción: sigue apuntando a `main`; no se ha modificado.
- Supabase: la migración 012 no se ha ejecutado desde esta sesión.
- Edge Function: el código está actualizado en la rama, pero no está desplegado en Supabase.

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
