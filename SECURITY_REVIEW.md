# Revisión de seguridad — Iglesia Renacer

## Qué corrige esta rama

- Los siete roles se comprueban por pertenencia explícita; Pastor, Líder y Servidor ya no se convierten en Escritura.
- La interfaz administrativa permite seleccionar varios roles explícitos.
- La función Edge de notificaciones solo autoriza a Admin o Escritura.
- La migración 012 elimina el límite heredado de dos roles y normaliza las notas de líderes a una fila por miembro y líder.
- Las notas históricas sin autor se conservan con `lider_id = NULL`; quedan visibles solo para Admin/Pastor y no se atribuyen artificialmente a un líder.

## Importante sobre visibilidad del directorio

La matriz de roles es independiente. Tener Pastor, Líder o Servidor no concede acceso al directorio. Si un Pastor o Líder necesita consultar el directorio, el administrador debe asignarle también el rol Lectura explícitamente. Escritura concede edición del directorio solo cuando ese rol está asignado.

## Pasos manuales antes de publicar

1. Respaldar Supabase.
2. Revisar y ejecutar `supabase/migrations/202611030012_roles_independientes_notas_lideres.sql` en el SQL Editor.
3. Desplegar la función Edge actualizada.
4. Probar con cuentas separadas para cada combinación de roles.
5. Confirmar que un Líder no puede leer ni modificar las notas de otro líder.
6. Confirmar que Pastor no puede gestionar miembros/anuncios salvo que tenga Escritura explícita.

## Límites de esta revisión

Esta rama no se fusiona ni despliega automáticamente. Las pruebas contra usuarios reales y la validación de RLS en el proyecto Supabase requieren ejecutarse con cuentas de prueba y el proyecto conectado.
