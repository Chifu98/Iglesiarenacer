-- Permitir los nuevos ministerios en las solicitudes públicas de registro.
alter table public.solicitudes_registro_miembros
  drop constraint if exists solicitudes_registro_miembros_ministry_check;

alter table public.solicitudes_registro_miembros
  add constraint solicitudes_registro_miembros_ministry_check
  check (ministry = any (array[
    'General', 'Alabanza', 'Servidor', 'Niños', 'Jóvenes',
    'Oración', 'Evangelismo', 'Redes', 'Damas', 'Matrimonio', 'Hombres'
  ]::text[]));
