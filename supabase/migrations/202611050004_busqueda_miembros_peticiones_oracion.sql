create or replace function public.buscar_miembros_para_peticion(p_busqueda text)
returns table(id text, name text, status text)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select m.id, m.name, m.status
  from public.miembros_app m
  where auth.uid() is not null
    and exists (
      select 1
      from public.perfiles_app p
      where p.id = auth.uid()
        and p.activo = true
    )
    and length(btrim(coalesce(p_busqueda, ''))) >= 2
    and m.name ilike ('%' || btrim(p_busqueda) || '%')
  order by
    case when lower(m.name) = lower(btrim(p_busqueda)) then 0 else 1 end,
    m.name
  limit 12;
$$;

revoke all on function public.buscar_miembros_para_peticion(text) from public;
revoke all on function public.buscar_miembros_para_peticion(text) from anon;
grant execute on function public.buscar_miembros_para_peticion(text) to authenticated;
