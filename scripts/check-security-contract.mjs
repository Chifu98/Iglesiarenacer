import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const app = read("../script.js");
const edge = read("../supabase/functions/send-announcement-push/index.ts");
const migration = read("../supabase/migrations/202611030015_pastor_reemplaza_escritura_lectura.sql");

assert.match(app, /function hasRole\(role\)\s*\{\s*return !!\(currentUser && Array\.isArray\(currentUser\.roles\) && currentUser\.roles\.includes\(role\)\);/);
assert.doesNotMatch(app, /escritura|lectura/i);
assert.match(app, /const allowedRoles = \["admin", "pastor", "lider", "servidor", "miembro"\]/);
assert.match(app, /\{ value: "pastor", label: "Pastor" \}/);
assert.match(app, /hasRole\("admin"\) \|\| hasRole\("pastor"\)/);
assert.match(app, /select multiple size="5"/);
assert.match(app, /onConflict: ["']miembro_id,lider_id["']/);
assert.match(edge, /roles\.includes\(["']admin["']\) \|\| roles\.includes\(["']pastor["']\)/);
assert.doesNotMatch(edge, /roles\.includes\(["'](?:escritura|lectura)["']\)/i);
assert.match(migration, /ARRAY\['admin','pastor','lider','servidor','hermano'\]/);
assert.match(migration, /WHEN 'escritura' THEN 'pastor'/);
assert.match(migration, /WHEN 'lectura' THEN 'hermano'/);
assert.match(migration, /CREATE POLICY miembros_app_select_privacidad/);
assert.match(migration, /public\.app_tiene_rol_exacto\('pastor'\)/);
assert.match(migration, /CREATE POLICY peticiones_update_gestores/);

console.log("Security contract checks passed.");
