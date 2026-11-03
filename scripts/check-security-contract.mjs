import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const app = read("../script.js");
const edge = read("../supabase/functions/send-announcement-push/index.ts");
const migration = read("../supabase/migrations/202611030012_roles_independientes_notas_lideres.sql");

assert.match(app, /function hasRole\(role\)\s*\{\s*return !!\(currentUser && Array\.isArray\(currentUser\.roles\) && currentUser\.roles\.includes\(role\)\);/);
assert.doesNotMatch(app, /role === ["']escritura["']\s*\)\s*return currentUser\.roles\.some/);
assert.match(app, /async function saveUserRoles\(userId\)/);
assert.match(app, /selectElement\.selectedOptions/);
assert.match(app, /onclick="saveUserRoles\(this\.dataset\.userId\)"/);
assert.match(app, /onConflict: ["']miembro_id,lider_id["']/);
assert.match(edge, /roles\.includes\(["']admin["']\) \|\| roles\.includes\(["']escritura["']\)/);
assert.doesNotMatch(edge, /\["admin",\s*"escritura",\s*"pastor",\s*"lider"\]/);
assert.match(migration, /cardinality\(p_roles\) BETWEEN 1 AND 7/);
assert.match(migration, /CREATE POLICY notas_lideres_select_privado/);
assert.match(migration, /public\.app_tiene_rol\('lider'\) AND lider_id = auth\.uid\(\)/);
assert.match(migration, /CREATE UNIQUE INDEX IF NOT EXISTS notas_lideres_miembro_lider_uidx/);

console.log("Security contract checks passed.");
