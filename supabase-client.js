// Datos de conexión de Supabase
const SUPABASE_URL = "https://oanmwvpvqcmdmdsmflie.supabase.co";

const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_iZ-XB47CWDbnAukioDAQWA_oHkOszCM";

// Crear conexión
if (!window.supabase) {
    throw new Error("No se pudo cargar Supabase JS");
}

window.supabaseClient = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY
);

console.log("Cliente Supabase inicializado");