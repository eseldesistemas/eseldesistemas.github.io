-- Es el de Sistemas: control de intentos del PIN.
-- No almacena contraseñas ni direcciones IP sin procesar.
CREATE TABLE IF NOT EXISTS login_attempts (
  client_key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
