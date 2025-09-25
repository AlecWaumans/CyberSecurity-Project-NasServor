# --- Utiliser la venv existante, sans activation ----------------------------
VENV_DIR="${VENV_DIR:-venv}"
PYBIN="$VENV_DIR/bin/python"

if [[ ! -x "$PYBIN" ]]; then
  echo "Erreur : venv introuvable à '$VENV_DIR'."
  echo "Crée-la ou ajuste VENV_DIR vers le bon dossier."
  exit 1
fi

echo "Venv Python: $("$PYBIN" -V)"
"$PYBIN" -c "import sys; print('sys.prefix:', sys.prefix); print('exe:', sys.executable)"

# pip dans la venv uniquement
"$PYBIN" -m ensurepip --upgrade || true
"$PYBIN" -m pip install --upgrade pip
"$PYBIN" -m pip install -r requirements.txt

# --- Lancer l’app avec le Python de la venv ---------------------------------
export FLASK_APP=app.py
export FLASK_ENV=development
exec "$PYBIN" app.py --host=0.0.0.0 --port=5000 \
  --cert="private/localhost.pem" \
  --key="private/localhost-key.pem"
