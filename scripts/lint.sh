set -e
set -x

ruff check src tests
ruff format src tests --check --diff
pyright --pythonpath "$(python -c 'import sys; print(sys.executable)')"
