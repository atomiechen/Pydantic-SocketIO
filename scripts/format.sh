set -x
set -e

ruff check src tests --fix
ruff format src tests
