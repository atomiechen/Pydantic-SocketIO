set -e
set -x

ruff check src tests
ruff format src tests --check
