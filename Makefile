.PHONY: install install-user uninstall test docker-build docker-run clean

# System-wide install (creates /usr/local/bin/autofuzz or similar) — needs sudo.
install:
	pip install --break-system-packages .

# Per-user install (creates ~/.local/bin/autofuzz) — no sudo needed.
install-user:
	pip install --break-system-packages --user .

uninstall:
	pip uninstall -y autofuzz

test:
	python3 -m pytest tests/ -v

docker-build:
	docker build -t autofuzz .

# Runs against the current directory: results/ lands in $(pwd) on the host.
# Example: make docker-run ARGS="-d https://example.com --json"
docker-run:
	docker run --rm -v "$$(pwd):/work" autofuzz $(ARGS)

clean:
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf .pytest_cache build dist *.egg-info
