# Developer convenience targets. End users install with pipx (see README).

VERSION := $(shell python3 -c "import sys; sys.path.insert(0, 'src'); import coxyz; print(coxyz.__version__)")

.PHONY: help test build clean release

help:
	@echo "make test     - run the test suite"
	@echo "make build    - build sdist + wheel into dist/"
	@echo "make clean    - remove build artefacts"
	@echo "make release  - tag v$(VERSION) and push it (CI publishes to PyPI)"

test:
	python3 -m unittest discover -s tests -v

build: clean
	python3 -m pip install --upgrade build
	python3 -m build

clean:
	rm -rf build dist src/*.egg-info

release:
	@git diff --quiet || { echo "Working tree is dirty — commit first."; exit 1; }
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"
	@echo ">>> Pushed tag v$(VERSION) — GitHub Actions will publish to PyPI."
