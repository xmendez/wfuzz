.PHONY: docs
tox:
	pip install tox
	tox --recreate
test:
	pytest -v -s tests/
flake8:
	black --check src tests
	flake8 src tests
publish:
	pip install 'twine>=1.5.0'
	python setup.py sdist
	twine upload dist/*
	rm -fr build dist

publish-dev:
	pip install 'twine>=1.5.0'
	python setup.py sdist
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*
	rm -fr build dist
docs:
	pip install -e ".[docs]"
	cd docs && make html

coverage:
	coverage report --skip-covered --include "*python3.8/site-packages/wfuzz*" -m

install: install-dev
	pip install -r requirements.txt

install-dev:
	pip install -e ".[dev]"

freeze:
	pip-compile --output-file requirements.txt setup.py
help:
	@echo "make help              Show this help message"
	@echo "make test              Run local tests with tox"
	@echo "make flake8            Run the code linter(s) and print any warnings"
	@echo "make publish           Publish pip lib to pypi"
	@echo "make publish-dev       Publish pip lib to pypi test"
	@echo "make docs              Create html docs"
	@echo "make install           Install requirements"
	@echo "make install-dev       Install dev requirements"
