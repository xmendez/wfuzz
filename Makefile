.PHONY: docs
test:
	pip install tox
	tox --recreate
flake8:
	pip install flake8
	flake8 --ignore=E501,E402,F401 src tests
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
	pip install Sphinx
	cd docs && make html

coverage:
	coverage report --skip-covered --include "*site-packages/wfuzz*" -m
