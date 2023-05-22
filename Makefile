deps: Pipfile.lock
	PIPENV_VENV_IN_PROJECT=true pipenv install
	touch .venv


sbom: deps
	pipenv run python3 -m sbom --ini=sbom.ini --template=sbom.html.tmpl --output=sbom.html
