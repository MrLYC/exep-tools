.PHONY: install
install: ## Install the poetry environment and install the pre-commit hooks
	@echo "🚀 Creating virtual environment using pyenv and poetry"
	@poetry install
	@ poetry run pre-commit install
	@poetry shell

.PHONY: check
check: ## Run code quality tools.
	@echo "🚀 Checking Poetry lock file consistency with 'pyproject.toml': Running poetry check --lock"
	@poetry check --lock
	@echo "🚀 Linting code: Running pre-commit"
	@poetry run pre-commit run -a

.PHONY: test
test: ## Test the code with pytest
	@echo "🚀 Testing code: Running pytest"
	$(eval args ?= --pdb)
	poetry run pytest --cov exep_tools --doctest-modules --maxfail 1 ${args}

example/click-commands.py:
	@poetry run python example/click-command.py check

.PHONY: build
build: clean-build ## Build wheel file using poetry
	@echo "🚀 Creating wheel file: $(uname -a)"
	@env RELEASE_BUILD=1 poetry build -f wheel

.PHONY: clean-build
clean-build: ## clean build artifacts
	@rm -rf dist

.PHONY: publish
publish: ## publish a release to pypi.
	@echo "🚀 Publishing: Dry run."
	@poetry config pypi-token.pypi $(PYPI_TOKEN)
	@poetry publish --dry-run
	@echo "🚀 Publishing."
	@poetry publish

.PHONY: build-and-publish
build-and-publish: build publish ## Build and publish.

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: command-test
command-test:
	@$(eval EXLK ?= 00000000000000000000000000000000)
	@$(eval EXLN ?= mrlyc)
	@mkdir -p .command-test
	@poetry run python exep_tools/main.py generate-ex -o .command-test/test.ex -p '{"K": "V"}'
	@poetry run python exep_tools/main.py decrypt-file -i .command-test/test.ex -o .command-test/test.decrypted.ex



.DEFAULT_GOAL := help
