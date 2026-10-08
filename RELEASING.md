# Publishing to PyPI

The distribution is named `pyflow-analysis`; its Python import is `pyflow`.
[publish.yml](.github/workflows/publish.yml) builds the wheel and source
distribution and uploads them when a `v*` tag is pushed to GitHub.

The PyPI Trusted Publisher is already configured for `ZJU-PL/pyflow` and
`publish.yml`. GitHub Actions authenticates through OIDC with `id-token: write`;
no local PyPI credentials or repository API-token secret is needed. See the
[PyPI Trusted Publishing documentation](https://docs.pypi.org/trusted-publishers/using-a-publisher/).

## Release steps

1. Choose a version that has not been published to
   [PyPI](https://pypi.org/project/pyflow-analysis/#history).
   Set `__version__` in `src/pyflow/__init__.py` and add a dated entry to
   `CHANGELOG.md`. The package version is read from `__version__`; the tag must
   match it with a `v` prefix.
2. In the project virtual environment, install development dependencies and
   validate the release:

   ```bash
   python -m pip install -e ".[dev]"
   python -m black --check src tests
   python -m pytest
   ```

   Run `python -m pytest -m integration tests/integration` when the release
   changes integration behavior. Let the relevant GitHub CI checks pass before
   pushing the release tag; the publishing workflow does not wait for CI.
3. Commit the release changes and push the release commit to `main`. Then tag
   that commit and push the tag. For example, for the next patch after 0.1.2:

   ```bash
   git add src/pyflow/__init__.py CHANGELOG.md
   git commit -m "Release 0.1.3"
   git push origin main
   # After CI passes for the release commit:
   git tag -a v0.1.3 -m "Release 0.1.3"
   git push origin v0.1.3
   ```

   Replace `0.1.3` consistently with the chosen version and include any other
   intended release changes in the commit.
4. Check the **Publish to PyPI** run in
   [GitHub Actions](https://github.com/ZJU-PL/pyflow/actions/workflows/publish.yml).
   Verify that the version appears on PyPI with both a wheel and a source
   distribution. In a separate environment, smoke-test installation:

   ```bash
   python -m pip install "pyflow-analysis==0.1.3"
   pyflow --version
   ```

A GitHub Release can be created for the existing tag afterward to share release
notes; it does not trigger another upload.

## Existing releases and failures

Version **0.1.2 was already uploaded directly with Twine**. Pushing `v0.1.2`
would trigger an upload of files that already exist; use a new version for the
next automated release. PyPI does not allow replacing uploaded files.

If authentication fails, check that the PyPI Trusted Publisher matches the
repository and workflow filename. If its configuration specifies a GitHub
environment, the publish job must use that same environment.

Retry a failed workflow only after checking whether any artifacts were uploaded.
For a partial upload, recover deliberately rather than blindly rerunning both
uploads. For changes to an already published package, bump the version and
publish a new release.

`make publish` is a manual Twine upload path requiring local credentials; use the
tag-triggered workflow for normal releases. `make publish-test` uploads to
TestPyPI, which has separate credentials and publisher configuration.
