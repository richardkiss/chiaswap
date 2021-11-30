# Starter SConstruct for enscons

import enscons
import setuptools_scm
import pytoml


metadata = dict(pytoml.load(open("pyproject.toml")))["tool"]["enscons"]
metadata["version"] = setuptools_scm.get_version(local_scheme="no-local-version")

full_tag = "py3-none-any"  # pure Python packages compatible with 2+3

env = Environment(
    tools=["default", "packaging", enscons.generate],
    PACKAGE_METADATA=metadata,
    WHEEL_TAG=full_tag,
    ROOT_IS_PURELIB=full_tag.endswith("-any"),
)

# Only *.py is included automatically by setup2toml.
# Add extra 'purelib' files or package_data here.
py_source = Glob("chiaswap/*.py") + Glob("chiaswap/*.cl")

chiaswap = env.Whl("purelib", py_source, root="")
whl = env.WhlFile(source=chiaswap)

# It's easier to just use Glob() instead of FindSourceFiles() since we have
# so few installed files..
sdist_source = (
    File(["PKG-INFO", "README.md", "SConstruct", "pyproject.toml"]) + py_source
)
sdist = env.SDist(source=sdist_source)
env.NoClean(sdist)
env.Alias("sdist", sdist)

# needed for pep517 (enscons.api) to work
env.Default(whl, sdist)


# TODO: run -d chiaswap/p2_delayed_or_preimage.cl > chiaswap/p2_delayed_or_preimage.cl.hex
