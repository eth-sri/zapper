import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

packages = setuptools.find_packages(exclude=["tests.*", "tests"])
tests_require = [
    'pytest>=6.2.3,<7',
	'numpy==1.22',
	'pandas==1.4',
	'matplotlib==3.5'
]
setuptools.setup(
    name="zapper",
    version="0.0.1",
    description="Support smart contracts with data privacy and identity privacy.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=packages,
    python_requires='>=3.10',
    install_requires=[
        'appdirs>=1.4.4,<2',
        'enforce-typing>=1.0.0,<2'
    ],
    tests_require=tests_require,
    extras_require={
        'test': tests_require
    }
)
