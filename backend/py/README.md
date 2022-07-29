# Zapper Backend Pyo3 Bindings

## Install (Development)

First, create/activate the Python environment where the backend should be installed:
```bash
conda activate zapper
```

Then, install [Maturin](https://github.com/PyO3/maturin):
```bash
pip install maturin
```

### Tiny version (faster tests and debugging)
Build the library and install the backend Python module `zapper_backend` into the current environment:
```bash
maturin develop --release --cargo-extra-args="--features tiny"
```

### Normal version
Build the library and install the backend Python module `zapper_backend` into the current environment:
```bash
maturin develop --release
```

## Use

After installing the library, simply import the module `zapper_backend` and use its members:
```python
import zapper_backend
```