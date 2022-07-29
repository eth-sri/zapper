# Specification for docker image
#
# Run and deploy by following the instructions in the Makefile


FROM python:3.10 as zapper-prerequisites

#######################
# PYTHON DEPENDENCIES #
#######################

# install dependencies
COPY zapper-copy/frontend/zapper.egg-info/requires.txt /requires.txt
RUN cat '/requires.txt'
RUN pip install `grep -v '^\[' /requires.txt`

########
# RUST #
########

# install rust (to build zapper_backend)
RUN apt-get update && apt-get install -y curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

# install maturin (to build PyO3 backend module)
RUN pip install maturin==0.12.14

##########
# ZAPPER #
##########

FROM zapper-prerequisites as zapper

# install latex (required for plots)
RUN apt-get update && apt-get install -y texlive texlive-latex-extra texlive-fonts-extra cm-super dvipng \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# copy
ENV ZAPPER_DIR /zapper
COPY zapper-copy $ZAPPER_DIR

# build and install backend
WORKDIR $ZAPPER_DIR/backend/py
ENV RUSTFLAGS="-C target-feature=+bmi2,+adx"
RUN maturin build --release --no-sdist --interpreter python --manylinux off
RUN pip install target/wheels/zapper_backend-*-cp310-cp310-linux*.whl

# install frontend
WORKDIR $ZAPPER_DIR/frontend
RUN pip install --upgrade --upgrade-strategy=eager --editable .[test]
RUN pytest --import-mode=importlib

WORKDIR $ZAPPER_DIR
