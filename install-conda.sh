#!/bin/bash
# Installs Zapper using conda

# enable bash strict mode
# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

# directory containing this script
BASEDIR="$( dirname "$0")"
cd "$BASEDIR"

#################
# PREPARE CONDA #
#################

set +u
# enable using conda from within this script
eval "$(conda shell.bash hook)"
set -u

######################
# CREATE ENVIRONMENT #
######################

CONDA_ENV="zapper"

echo "Removing potentially outdated old environment..."
conda deactivate
conda env remove --name $CONDA_ENV

echo "Creating and activating new environment..."
conda create --yes --name $CONDA_ENV python=3.10
conda activate $CONDA_ENV

#########################
# ENVIRONMENT VARIABLES #
#########################

conda env config vars set ZAPPER_ENABLE_LOGGING=true

########
# RUST #
########

conda install --yes -c conda-forge rust
pip install maturin==0.12.14

##########
# Zapper #
##########

cd backend/py
export RUSTFLAGS="-C target-feature=+bmi2,+adx" # enable specialized instructions for high performance
time maturin build --release --no-sdist --interpreter python --manylinux off
WHL=(target/wheels/zapper_backend-*-cp310-cp310-linux*.whl)
pip install $WHL
cd ../..

cd frontend
time pip install --upgrade --upgrade-strategy=eager --editable .[test]
cd ..
