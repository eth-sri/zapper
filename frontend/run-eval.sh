#!/bin/bash

# usage:
# bash ./run-eval.sh [optional: <tag>]

###### CONFIG ######

OUT_BASE_DIR="eval/results"
CONDA_ENV_NAME="zapper"

####################

## Computing id and setting up directories

PROJECT_BASE_DIR=`dirname "$(readlink -f "$0")"`

if [[ "$#" -lt 1 ]]; then
    EXPERIMENT_TAG=""
else
    EXPERIMENT_TAG="_$1"
fi
EXPERIMENT_ID=`echo $RANDOM | md5sum | head -c 12`
NOW=`date +'%Y-%m-%d_%H-%M-%S'`
BASE_NAME="${NOW}_${EXPERIMENT_ID}${EXPERIMENT_TAG}"

OUT_DIR="${PWD}/${OUT_BASE_DIR}/${BASE_NAME}"
OUT_SYSINFO_FILE="${OUT_DIR}/${BASE_NAME}_sysinfo.txt"
OUT_LOG_FILE="${OUT_DIR}/${BASE_NAME}_log.log"
OUT_DATA_FILE="${OUT_DIR}/${BASE_NAME}_data.log"
OUT_BACKEND_DATA_FILE="${OUT_DIR}/${BASE_NAME}_backend_data.log"

####################

## Check git status and warn if not up to date

if [ -d ../.git ]; then
	GIT_REV=`git rev-parse HEAD`

	git remote update >/dev/null 2>&1

	NOF_CHANGES=`git status -uno --short | wc -l`
	if [[ "$NOF_CHANGES" -ne 0 ]]; then
		echo "WARNING: the current working copy contains uncommitted changes"
		git status -uno --short
		read -p "Do you nevertheless want to continue? [y/n] " yn
		case $yn in
			[Yy]* ) ;;
			[Nn]* ) exit;;
			* ) exit;;
		esac
	fi

	up_to_date=0
	git status | grep -q 'Your branch is up to date' && up_to_date=1
	if [[ "$up_to_date" -ne 1 ]]; then
		echo "WARNING: the current branch is not in sync with its remote tracking branch (forgot to pull?)"
		read -p "Do you nevertheless want to continue? [y/n] " yn
		case $yn in
			[Yy]* ) ;;
			[Nn]* ) exit;;
			* ) exit;;
		esac
	fi
else
	GIT_REV='NOT-A-GIT-REPO'
fi

####################

mkdir -p $OUT_DIR
echo "storing experiment results to $OUT_DIR"

## Storing system information to sysinfo file

# store git commit hash
echo "git revision: $GIT_REV" >> $OUT_SYSINFO_FILE

# get system information (host name, operating system)
echo "" >> $OUT_SYSINFO_FILE
uname -a >> $OUT_SYSINFO_FILE

# get CPU information
echo "" >> $OUT_SYSINFO_FILE
lscpu >> $OUT_SYSINFO_FILE

# get memory information
echo "" >> $OUT_SYSINFO_FILE
free -h >> $OUT_SYSINFO_FILE

# check if conda is installed
if [ -x "$(command -v conda)" ]; then
	# check if zapper environment exists
	if { conda env list | grep 'zapper'; } >/dev/null 2>&1; then

		# check if zapper environment is active
		if [ "$CONDA_DEFAULT_ENV" != "zapper" ]; then
			echo "WARNING: conda zapper environment is available but not active."
			read -p "Do you nevertheless want to continue? [y/n] " yn
			case $yn in
				[Yy]* ) ;;
				[Nn]* ) exit;;
				* ) exit;;
			esac
		fi
	fi
fi

####################

## Run actual experiment

# build backend
cd ${PROJECT_BASE_DIR}/../backend/py
cargo clean
export RUSTFLAGS="-C target-feature=+bmi2,+adx" # enable specialized instructions for high performance
time maturin build --release --no-sdist --interpreter python --manylinux off
WHL=(target/wheels/zapper_backend-*-cp310-cp310-linux*.whl)
pip install --force-reinstall $WHL

# run eval
cd ${PROJECT_BASE_DIR}/eval
touch $OUT_DATA_FILE
export ZAPPER_DATA_LOG_FILE=$OUT_DATA_FILE
export ZAPPER_BACKEND_DATA_LOG_FILE=$OUT_BACKEND_DATA_FILE
export ZAPPER_LOGGING_ENABLED=1
export ZAPPER_LOG_LEVEL="INFO"
export ZAPPER_LOG_DIRECTORY=$OUT_DIR
python run.py
