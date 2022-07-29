# Zapper

Zapper is a privacy-focused smart contract system that hides the processed data and the identity of its users by leveraging encryption and non-interactive zero-knowledge proofs (specifically, zk-SNARKs). This repository contains an implementation of the Zapper system, which is described in the following [research paper][steffen2022zapper]:

> Samuel Steffen, Benjamin Bichsel, and Martin Vechev. 2022. _Zapper: Smart Contracts with Data and Identity Privacy._ In Proceedings of CCS ’22.

## Warning / Security Disclaimer

Zapper is a research project and its implementation should not be considered secure (e.g., it may contain bugs and has not undergone any security review)! Do not use Zapper in a productive system or to process sensitive confidential data.

## Installation and Usage

We recommend using Zapper via its Docker image.

To this end, install [docker](https://docs.docker.com/engine/install/ubuntu/) in [rootless mode](https://docs.docker.com/engine/security/rootless/)  (as an alternative to rootless mode, you can use `sudo` to run docker). Further, you will need the following general-purpose dependencies:

```bash
sudo apt-get install build-essential rsync
```

Then, running the following command will enter a shell inside a docker container with zapper installed.

```bash
cd docker
make run  # use `sudo make run` if you cannot run docker in rootless mode
```

### Unit tests

To check if your installation was successful, you can run Zapper's unit tests:

```bash
pytest --import-mode=importlib
```

### Run

To create a new application, follow the [existing examples](frontend/eval/scenarios). Then, you can compile it and run a specific scenario by following the [existing evaluation script](frontend/eval/run.py).

## CCS 2022 Evaluation

The original artifact evaluated in the [CCS 2022 paper][steffen2022zapper] can be found under the tag `ccs2022`. The evaluation consists of two parts: a main evaluation for fixed system parameters (folder `./frontend/eval`) and microbenchmarks for varying system parameters (folder `./microbench`).

### Reproduce Plots from Reference Data

This repository contains the reference data (see `./frontend/eval/results/reference` and `./microbench/*-results.log`) resulting from running the experiments on our machine and used to create the plots in the CCS 2022 paper. To reproduce these plots, run the following commands:

```bash
cd frontend/eval
python ./analyze_results.py
cd ../..
cd microbench
python ./analyze.py
cd ..
```

These commands produce the following outputs:
- in stdout: LaTex-friendly text containing key numbers and tables
- a PDF plot `./frontend/eval/circuit-components-plot.pdf`
- a PDF plot `./microbench/one-dim-params-plot.pdf`

If you want to copy files from your docker container to your host system,
you can use [docker cp](https://docs.docker.com/engine/reference/commandline/cp/) (from outside docker):

```bash
docker cp zapper:/zapper ./zapper-copied-from-docker-image  # copy all files to host
```

### Reproduce Results

To reproduce the evaluation results, run the following commands:

```bash
cd ./frontend
bash ./run-eval.sh           # main results
cd -
cd ./microbench
python ./run_microbench.py   # results for varying system parameters
cd -
```

_Note:_ The second command may take a long time to execute (several hours).

These commands produce the following outputs:
- a folder `./frontend/eval/results/<datetime>_<id>` containing JSON-formatted data in the `*_data.log` and `*_backend_data.log` files
- a file `./microbench/grid-results.log` containing data used for the least-squares fit of circuit size estimation coefficients
- a file `./microbench/line-results.log` containing data used to generate the microbenchmarking plots

## Development

To set up Zapper for development, we recommend using miniconda.

To this end, install [miniconda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/linux.html).

Then, install Zapper using

```bash
./install-conda.sh
```

To enter the installed Zapper environment, run:

```bash
conda activate zapper
```

## Citing this Work

You are encouraged to cite the following [research paper][steffen2022zapper] if you use Zapper for academic research.

```
@inproceedings{steffen2022zapper,
    author = {Steffen, Samuel and Bichsel, Benjamin and Vechev, Martin},
    title = {Zapper: Smart Contracts with Data and Identity Privacy},
    year = {2022},
    publisher = {Association for Computing Machinery},
    booktitle = {Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security},
    location = {Los Angeles, U.S.A.},
    series = {CCS ’22}
}
```

[steffen2022zapper]: https://www.sri.inf.ethz.ch/publications/steffen2022zapper