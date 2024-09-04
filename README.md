# KERI Under Scrutiny: Use-Case Study for the Swiss e-ID | Master Thesis @ CS ETH Zurich

*Abstract*: This thesis presents an overview and an analysis of the distributed key management system KERI (Key Event Receipt Infrastructure) and its ecosystem with a focus on security and scalability. With the goal of providing the basis for a digital identity system for Switzerland, a KERI Network model is proposed and analyzed. The model is run on a large network of up to 10'000 users, the first time KERI has been tested at this scale. By using the keriox rust library we also contributed to its development. The final recommendation is that KERI is not suitable for the presented use case, but could be used to implement part of the infrastructure. 

This repository contains the code and the data collected during the thesis.

## Repository structure
The folder `basic-kel` contains the RUST code and the configuration data. `infra-test.rs` runs a KERI network locally by using the keriox executables in the `target_from_keriox` folder. `issuer.rs` is the issuer running locally and communicating with the AWS network, while `tests.rs` is the code of the client on the AWS network. `config` contains configuration files for both local and remote entities. `wit_wat_keypairs.json` are the pre-defined keys of witnessess and watchers for the AWS network.

The folder `amazon-aws` contains the script to spawn an amazon AWS KERI network. You need to install rust and provide an AWS key (to put in the folder `amazon-aws/private`). The variables KERIOX_DIRECTORY and TEST_DIRECTORY have to be adapted according to the local settings.

The folder `experiments` contains the results and the data collected during the thesis, as well as the plots code.
