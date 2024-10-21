# Evaluation-Suite

This project automates the evaluation of the [logdata-anomaly-miner](https://github.com/ait-aecid/logdata-anomaly-miner) (AMiner).

## **Installation**
At first we have to install the [AMiner](https://github.com/ait-aecid/logdata-anomaly-miner). Follow the link for instructions.

Clone the repository from git:
```bash
git clone https://github.com/ait-aecid/evaluation-suite
git submodule update --init
```

## **Execution**

1. Drop relevant files into directory [data/](data/). The log data has to be of a single type (e.g. audit or Apache Access). The given sample data in directory [data/logs/](data/logs/) is Apache Access data from [AIT Log Data Set V2.0](https://zenodo.org/records/5789064) and should be removed before dropping new files. The label file in [data/labels](data/labels/) contains the labels for the anomalies in the data.
2. Execute the command (from within the directory) which lets you specify the following parameters:
```bash
python3 evaluate.py [-h] [-d DATA_DIR] [-pd USE_PARSED_DATA] [-l LABEL_FILE_PATH] [-p PARSER_NAME] [-id DETECTOR_IDS] [-c CONFIG_FILE_PATH]
```

For instance, this command will evaluate the AMiner with the given data and specified labels (using the Apache Access parser) for the detectors with IDs 1, 2 and 4 with the given configuration.
```bash
python3 evaluate.py -d data/logs -l data/labels/intranet.smith.russellmitchell.com-access2.log -p ApacheAccessParsingModel -id 1,2,4 -c example_config.yaml
```
For more information:
```bash
python3 evaluate.py --help
```

If the configuration of the AMiner seems to complicated, there is a possibility to automatically generate configurations using the [AMiner-Configuration-Engine](https://github.com/ait-aecid/aminer-configuration-engine).