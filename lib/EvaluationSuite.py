import os
import pandas as pd
import json
import numpy as np
import time
import yaml
import getpass

# import from submodule
import sys
sys.path.append('log-preprocessor')
from LogData import LogData
from tools.AMinerModel import AMinerModel
from utils.constants import DETECTOR_ID_DICT

from lib.configUtils import *
from lib.transformationUtils import *
from lib.Evaluation import Evaluation

def in_jupyter_notebook():
    """Check if the function was called from within a jupyter notebook."""
    try:
        # Check if the get_ipython function exists (unique to IPython environments)
        from IPython import get_ipython
        ipy_instance = get_ipython()
        if ipy_instance and 'IPKernelApp' in ipy_instance.config:
            return True
        else:
            return False
    except ImportError:
        # IPython is not installed, likely not running in a Jupyter notebook
        return False

def get_attack_idx(path, offset=0):
    """Returns the attack row numbers (indices) from the specifed attack labels file."""
    rows = []
    with open(path, 'r') as file:
        for line in file:
            rows.append(json.loads(line)["line"])
    return list(np.array(rows) - 1 + offset)

class EvaluationSuite:
    """This class contains all the functionality that is required for the initialization of this project."""

    def __init__(
            self,
            data_dir: str,
            label_file_path: str,
            config_file_path: str,
            parser_name: str,
            use_parsed_data=True,
            tmp_save_path="/tmp/current_data.log"
        ):
        """Initialize evaluation pipeline."""
        self.label_file_path = label_file_path
        self.parser_name = parser_name
        self.tmp_save_path = tmp_save_path
        # get the data
        print("\n------------------------------- DATA EXTRACTION -------------------------------")
        start = time.time()
        data = LogData(
            data_dir,
            parser_name,
            tmp_save_path=self.tmp_save_path
        )
        self.df = data.get_df(use_parsed_data)
        print(f"Data extraction finished. (runtime: {time.time() - start})")

        with open("settings/config.yaml") as file:
            self.settings = yaml.safe_load(file)
        self.considered_atacks = self.settings["considered_attacks"]

        # multiple data files introduce an offset to the labels' attack line numbers 
        input_filenames = [os.path.basename(path) for path in data.input_filepaths]
        file_with_attacks_idx = input_filenames.index(os.path.basename(label_file_path)) # get idx of file with attacks
        ordered_n_lines_list = [data.n_lines_per_file[file] for file in input_filenames]
        self.attack_offset = sum(ordered_n_lines_list[:file_with_attacks_idx])
        all_attack_idx = get_attack_idx(label_file_path, offset=self.attack_offset)
        self.attack_idx = sorted(list(set(all_attack_idx).intersection(set(self.df.index))))

        self.ts_attack = self.df["ts"][self.attack_idx]
        self.df_attack_periods = self.get_attack_periods()
        self.attack_start = self.ts_attack.iloc[0]
        self.attack_end = self.ts_attack.iloc[-1]

        self.df_train, self.df_test = self.df[:self.attack_idx[0]], self.df[self.attack_idx[0]:]
        self.test_offset = (0, len(self.df_train) - 1)

        with open(config_file_path) as file:
            self.config = yaml.safe_load(file)

    def evaluate(self, detector_ids="1,2,3,4,5,6,7"):
        """Evaluate the AMiner """
        print("\n------------------------------------ INFO -------------------------------------")
        self.print_info()
        detectors = [DETECTOR_ID_DICT[id] for id in detector_ids.split(",")]
        output_dir = self.init_output_dir(detectors)

        # to avoid detection of trivial anomalies
        if not any(d.get("type") == "NewMatchPathDetector" for d in self.config["Analysis"]):
            self.config["Analysis"].append({
                "type": "NewMatchPathDetector",
                "id": "NewMatchPathDetector",
                "suppress": True
            })
        # to avoid recognition of unparsed log lines as detected anomalies
        if not any(d.get("type") == "VerboseUnparsedAtomHandler" for d in self.config["Analysis"]):
            self.config["Analysis"].append({
                "type": 'VerboseUnparsedAtomHandler',
                "id": "VerboseUnparsedAtomHandler",
                "suppress": True
            })
        print("\n--------------------------------- EVALUATION ----------------------------------")
        # get password if execution is in jupyter notebook
        pwd=None
        if in_jupyter_notebook():
            print("(running in Jupyter notebook)")
            if pwd is None:
                pwd = getpass.getpass("Execution in jupyter notebook requires sudo password:")
        model = AMinerModel(
            config=self.config,
            input_path=self.tmp_save_path,
            tmp_dir=output_dir,
            pwd=pwd
        )
        model.fit_predict(self.df_train, self.df_test, print_progress=True)

        print("Evaluating results...")
        start = time.time()
        results_aminer = Evaluation(self.df_test, self.attack_idx, detectors, self.test_offset[0], self.test_offset[1])
        attack_tolerance = 0
        results_aminer.eval_per_time(self.df_attack_periods, attack_tolerance)
        print(f"Evaluation finished. (runtime: {time.time()-start})\n")

        results_aminer.print_results()

    def get_label_file_info(self) -> dict:
        """Returns a dict containing label file infos."""
        keywords = self.considered_atacks
        labels = {}
        with open(self.label_file_path, 'r') as file:
            data = [json.loads(line) for line in file.read().splitlines()]
            [labels.setdefault(label, []).append(line['line'] - 1 + self.attack_offset) for line in data for label in list(set(line['labels']).intersection(keywords))]
        for label in labels.keys():
            labels[label] = list(set(labels[label]).intersection(set(self.df.index)))
        info = {}
        for label in labels:
            info[label] = group_consecutive(labels.get(label))
        return info
    
    def get_attack_periods(self) -> pd.DataFrame:
        """Returns a dataframe containing the attack periods of each attack type."""
        timestamps = (self.ts_attack)
        info_attacks_timestamp = {}
        info_attacks = self.get_label_file_info()
        for key, value in info_attacks.items():
            new_values = []
            for start, end in value:
                new_values.append((timestamps[start], timestamps[end])) # index=linenumber-1
            info_attacks_timestamp[key] = new_values
        df = pd.DataFrame([info_attacks_timestamp]).T
        df.columns = ["attack_periods"]
        return df

    def init_output_dir(self, detectors: list):
        """Initialize output dir."""
        result_label = f"{str(len(self.df))}_samples"
        output_dir_rel = os.path.join("output", '_'.join(detectors), self.parser_name, result_label)
        output_dir = os.path.abspath(output_dir_rel)
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    
    def print_info(self):
        info = (
            f"\nDate range:       [{str(self.df['ts'].iloc[0])}] to [{str(self.df['ts'].iloc[-1])}]"
            f"\nAttack period:    [{str(self.attack_start)}] to [{str(self.attack_end)}]"
            f"\nTraining period:  [{str(self.df['ts'].iloc[0])}] to [{str(self.attack_start)}]"
            f"\nTraining time:    [{str(self.attack_start - self.df['ts'].iloc[0])}]"
            f"\nAttack offset:    {self.attack_offset}"
            f"\nTraining samples: {str(len(self.df_train))}"
            f"\nTest samples:     {str(len(self.df_test))}"
        )
        print(info)
        
