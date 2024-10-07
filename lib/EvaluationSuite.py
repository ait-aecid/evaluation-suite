import os
import argparse
import pandas as pd
import json
import numpy as np
import pickle
import time
import yaml

# import from submodule
import sys
sys.path.append('log-preprocessor')
from Data import Data

from lib.configUtils import *
from lib.transformationUtils import *

from utils.constants import DETECTOR_ID_DICT, POSSIBLE_TIMESTAMP_PATHS

def get_attack_idx(path, offset=0):
    """Returns the attack row numbers (indices) from the specifed attack labels file."""
    rows = []
    with open(path, 'r') as file:
        for line in file:
            rows.append(json.loads(line)["line"])
    return list(np.array(rows) - 1 + offset)

class EvaluationSuite:
    """This class contains all the functionality that is required for the initialization of this project."""

    def __init__(self, params):
        """Initialize evaluation pipeline."""

        self.__dict__.update(params)
        os.makedirs("tmp", exist_ok=True) # create tmp directory
        os.makedirs(os.path.join("tmp", "data_parsed"), exist_ok=True)
        self.tmp_save_path = os.path.join("tmp", "current_data.log")
        self.detectors = [DETECTOR_ID_DICT[id] for id in self.detector_ids.split(",")]
        # get the data
        start = time.time()
        data = Data(
            self.data_dir,
            self.parser_name,
            POSSIBLE_TIMESTAMP_PATHS,
            tmp_save_path=self.tmp_save_path
        )
        self.df = data.get_df(self.use_parsed_data)
        print(f"Finished data extraction (runtime: {time.time() - start}).")

        with open("config.yaml") as file:
            self.eval_config = yaml.safe_load(file)
        self.considered_atacks = self.eval_config["considered_attacks"]

        # multiple data files introduce an offset to the labels' attack line numbers 
        input_filenames = [os.path.basename(path) for path in data.input_filepaths]
        file_with_attacks_idx = input_filenames.index(os.path.basename(self.label_file_path)) # get idx of file with attacks
        ordered_n_lines_list = [data.n_lines[file] for file in input_filenames]
        self.attack_offset = sum(ordered_n_lines_list[:file_with_attacks_idx])
        all_attack_idx = get_attack_idx(self.label_file_path, offset=self.attack_offset)
        self.attack_idx = sorted(list(set(all_attack_idx).intersection(set(self.df.index))))

        self.ts_attack = self.df["ts"][self.attack_idx]
        self.df_attack_periods = self.get_attack_periods()
        self.attack_start = self.ts_attack.iloc[0]
        self.attack_end = self.ts_attack.iloc[-1]

        self.df_train, self.df_test = self.df[:self.attack_rows[0]], self.df[self.attack_rows[0]:]
        self.test_offset = (0, len(self.df_train) - 1)

    
    def get_timestamps(self, interval=None):
        """Get a list of match dictionaries from log data."""
        timestamps = []
        with open(self.data_path, "rb") as file:
            for _ in range(interval[0]): # skip lines
                file.readline()
            for i in range(interval[0], interval[1]):
                line_data = file.readline().strip()
                if not line_data:
                    break
                text_data = line_data.decode("utf-8")
                timestamps.append(self.get_timestamp_from_string(text_data))
        # unwrap contents of match_dict_list from custom class objects (MatchElement) to type string.
        return pd.to_datetime(timestamps).tz_localize(None)

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
        #print(timestamps)
        info_attacks_timestamp = {}
        info_attacks = self.get_label_file_info()
        #print(info_attacks)
        for key, value in info_attacks.items():
            new_values = []
            for start, end in value:
                new_values.append((timestamps[start], timestamps[end])) # index=linenumber-1
            info_attacks_timestamp[key] = new_values
        df = pd.DataFrame([info_attacks_timestamp]).T
        df.columns = ["attack_periods"]
        return df

    def aminer_run(self, X, analysis_config, training: bool, label: str):
        """Fit AMiner to training data and predict test data."""
        outputfile = os.path.join(self.output_dir, "data", label + ".log")
        config_path = os.path.join(self.output_dir, "config", label + ".yaml")
        # save data for aminer
        copy_and_save_file(self.data_path, outputfile, list(X.index))
        # update config
        self.config["LearnMode"] = training
        self.config["LogResourceList"] = [self.project_dir_abs + outputfile]
        self.config["Analysis"] = analysis_config
        self.config["LogLineIdentifier"] = True
        # parse to config file
        dump_config(config_path, self.config)
        # run AMiner
        if training:
            command = f"sudo -S aminer -C -o -c " + config_path
        else:
            command = f"sudo -S aminer -o -c " + config_path
        os.system(command)

    def init_output_dir(self):
        """Initialize output dir."""
        if self.predefined_config!=None:
            prefix = self.predefined_config_path.split(".")[0].split("/")[-1]
        else:
            prefix = "ace"
        self.result_label = f"{prefix}_R{self.train_splits}_S{str(len(self.current_X))}"
        self.output_dir = os.path.join("output", '_'.join(self.detectors), self.datatype, self.dataset, self.result_label)
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "plots"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "data"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "config"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "optimization"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "optimization", "data"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "optimization", "config"), exist_ok=True)
    
    def print_info(self, verbose=True):
        if verbose:
            print("\nDate range:\t\t[" + str(self.df["ts"].iloc[0]) + "] to [" + str(self.df["ts"].iloc[-1]) + "]")
            print("Attack period:\t\t[" + str(self.attack_start) + "] to [" + str(self.attack_end) + "]")
            print("Training period: \t[" + str(self.df["ts"].iloc[0]) + "] to [" + str(self.attack_start) + "]")
            print("Training time: \t\t[" + str(self.attack_start - self.df["ts"].iloc[0]) + "]")
            print(f"Attack offset:\t\t{self.attack_offset}")
        print("\nTraining samples:\t" + str(len(self.df_train)))
        print("Test samples:\t\t" + str(len(self.df_test)))
        print("----------------------------------------------")
