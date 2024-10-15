import getpass
import pandas as pd
import os
import time

import sys
sys.path.append('log-preprocessor')
from tools.run_AMiner import run_AMiner

class AMinerModel:
    """This class contains the functionality to train and test the AMiner in a 'scikit-learn'-like way."""

    def __init__(
            self,
            config: dict,
            permanent_permission=False,
            input_path="/tmp/aminer/current_data.log", # single input file - whole data (train + test)
            output_path="/tmp/aminer_out.json", # output file has to be in /tmp
            tmp_dir="/tmp/aminer", 
        ):
        self.config = config
        self.tmp_dir = tmp_dir
        os.makedirs(tmp_dir, exist_ok=True)
        self.input_path = input_path
        self.output_path = output_path
        # probably not best practice but necessary as long as we use the aminer.py script
        self.password = None
        if permanent_permission:
            self.password = getpass.getpass("Enter sudo password: ")

    def fit(self, df: pd.DataFrame, print_progress=True):
        """Train the AMiner with the given data."""
        if print_progress:
            print("Training AMiner ...")
        start = time.time()
        run_AMiner(
            df, # specify training df
            input_path=self.input_path, 
            output_path="/tmp/aminer_training_out.json", # output often not needed
            config=self.config,
            training=True, 
            label="train",
            tmp_dir=self.tmp_dir,
            password=self.password
        )
        self.last_runtime = time.time() - start
        if print_progress:
            print(f"Finished. (runtime: {self.last_runtime})")
    
    def predict(self, df: pd.DataFrame, print_progress=True):
        """Test the AMiner with the given data."""
        if print_progress:
            print("Testing AMiner ...")
        start = time.time()
        run_AMiner(
            df, # specify test df
            input_path=self.input_path, 
            output_path=self.output_path,
            config=self.config, 
            training=False, 
            label="test",
            tmp_dir=self.tmp_dir,
            password=self.password
        )
        self.last_runtime = time.time() - start
        if print_progress:
            print(f"Finished. (runtime: {self.last_runtime})")
        print("Raw results saved to:", self.output_path)
    
    def fit_predict(self, df_train: pd.DataFrame, df_test: pd.DataFrame, print_progress=True):
        """Train and test the AMiner with the given data."""
        self.fit(df_train, print_progress=True)
        self.predict(df_test, print_progress=True)
