import argparse
from lib.EvaluationSuite import EvaluationSuite

# import from submodule
import sys
sys.path.append('log-preprocessor')
from utils.constants import DETECTOR_ID_DICT

def get_args():
    """Returns command line arguments."""
    detector_help = f"Choose which detectors to be evaluated by their IDs (e.g., '13' means detectors with IDs 1 and 3): {str(DETECTOR_ID_DICT)}"
    parser = argparse.ArgumentParser(description="", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-d", "--data_dir", type=str, default="/data", help="Directory with data files. All log files in folder will be used as training data.")
    parser.add_argument("-pd", "--use_parsed_data", type=str, default="true", help="Use already parsed data if same data was previsouly parsed? Parsed data is saved temporarily in /tmp.")
    parser.add_argument("-l", "--label_file_path", type=str, default=None, help="Path to label file.")
    parser.add_argument("-p", "--parser_name", type=str, default="ApacheAccessParsingModel", help="Type of parser.")
    parser.add_argument("-id", "--detector_ids", type=str, default="1,2,3,4,5,6,7", help=detector_help)
    parser.add_argument("-c", "--config_file_path", type=str, default=None, help="Path to the configuration file.")
    args = parser.parse_args()
    return args.__dict__

def evaluate(params):
    detector_ids = params.pop("detector_ids")
    evaluator = EvaluationSuite(**params)
    evaluator.evaluate(detector_ids)

if __name__ == "__main__":
    params = get_args()
    evaluate(params)