import pandas as pd
import os
import argparse
import time
from itertools import product
from lib.EvaluationSuite import EvaluationSuite
from lib.Evaluation import Evaluation
from lib.AMinerModel import AMinerModel

# import from submodule
import sys
sys.path.append('log-preprocessor')
from utils.constants import DETECTOR_ID_DICT

# from tools.plotter import *
# from main import main
# from lib.AminerConfigurationEngine import AminerConfigurationEngine as ace
# from lib.Evaluation import Evaluation

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
    start_total = time.time()
    evaluator = EvaluationSuite(**params)
    
    evaluator.print_info(verbose=True)

    # to avoid detection of trivial anomalies
    # evaluator.config["Analysis"].append({
    #     "type": "NewMatchPathDetector",
    #     "id": "NewMatchPathDetector",
    #     "suppress": True
    # })
    # # forgot why this is here but i think it is important
    # evaluator.config["Analysis"].append({
    #     "type": 'VerboseUnparsedAtomHandler',
    #     "id": "VerboseUnparsedAtomHandler",
    #     "suppress": True
    # })

    model = AMinerModel(
        config=evaluator.config,
        permanent_permission=False,
        input_path=evaluator.tmp_save_path,
        tmp_dir=evaluator.output_dir
    )
    model.fit_predict(evaluator.df_train, evaluator.df_test, print_progress=True)

    print("\nEvaluating results...")
    start = time.time()
    results_aminer = Evaluation(evaluator.df_test, evaluator.attack_idx, evaluator.detectors, evaluator.test_offset[0], evaluator.test_offset[1])
    attack_tolerance = 0
    results_aminer.eval_per_time(evaluator.df_attack_periods, attack_tolerance)
    print(f"Evaluation completed (runtime: {time.time()-start})\n")

    # # add runtimes to results
    # results_aminer.eval_dict["metrics"]["Runtime Configuration"] = config_runtime
    # results_aminer.eval_dict["metrics_over_time"]["Runtime Configuration"] = config_runtime
    # results_aminer.eval_dict["metrics"]["Runtime AMiner"] = aminer_runtime
    # results_aminer.eval_dict["metrics_over_time"]["Runtime AMiner"] = aminer_runtime

    # # add hyperparam to results
    # if evaluator.hyperparameter_tuning:
    #     results_aminer.eval_dict["metrics"]["hp_value"] = evaluator.hp_value
    #     results_aminer.eval_dict["metrics_over_time"]["hp_value"] = evaluator.hp_value

    results_aminer.print_results()

    # plot stuff
    #plot_dicts_by_key(scores, range(len(samples)), samples, ', '.join(evaluator.detectors), os.path.join(evaluator.output_dir, "plots", "abs_metrics"), xlabel="Sample size", save=True)

    end_total = time.time()
    print("\nTotal runtime:", end_total-start_total, "seconds")
    print("------------------------------------------------------------------------------------------------")
    return results_aminer.eval_dict

params = get_args()

evaluate(params)

# all_params = {
#     "dataset" : [
#         "russellmitchell",
#         #"fox",
#         #"harrison",
#         #"mail.onion.com",
        
#         # "santos",
#         # "shaw",
#         # "wardbeck", 
#         # "wheeler",  
#         # "wilson",
#         # "mail.spiral.com",
#         # "mail.insect.com",
#         # "mail.cup.com"
#     ],
#     "parser" : [
#         "ApacheAccessParsingModel",
#         #"AuditdParsingModel",
#     ], 
#     "train_splits" : [1],
#     "split_function" : ["x"], #(0.5*x)**2
#     "detector_ids" : ["1"],
#     "predefined_config_path" : [
#         None,
#         # "baseline/original/landauer.yml",
#         # "baseline/adapted/sauerzopf.yml",
#         # "baseline/adapted/hotwagner.yml",
#     ],
#     "max_train_test_samples" : [None],
#     "attack_tolerance": [0], # in minutes

#     # not more than one element per list !!!!
#     "hyperparameter_tuning" : [False],
#     "hp_path": [
#         #["ParameterSelection","NewMatchPathValueDetector","Variables","Select","Stable","segment_threshs"],
#         #["ParameterSelection","NewMatchPathValueComboDetector","Variables","Select","Co-OccurrenceCombos","min_co_occurrence"]
#         #["ParameterSelection","CharsetDetector","Variables","Select","Stable","segment_threshs"]
#         #["ParameterSelection","EntropyDetector","Variables","Select","CharacterPairProbability","mean_crit_thresh"],
#         #["ParameterSelection","ValueRangeDetector","Variables","Select","Stable","segment_threshs"],
#         ["ParameterSelection","EventFrequencyDetector","Variables","Select","EventFrequency","events_per_window"],
#     ],
#     "hp_value": [
#         #EventFrequencyDetector
#         #0.1,0.25,0.5,0.75,1.0,10.0,25.0,50.0,100.0

#         #entropydetector
#         #0.4,0.5,0.6,0.7,0.8,0.9

#         #combodetector
#         #0.0,0.01,0.1,0.5,0.9,1.0

#         #nmpvd
#         #[1.0, 0.819, 0.67, 0.549, 0.449],
#         #[1.0, 0.67, 0.449, 0.301, 0.202],
#         #[1.0, 0.549, 0.301, 0.165, 0.091],
#         #[1.0, 0.449, 0.202, 0.091, 0.041],
#         #[1.0, 0.368, 0.135, 0.05, 0.018],
#         #[1.0, 0.247, 0.061, 0.015, 0.004],
#         #[1.0, 0.165, 0.027, 0.005, 0.001],
#         #[1.0, 0.0, 0.0, 0.0, 0.0]

#         # charset and valuerange detector
#         #[1.0,0.6065306597,0.3678794412,0.2231301601,0.1353352832,0.0820849986,0.0497870684,0.0301973834,0.0183156389,0.0111089965],
#         #[1.0,0.3678794412,0.1353352832,0.0497870684,0.0183156389,0.006737947,0.0024787522,0.000911882,0.0003354626,0.0001234098],
#         #[1.0,0.1353352832,0.0183156389,0.0024787522,0.0003354626,4.53999e-05,6.1442e-06,8.315e-07,1.125e-07,1.52e-08],
#         #[1.0,0.0183156389,0.0003354626,6.1442e-06,1.125e-07,2.1e-09,0.0,0.0,0.0,0.0],
#         #[1.0, 0.0024787522, 6.1442e-06, 1.52e-08, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
#         #[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
#     ]
# }

# if not all_params["hyperparameter_tuning"][0]:
#     del all_params["hp_value"]

# # get all param combinations
# param_lists = list(all_params.values())
# combinations = list(product(*param_lists))
# param_grid = [{key : val for key, val in zip(all_params.keys(), combination)} for combination in combinations]
# n_param_combos = len(param_grid)

# # run over all combos
# eval_dicts = {}
# for i, params in enumerate(param_grid):
#     print(f"Run {i+1}/{n_param_combos}")
#     eval_dict = evaluation_pipeline(params)
#     if params["predefined_config_path"]:
#         add_str = "_" + params["predefined_config_path"].split(".")[0].split("/")[-1]
#     else:
#         add_str = ""
#     dataset_name = params["dataset"] + add_str
#     if dataset_name not in eval_dicts.keys():
#         eval_dicts[dataset_name] = []
#     eval_dicts[dataset_name].append(eval_dict)

# # postprocessing
    
# # hyperparameter tuning (hpt)
# if all_params["hyperparameter_tuning"][0]:
#     for dataset in eval_dicts.keys():
#         name = "_".join([p[-1] for p in all_params["hp_path"]])
#         detector_id = all_params["detector_ids"][0]
#         path = os.path.join("results/hp_tuning", all_params["parser"][0], f"detector_{detector_id}", name)
#         metrics_dicts_to_df(eval_dicts[dataset], to_csv=True, path=path, filename=f"{dataset}", hp_list=None)

# # save latest run - does not work for hpt!!!!
# # saves performance for multiple datasets
# if not all_params["hyperparameter_tuning"][0]:
#     res_point = {}
#     res_collective = {}
#     for dataset in eval_dicts.keys():
#         restructured_results = list_of_dicts_to_dict_of_lists(eval_dicts[dataset])
#         res_point[dataset] = restructured_results["metrics"][0]
#         res_collective[dataset] = restructured_results["metrics_over_time"][0]
#     df_point = calculate_metrics(pd.DataFrame(res_point).T).T
#     df_collective = calculate_metrics(pd.DataFrame(res_collective).T).T
#     df_point.to_csv("tmp/point_" + all_params["detector_ids"][0] + "_" + all_params["parser"][0] + ".csv")
#     df_collective.to_csv("tmp/collective_" + all_params["detector_ids"][0] + "_" + all_params["parser"][0] + ".csv")