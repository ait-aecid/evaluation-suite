import json
import numpy as np
import pandas as pd
import shutil
import itertools

# unused rn
def get_results_file(filename='/tmp/aminer_out.json', save=False, save_to="tmp/aminer_out.json"):
    """Get output file that was generated from running the AMiner. JSON format is expected ('pretty=false')."""
    data = []
    with open(filename, 'r') as file:
        for line in file:
            data.append(json.loads(line))
    if save:
        shutil.copy(filename, save_to)
    return data

def get_alert_idx_from_file(filename='/tmp/aminer_out.json', offset1=0, offset2=0, save=False, save_to="tmp/aminer_out.json"):
        """Returns the row numbers that triggered alerts."""
        offset2 = offset2 + 1 # offset is exclusive
        alerts = set()
        with open(filename, "r") as file:
            for line in file:
                alert_rel = json.loads(line)["LogLineIdentifier"]
                if offset1 == 0:
                    alert = alert_rel + offset2
                else:
                    if alert_rel < offset1:
                        alert = alert_rel
                    else:
                        alert = alert_rel + offset2 - offset1
                alerts.add(alert)
        if save:
            shutil.copy(filename, save_to)
        return list(alerts)


class Evaluation():
    """This class contans functions for evaluating the AMiner output."""

    def __init__(self, df_test, attack_idx, detectors=[], offset1=0, offset2=0, save=False, save_to="tmp/aminer_out.json"):
        self.attack_idx = attack_idx
        self.detectors = detectors
        self.df_test = df_test
        self.test_idx = list(df_test.index)
        #self.results = get_results_file(save=save, save_to=save_to)
        self.alert_idx = get_alert_idx_from_file('/tmp/aminer_out.json', offset1, offset2)
        self.abs_metrics = evaluation.get_abs_metrics(attack_idx, self.alert_idx, self.test_idx)[1]
        self.rel_metrics = evaluation.get_rel_metrics(self.abs_metrics)
        self.eval_dict = {
            "metrics" : self.abs_metrics, 
            #"rel" : self.rel_metrics
        }

    def eval_per_time(self, df_attack_periods, minutes_to_add):
        #self.info = self.get_relevant_info()
        self.df_attack_periods = df_attack_periods
        self.alert_timestamps = self.df_test.loc[self.alert_idx]["ts"]
        attack_type_evaluation = evaluation.eval_by_attack_type(self.alert_timestamps, df_attack_periods, minutes_to_add)
        assert len(list(attack_type_evaluation.keys())) < 2, "More than one label file encountered. This is not supported!"
        self.attack_type_evaluation = attack_type_evaluation[list(attack_type_evaluation.keys())[0]]
        self.abs_metrics_over_time = self.get_abs_metrics_over_time(self.attack_type_evaluation)
        self.rel_metrics_over_time = evaluation.get_rel_metrics(self.abs_metrics_over_time)
        self.eval_dict["metrics_over_time"] = self.abs_metrics_over_time
        #self.eval_dict["rel_over_time"] = self.rel_metrics_over_time

    def print_results(self):
        keys_to_print = ["FP", "TN", "TP", "FN"]  
        print("Absolute (point-anomaly):", {key: self.abs_metrics[key] for key in keys_to_print})
        print("Relative (point-anomaly):", self.rel_metrics, "\n")
        if self.abs_metrics_over_time:
            #print(self.attack_type_evaluation)
            print("Absolute (collective-anomaly):", {key: self.abs_metrics_over_time[key] for key in keys_to_print})
            print("Relative (collective-anomaly):", self.rel_metrics_over_time)

    def get_abs_metrics_over_time(self, attack_type_evaluation: dict) -> dict:
        """Get metrics evaluated over time periods of the different attacks."""
        metrics = {}
        if "FP" in attack_type_evaluation.keys():
            actual_tp = len(attack_type_evaluation) - 1 # "FP" is also counted therefore -1
            fp = attack_type_evaluation["FP"]
        else:
            actual_tp = len(attack_type_evaluation)
            fp = 0
        tp = sum([1 for key, val in attack_type_evaluation.items() if val != 0 and key != "FP"])
        fn = actual_tp - tp
        tn = len(self.df_test) - (tp + fp + fn)
        metrics = {
            "FP": fp,
            "TN": tn,
            "TP": tp,
            "FN": fn
        }
        return metrics
        
    def get_relevant_info(self) -> dict:
        """Returns detector type, id of the triggered instance, line index, timestamp and variable(s) for each alert."""
        results = get_results_file()
        info = []
        for detector in self.detectors:
            for i in range(len(results)):
                if results[i]['AnalysisComponent']["AnalysisComponentType"].startswith(detector):
                    var = results[i]['AnalysisComponent']["AffectedLogAtomPaths"]
                    idx = results[i]["LogLineIdentifier"]
                    ts = pd.to_datetime(results[i]['LogData']["Timestamps"], unit="s")
                    crit = results[i]['AnalysisComponent']["CriticalValue"] if "CriticalValue" in results[i]['AnalysisComponent'].keys() else None
                    id = results[i]['AnalysisComponent']["AnalysisComponentName"]
                    info.append({"detector":detector, "id":id, "var":var, "idx":idx, "ts":ts, "crit":crit})
        return pd.DataFrame(info, columns=["detector", "id", "var", "idx", "ts", "crit"])
    

    

