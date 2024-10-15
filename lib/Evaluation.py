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
        self.abs_metrics = get_abs_metrics(attack_idx, self.alert_idx, self.test_idx)[1]
        self.rel_metrics = get_rel_metrics(self.abs_metrics)
        self.eval_dict = {
            "metrics" : self.abs_metrics, 
            #"rel" : self.rel_metrics
        }

    def eval_per_time(self, df_attack_periods, minutes_to_add):
        #self.info = self.get_relevant_info()
        self.df_attack_periods = df_attack_periods
        self.alert_timestamps = self.df_test.loc[self.alert_idx]["ts"]
        attack_type_evaluation = eval_by_attack_type(self.alert_timestamps, df_attack_periods, minutes_to_add)
        assert len(list(attack_type_evaluation.keys())) < 2, "More than one label file encountered. This is not supported!"
        self.attack_type_evaluation = attack_type_evaluation[list(attack_type_evaluation.keys())[0]]
        self.abs_metrics_over_time = self.get_abs_metrics_over_time(self.attack_type_evaluation)
        self.rel_metrics_over_time = get_rel_metrics(self.abs_metrics_over_time)
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
    


from datetime import timedelta, datetime
import itertools
import json
import pandas as pd
import numpy as np

def add_minutes_to_tuples(input_list: list, minutes_to_add: int = 5) -> list:
    return [(start_time, end_time + timedelta(minutes=minutes_to_add)) for start_time, end_time in input_list]


def is_timestamp_between(_time_intervals: list, timestamp: datetime) -> bool:
    return any(start_time <= timestamp <= end_time for start_time, end_time in _time_intervals)


def get_time_intervals_with_offset(attack_times, minutes_to_add=5):
    time_intervals = list(itertools.chain.from_iterable(attack_times))
    time_intervals_with_delta = add_minutes_to_tuples(time_intervals, minutes_to_add=minutes_to_add)
    return time_intervals_with_delta


def get_results_file(filename='/tmp/aminer_out.json') -> list:
    data = []
    with open(filename, 'r') as file:
        for line in file:
            data.append(json.loads(line))
    return data

# include in class?
def get_relevant_output(filename='/tmp/aminer_out.json') -> dict:
    aminer_out = get_results_file(filename)
    output = []
    for i in range(len(aminer_out)):
        detector = aminer_out[i]['AnalysisComponent']["AnalysisComponentType"]
        var = aminer_out[i]['AnalysisComponent']["AffectedLogAtomPaths"]
        #idx = aminer_out[i]['LogData']["LineNumber"] # "LineNumber" is a custom output !!!
        ts = pd.to_datetime(aminer_out[i]['LogData']["Timestamps"], unit="s")
        crit = aminer_out[i]['AnalysisComponent']["CriticalValue"] if "CriticalValue" in aminer_out[i]['AnalysisComponent'].keys() else None
        id = aminer_out[i]['AnalysisComponent']["AnalysisComponentName"]
        #output.append({"detector":detector, "id":id, "var":var, "idx":idx, "ts":ts, "crit":crit})
        output.append({"detector":detector, "id":id, "var":var, "ts":ts, "crit":crit})
    return pd.DataFrame(output, columns=["detector", "id", "var", "idx", "ts", "crit"])


def get_abs_metrics(actual_positives: list, predicted_positives: list, test_samples: list):
    """Classifies elemtents as TP, TN, FP, FN."""

    actual_set = set(actual_positives)
    predicted_set = set(predicted_positives)

    tp = sorted(list(actual_set.intersection(predicted_set)))
    fp = sorted(list(predicted_set.difference(actual_set)))
    fn = sorted(list(actual_set.difference(predicted_set)))
    tn = sorted(list(set(test_samples) - (set(tp) | set(fp) | set(fn))))
    sum = tp + fp + fn + tn
    try:
        assert len(test_samples) == len(sum), f"Number of test samples ({len(test_samples)}) is not equal to number of results ({len(sum)})!"
    except AssertionError as e:
        print(f'AssertionError: {e}')
        print(f"Affected elements: {set(sum).symmetric_difference(set(test_samples))}")
        raise SystemExit

    elements = {
        'FP': fp,
        'TN': tn,
        'TP': tp,
        'FN': fn,
    }
    counts = {key: len(val) for key, val in elements.items()}
    return elements, counts

def get_rel_metrics(abs_metrics: dict) -> dict:
    fp = abs_metrics["FP"]
    fn = abs_metrics["FN"]
    tp = abs_metrics["TP"]
    tn = abs_metrics["TN"]
    sum = tp + fp + fn + tn

    # safe divide
    div = lambda x,y: x/y if y != 0 else np.nan

    accuracy = div(tp + tn, sum)
    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    f1 = div(2 * precision * recall, precision + recall)

    metrics = {
        "Accuracy" : round(accuracy, 3),
        "Precision" : round(precision, 3),
        "Recall" : round(recall, 3), 
        "F1" : round(f1, 3)
    }
    return metrics


def evaluate_alerts(df_attack_periods: pd.DataFrame, aminer_out: pd.DataFrame) -> pd.DataFrame:
    new_df = aminer_out.copy()
    alert_evaluation = []

    for label_file in df_attack_periods:
        df_extended = df_attack_periods.explode(label_file)[label_file]
        for idx, ts in zip(aminer_out.index, aminer_out["ts"]):
            found_attacks = []
            for attack, period in df_extended.items():
                if is_timestamp_between([(period[0], period[1] + pd.Timedelta(minutes=0))], ts):
                    found_attacks.append(attack)
            alert_evaluation.append(found_attacks)
    new_df["found_attacks"] = alert_evaluation
    return new_df


def eval_by_attack_type(alert_timestamps, attack_ts_df: pd.DataFrame, minutes_to_add=5):
    """Returns a dict with attack types as keys and the number of how often they were identified as values."""

    attacks_dict_raw = attack_ts_df.to_dict()
    # get multiple keys for attacks with multiple attack periods
    attacks_dict = {}
    for label_file in attacks_dict_raw.keys():
        attacks_dict[label_file] = {}
        for key, val in attacks_dict_raw[label_file].items():
            for i, period in enumerate(val):
                attacks_dict[label_file][key + str(i) if i != 0 else key] = [period]
    eval_access = Ev(attack_ts_df)
    alert_ts_set = set(alert_timestamps)
    eval_dict = {key: {key: 0 for key, val in attacks_dict[key].items()} for key, val in attacks_dict.items()}
    #print(alert_ts_set)
    for alert_ts in alert_ts_set:
        for label_file in attacks_dict:
            if eval_access.check_timestamp(alert_ts, minutes_to_add)[label_file]:
                for attack_type in attacks_dict[label_file]:
                    attack_ts_with_offset = add_minutes_to_tuples(attacks_dict[label_file][attack_type], minutes_to_add)
                    if is_timestamp_between(attack_ts_with_offset, alert_ts):
                        eval_dict[label_file][attack_type] += 1
            else:
                if "FP" in eval_dict[label_file].keys():
                    eval_dict[label_file]["FP"] += 1
                else: 
                    eval_dict[label_file]["FP"] = 1
    return eval_dict


class Ev:
    def __init__(self, df_attack_times):
        self.df_attack_times = df_attack_times

    def check_timestamp(self, _timestamp: datetime, minutes_to_add: int = 5) -> dict:
        results = {}
        for col in self.df_attack_times:
            time_intervals_with_delta = (
                get_time_intervals_with_offset(self.df_attack_times[col].dropna().tolist(), minutes_to_add))
            results[col] = is_timestamp_between(time_intervals_with_delta, _timestamp)
        return results
    
    

    # TODO: add method to check list of timestamps
    # TODO: add function for evaluation metrics
    # TODO: ? method for only one list of tuples needed? -> maybe a better init can be found
