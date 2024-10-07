import time
from lib.configUtils import *
from lib.AminerConfigurationEngine import AminerConfigurationEngine as ace

def get_args():
    """TBA"""
    return
    
def set_value(d, keys, new_value):
    """
    Recursively traverse the dictionary using the list of keys.
    Sets the value at the specified level if found.
    """
    if len(keys) == 1:  # If only one key left, set the value
        d[keys[0]] = new_value
    else:
        key = keys[0]  # Get the first key
        if key in d:  # Check if the key exists in the dictionary
            set_value(d[key], keys[1:], new_value)  # Recursively call with remaining keys


def main(
    df_train=None, 
    df_test=None, 
    data_path="", 
    label="", 
    parser="", 
    detectors=[], 
    predefined_config=None, 
    output_dir="output", 
    test_run=False,
    hyperparam_tuning=None
):
    """Main function of the configuration automation process for the AMiner."""

    #return None, None

    # initialize AminerConfigurationEngine
    Ace = ace(data_path, parser, detectors, output_dir)
    # df_train should actually be created in ace() - implement later

    # hyperparam tuning - delete later
    if hyperparam_tuning is not None:
        print("\nHyperparametertuning:", hyperparam_tuning)
        set_value(Ace.settings, hyperparam_tuning["hp_path"], hyperparam_tuning["hp_value"])
    
    print("\nConfiguring detectors ...")
    start = time.time()
    
    analysis_config = Ace.configure_detectors(df_train, predefined_config)

    config_runtime = time.time()-start
    print(f"Configuration completed (runtime: {config_runtime})\n")

    # delete later!!
    analysis_config.append({
        "type": "NewMatchPathDetector",
        "id": "NewMatchPathDetector",
        "suppress": True
    })
    analysis_config.append({
        "type": 'VerboseUnparsedAtomHandler',
        "id": "VerboseUnparsedAtomHandler",
        "suppress": True
    })

    print("Run AMiner ...")
    start = time.time()
    Ace.aminer_run(df_train, analysis_config, True, "train" + label)
    if test_run:
        Ace.aminer_run(df_test, analysis_config, False, "test" + label)
    aminer_runtime = time.time()-start
    print(f"AMiner finished (runtime: {aminer_runtime})")

    return config_runtime, aminer_runtime

if __name__ == "__main__":
    input_args = get_args()
    main(*input_args)