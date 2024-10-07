from ruamel import yaml

def load_yaml_file(file_path):
    """Load .yaml file into a dictionary."""

    with open(file_path, 'r') as file:
        try:
            yaml_data = yaml.safe_load(file)
            return yaml_data
        except yaml.YAMLError as e:
            print(f"Error while loading YAML file: {e}")


def dump_config(filename : str, configuration : dict):
    """Create config file from dictionary."""
    #yaml.add_representer(float, represent_float)
    with open(filename, "w") as file:
        yaml.dump(configuration, file, sort_keys=False, indent=4)


def adapt_predefined_analysis_config(analysis_config, detectors, df, print_deleted=False):
    """Adapt a predefined analysis config. by filtering instances that were not specified or contain variables that are not given in the data."""

    allowed_items=["type","id","paths","persistence_id","output_logline", "season", "num_windows", "confidence_factor", "window_size", "prob_thresh"]
    adapted_config = []
    deleted_items = {"types": [], "paths": []}
    remaining_types = []
    remaining_paths = []

    conf = analysis_config.copy()
    for item in conf:
        if item["type"] not in detectors:
            deleted_items["types"].append(item["type"])
        elif not any(path in df.columns for path in item["paths"]):
            deleted_items["paths"].extend(item["paths"])
        else:
            item["output_logline"] = True
            new_item = {key: val for key, val in item.items() if key in allowed_items}
            remaining_types.append(new_item["type"])
            remaining_paths.append(new_item["paths"])
            adapted_config.append(new_item)
    if print_deleted:
        print(f"Remaining types: {remaining_types}")
        print(f"Remaining paths: {remaining_paths}\n")
    return adapted_config