from mud import parse_mud_file
import argparse
import os

"""
Helper file just to verify we can parse all mud files
"""

def get_json_files(folder: str):
    jsonfiles = []
    for entry in os.listdir(folder):
        full_path = os.path.join(folder, entry)
        if os.path.isdir(full_path):
            jsonfiles += [os.path.join(full_path, file) for file in os.listdir(full_path) if file.endswith('Mud.json')]
        if entry.endswith('Mud.json'):
            jsonfiles.append(entry)
    return jsonfiles


def main(folder: str):
    """
    Read all json files in a given directory, verify we can parse all ipv4 rules
    :raises Exception if can't parse a rule
    """
    files = get_json_files(folder)
    for file in files:
        print(f'doing file {file}')
        parse_mud_file(file, {}, raise_on_unknown_rule=True)


def get_args():
    parser = argparse.ArgumentParser(description='Pcap parser')
    parser.add_argument('-f', '--folder', dest='folder', required=True, help='folder to read muds from')

    return parser.parse_args()


if __name__ == '__main__':
    args = get_args()
    main(args.folder)
