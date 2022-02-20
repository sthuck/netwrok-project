# from mud import parse_mud_file, ParsedMudFile
# import argparse
# import pprint
# from extract_dns import extract_dns
# from iterate_pcap import iterate_pcap
#
# pp = pprint.PrettyPrinter(indent=2)
#
#
# def get_args():
#     parser = argparse.ArgumentParser(description='Pcap parser')
#     parser.add_argument('-f', '--file', dest='filename', required=True, help='pcap to parse')
#     parser.add_argument('-c', '--config', dest='config', required=True, help='mud file')
#
#     return parser.parse_args()
#
#
# def main(config: str, pcap: str):
#     _, ip_to_name = extract_dns(pcap)
#     configs = parse_mud_file(config, ip_to_name)
#     iterate_pcap(pcap, configs)
#     pp.pprint(configs)
#
#
# if __name__ == '__main__':
#     # main('./IoT_mud_files_locations/fire_tv_merged_uk/fire_tv_merged_ukMud.json', './merged_pcaps_only/firetv_merged_uk.pcapng')
#     args = get_args()
#     main(args.config, args.filename)
