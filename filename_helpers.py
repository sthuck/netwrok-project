

def get_pcap(device, country):
    return f'merged_pcaps_only/{device}_{country}.pcapng'


def get_pcap_dns(device, country):
    return f'merged_pcaps_only/DNS_only/{device}_{country}_DNS.pcapng'


def get_mud(device, country):
    device = device.replace('-', '_') \
        .replace('echodot', 'echo_dot') \
        .replace('echospot', 'echo_spot') \
        .replace('echoplus', 'echo_plus') \
        .replace('firetv', 'fire_tv') \
        .replace('wansview_cam_wired', 'wansview_cam')

    return f'IoT_mud_files_locations/{device}_{country}/{device}_{country}Mud.json'

