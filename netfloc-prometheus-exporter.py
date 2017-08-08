# Copyright (c) 2017. Zuercher Hochschule fuer Angewandte Wissenschaften
#  All Rights Reserved.
#
#     Licensed under the Apache License, Version 2.0 (the "License"); you may
#     not use this file except in compliance with the License. You may obtain
#     a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#     WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#     License for the specific language governing permissions and limitations
#     under the License.

################################################################################
# Netfloc exporter for Prometheus: Scrapes metrics from Netfloc monitoring module.
# These metrics are exposed via the OpenFlow plugin statistics Collector APIs:
# https://wiki.opendaylight.org/view/OpenDaylight_OpenFlow_Plugin:Statistics
# This exporter is based on the Jenkins Prometheus exporters:
# https://www.robustperception.io/writing-a-jenkins-exporter-in-python/
# https://github.com/lovoo/jenkins_exporter
################################################################################

#!/usr/bin/python
__author__ = 'traj'

import json
import re
import sys
import time
import argparse
import requests
from requests.exceptions import ConnectionError
import os

try:
  import urllib2
except:
  #Python 3
  import urllib.request as urllib2

from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY

# Hosts related to the data exported.
hosts_dict = {}

class NetflocCollector(object):
  def __init__(self, target, netfloc_inventory_url):
    self._target = target.rstrip("/")
    self._netfloc_inventory_url = netfloc_inventory_url

    try:
        inventory = requests.get(self._netfloc_inventory_url)
        hosts_data = json.loads(inventory.content).get("nodes").get("node")

        for host in hosts_data:

            ip_addr = host.get("flow-node-inventory:ip-address")
            host_name = self._ip_to_host_name_mapping(ip_addr)
            hosts_dict[host_name] = host.get("id")

    except ConnectionError:
        print "Netfloc is either not running or it is unreachable."

  def _ip_to_host_name_mapping(self, ip):
      return {
          '192.168.5.61': 'netfloc',
          '192.168.5.31': 'compute',
          '192.168.5.21': 'neutron',
          '192.168.5.11': 'control',
      }.get(ip, 'Wrong IP address.')

  def _setup_new_metrics(self, host, ports_list, flows_list):

    # Metrics to export from Netfloc.
    self._metrics_host = {}

    self._metrics_port = {}

    self._metrics_flow = {}

    openflow_id = hosts_dict[host].replace(":", "_")

    # Example metric: netfloc_packet_count_compute
    self._metrics_host[host] = {
    'byte-count':
    GaugeMetricFamily('netfloc_byte_count_'+host,
        'Netfloc byte count per node', labels=[openflow_id]),
    'flow-count':
    GaugeMetricFamily('netfloc_flow_count_'+host,
        'Netfloc flow count per node', labels=[openflow_id]),
    'packet-count':
    GaugeMetricFamily('netfloc_packet_count_'+host,
        'Netfloc packet count per node', labels=[openflow_id]),
    'active-flows':
    GaugeMetricFamily('netfloc_active_flows_'+host,
        'Netfloc active flows per node', labels=[openflow_id]),
    'packets-lookedup':
    GaugeMetricFamily('netfloc_packets_looked_up_'+host,
        'Netfloc packets lookedup per node', labels=[openflow_id]),
    'packets-matched':
    GaugeMetricFamily('netfloc_packets_matched_'+host,
        'Netfloc packets matched per node', labels=[openflow_id])
    }

    for port in ports_list:

        # Example metric: netfloc_bytes_received_control_eth1_1
        self._metrics_port[port] = {
        'packets-received':
        GaugeMetricFamily('netfloc_packets_received_'+host+'_'+port,
            'Netfloc packets received per node and per port', labels=[host+'_'+port]),
        'packets-transmitted':
        GaugeMetricFamily('netfloc_packets_transmitted_'+host+'_'+port,
            'Netfloc packets transmitted per node and per port', labels=[host+'_'+port]),
        'bytes-received':
        GaugeMetricFamily('netfloc_bytes_received_'+host+'_'+port,
            'Netfloc bytes received per node and per port', labels=[host+'_'+port]),
        'bytes-transmitted':
        GaugeMetricFamily('netfloc_bytes_transmitted_'+host+'_'+port,
            'Netfloc bytes transmitted per node and per port', labels=[host+'_'+port])
        }

    for flow in flows_list:

        # Example metric: netfloc_flow_packet_count_compute_ServiceChainEndRewrite_2_1_00_00_e8_94_f6_08_53_70
        self._metrics_flow[flow] = {
        'flow-duration':
        GaugeMetricFamily('netfloc_flow_duration_'+host+'_'+flow,
            'Netfloc flow duration per node', labels=[flow]),
        'flow-packet-count':
        GaugeMetricFamily('netfloc_flow_packet_count_'+host+'_'+flow,
            'Netfloc flow packet count per node', labels=[flow]),
        'flow-byte-count':
        GaugeMetricFamily('netfloc_flow_byte_count_'+host+'_'+flow,
            'Netfloc flow byte count per node', labels=[flow]),
        }

  def _request_netfloc_data(self, host, node_connector_list, flow_statistics_list):

    # Data to export from Netfloc.
    data_dict = {}

    try:
        # Flow table statistics per host (eg. netfloc, compute, control and neutron)
        table_flow_statistics_url = "%s%s%s%s" % (self._netfloc_inventory_url,'/node/',hosts_dict[host],'/table/0/opendaylight-flow-table-statistics:flow-table-statistics')
        table_flow_statistics = requests.get(table_flow_statistics_url)
        data_dict["table_flow_statistics"] = table_flow_statistics

        # Aggregate flow statistics per host (eg. netfloc, compute, control and neutron)
        aggregate_flow_statistics_url = "%s%s%s%s" % (self._netfloc_inventory_url,'/node/',hosts_dict[host],'/table/0/aggregate-flow-statistics/')
        aggregate_flow_statistics = requests.get(aggregate_flow_statistics_url)
        data_dict["aggregate_flow_statistics"] = aggregate_flow_statistics

        # Service Function Chain-related flow statistics per host (eg. netfloc, compute, control and neutron)
        data_dict["flow_statistics_list"] = flow_statistics_list

        # Port statistics per host (eg. netfloc, compute, control and neutron)
        data_dict["node_connector_list"] = node_connector_list


    except ConnectionError:
        print("Error fetching data from Netfloc.")

    return data_dict

  def _add_data_prometheus(self, data_dict, host, ports_list, flows_list):

    try:
        # Flow table statistics per host
        table_flow_statistics = json.loads(data_dict["table_flow_statistics"].content).get("opendaylight-flow-table-statistics:flow-table-statistics")
        self._metrics_host[host]['active-flows'].add_metric('active-flows', table_flow_statistics.get("active-flows"))
        self._metrics_host[host]['packets-lookedup'].add_metric('packets-lookedup', table_flow_statistics.get("packets-looked-up"))
        self._metrics_host[host]['packets-matched'].add_metric('packets-matched', table_flow_statistics.get("packets-matched"))
    except ConnectionError:
        print "Netfloc flow table statistics can not be retrieved."

    try:
        # Aggregate flow statistics per host
        aggregate_flow_statistics = json.loads(data_dict["aggregate_flow_statistics"].content).get("opendaylight-flow-statistics:aggregate-flow-statistics")
        self._metrics_host[host]['byte-count'].add_metric('byte-count', aggregate_flow_statistics.get("byte-count"))
        self._metrics_host[host]['flow-count'].add_metric('flow-count', aggregate_flow_statistics.get("flow-count"))
        self._metrics_host[host]['packet-count'].add_metric('packet-count', aggregate_flow_statistics.get("packet-count"))
    except ConnectionError:
        print "Netfloc aggregate flow statistics can not be retrieved."

    try:
        # Service Function Chain-related flow statistics per host (SFC flows priority=20)
        for key, value in data_dict["flow_statistics_list"].items():
            if key == "flow":
                for i in range(0, len(value)):
                    if value[i].get("opendaylight-flow-statistics:flow-statistics") is not None and value[i].get('priority') == 20:

                        flow_duration = value[i].get("opendaylight-flow-statistics:flow-statistics").get("duration").get("second")
                        flow_packet_count = value[i].get("opendaylight-flow-statistics:flow-statistics").get("packet-count")
                        flow_byte_count = value[i].get("opendaylight-flow-statistics:flow-statistics").get("byte-count")

                        self._metrics_flow[value[i].get('id').replace(":","_")]['flow-duration'].add_metric('flow-duration', flow_duration)
                        self._metrics_flow[value[i].get('id').replace(":","_")]['flow-packet-count'].add_metric('flow-packet-count', flow_packet_count)
                        self._metrics_flow[value[i].get('id').replace(":","_")]['flow-byte-count'].add_metric('flow-byte-count', flow_byte_count)

    except ConnectionError:
        print "Netfloc SFC flow statistics can not be retrieved."

    try:
        # Port statistics per host (eg. netfloc, compute, control and neutron)
        for key, value in data_dict["node_connector_list"].items():
            if "node-connector" in key:
                for i in range(0, len(value)):
                    if value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics") is not None:
                        packets_received = value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics").get("packets").get("received")
                        packets_transmitted = value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics").get("packets").get("transmitted")
                        bytes_received = value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics").get("bytes").get("received")
                        bytes_transmitted = value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics").get("bytes").get("received")

                        self._metrics_port[ports_list[i]]['packets-received'].add_metric('packets-received', packets_received)
                        self._metrics_port[ports_list[i]]['packets-transmitted'].add_metric('packets-transmitted', packets_transmitted)
                        self._metrics_port[ports_list[i]]['bytes-received'].add_metric('bytes-received', bytes_received)
                        self._metrics_port[ports_list[i]]['bytes-transmitted'].add_metric('bytes-transmitted', bytes_transmitted)
    except ConnectionError:
        print "Netfloc port statistics can not be retrieved."

  def collect(self):

    for host in hosts_dict:

        ports_list = []

        try:
            node_connector_url = "%s%s%s" % (self._netfloc_inventory_url,'/node/',hosts_dict[host])
            node_connector = requests.get(node_connector_url)
            node_connector_list = json.loads(node_connector.content).get("node")[0]

            # Iterate ports list to setup acceptable port name. Format: port_name_port_number: tap596e3e22_12_76 -> name: tap596e3e22-12 number: 76
            # Expeceted output example: [u'eth3_3', u'br0_LOCAL', u'eth2_2', u'eth1_1']
            for key, value in node_connector_list.items():
                if "node-connector" in key:
                    for i in range(0, len(value)):
                        port_name = value[i].get("flow-node-inventory:name")
                        new_port_name = str(port_name).replace("-","_")
                        port_number = value[i].get("flow-node-inventory:port-number")
                        ports_list.append(new_port_name+"_"+port_number)

        except ConnectionError:
            print "Netfloc port statistics can not be retrieved."

        flows_list = []

        try:
            flow_statistics_url =  "%s%s%s%s" % (self._netfloc_inventory_url,'/node/',hosts_dict[host],'/table/0/')
            flow_statistics = requests.get(flow_statistics_url)
            flow_statistics_list = json.loads(flow_statistics.content).get('flow-node-inventory:table')[0]

            # Iterate flows list to filter the IDs of the Service Function Chain flows (priority=20)
            # Format: flow_id: ServiceChainEndRewrite_3_1_00_00_e8_94_f6_08_53_70
            for key, value in flow_statistics_list.items():
                if key == "flow":
                    for i in range(0, len(value)):
                        if value[i].get('priority') == 20:
                            flow_id = value[i].get('id')
                            new_flow_id = str(flow_id).replace(":","_")
                            flows_list.append(new_flow_id)

        except ConnectionError:
            print "Netfloc flow statistics can not be retrieved."

        self._setup_new_metrics(host, ports_list, flows_list)
        data_dict = self._request_netfloc_data(host, node_connector_list, flow_statistics_list)
        self._add_data_prometheus(data_dict, host, ports_list, flows_list)

        for metric_host in self._metrics_host[host].values():
            yield metric_host

        for port in ports_list:
            for metric_port in self._metrics_port[port].values():
                yield metric_port

        for flow in flows_list:
            for metric_flow in self._metrics_flow[flow].values():
                yield metric_flow

def parse_args():
    parser = argparse.ArgumentParser(
        description='Netfloc exporter args - netfloc address, inventory and port'
    )
    parser.add_argument(
        '-n', '--netfloc',
        metavar='netfloc',
        required=False,
        help='Netfloc url',
        default=os.environ.get('NETFLOC_NODE', 'http://192.168.5.61:8181')
    )
    parser.add_argument(
        '-i', '--netfloc_inventory',
        metavar='netfloc_inventory',
        required=False,
        help='Netfloc inventory url',
        default=os.environ.get('NETFLOC_INVENTORY', 'http://admin:admin@192.168.5.61:8181/restconf/operational/opendaylight-inventory:nodes')
    )
    parser.add_argument(
        '-p', '--port',
        metavar='port',
        required=False,
        type=int,
        help='Exporter listens to this port',
        default=int(os.environ.get('VIRTUAL_PORT', '9118'))
    )
    return parser.parse_args()

def main():
    try:
        args = parse_args()
        port = int(args.port)
        REGISTRY.register(NetflocCollector(args.netfloc, args.netfloc_inventory))
        start_http_server(port)
        print "Polling data from Netfloc: %s. Server running on port: %s" % (args.netfloc, port)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(" Interrupted")
        exit(0)

if __name__ == "__main__":
    main()
