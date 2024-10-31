# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app import simple_switch_13
from ryu.lib import hub

import time
from datetime import datetime
import csv
import threading

# Variables to store packet timestamps and response times
packet_times = {}
response_times = []

# CSV setup to write response times per second (saved to the current directory)
csv_file_path = 'packet_response_times.csv'
flow_stats_file_path = './results/flow_stats.csv'
port_stats_file_path = './results/port_stats.csv'

# Ensure CSV headers are written
with open(csv_file_path, mode='w', newline='') as file:
	writer = csv.writer(file)
	writer.writerow(["Timestamp", "Average Response Time (ms)"])

# Ensure CSV headers are written for flow stats
with open(flow_stats_file_path, mode='w', newline='') as file:
	writer = csv.writer(file)
	writer.writerow(["DPID", "Packet Count", "Byte Count", "Duration Sec", "Duration NSec"])

# Ensure CSV headers are written for port stats
with open(port_stats_file_path, mode='w', newline='') as file:
	writer = csv.writer(file)
	writer.writerow(["DPID", "Port No", "RX Packets", "TX Packets", "RX Bytes", "TX Bytes", "RX Errors", "TX Errors"])


# Function to update CSV with average response time every second
def log_average_response_time():
	while True:
		if response_times:
			# Calculate the average response time for the last second
			average_response_time = sum(response_times) / len(response_times)
			
			# Get the current epoch timestamp (system time)
			epoch_timestamp = int(time.time())
			
			# Write the average response time for this second into the CSV
			with open(csv_file_path, mode='a', newline='') as file:
				writer = csv.writer(file)
				writer.writerow([epoch_timestamp, average_response_time])
			
			# Clear the response times list after logging the average
			response_times.clear()
		
		# Sleep for 1 second before calculating the next average
		time.sleep(1)

# Start the logging function in a separate thread
threading.Thread(target=log_average_response_time, daemon=True).start()

# Function to save flow stats to CSV
def log_flow_stats(dp, body):
	dpid_str = dpid_lib.dpid_to_str(dp.id)
	with open(flow_stats_file_path, mode='a', newline='') as file:
		writer = csv.writer(file)
		for stat in body:
			writer.writerow([dpid_str, stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec])

# Function to save port stats to CSV
def log_port_stats(dp, body):
	dpid_str = dpid_lib.dpid_to_str(dp.id)
	with open(port_stats_file_path, mode='a', newline='') as file:
		writer = csv.writer(file)
		for stat in body:
			writer.writerow([dpid_str, stat.port_no, stat.rx_packets, stat.tx_packets,
							 stat.rx_bytes, stat.tx_bytes, stat.rx_errors, stat.tx_errors])


class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'stplib': stplib.Stp}

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		
		#From Monitor
		self.datapaths = {}
		self.monitor_thread = hub.spawn(self._monitor)

		self.mac_to_port = {}
		self.stp = kwargs['stplib']

		# Sample of stplib config.
		#  please refer to stplib.Stp.set_config() for details.
		config = {dpid_lib.str_to_dpid('0000000000000001'):
				  {'bridge': {'priority': 0x8000}},
				  dpid_lib.str_to_dpid('0000000000000002'):
				  {'bridge': {'priority': 0x9000}},
				  dpid_lib.str_to_dpid('0000000000000003'):
				  {'bridge': {'priority': 0xa000}}}
		self.stp.set_config(config)

#------------------ Port Stats/Flow Stats Monitoring ------------------------

	@set_ev_cls(ofp_event.EventOFPStateChange,
				[MAIN_DISPATCHER, DEAD_DISPATCHER])
	def _state_change_handler(self, ev):
		datapath = ev.datapath
		if ev.state == MAIN_DISPATCHER:
			if datapath.id not in self.datapaths:
				self.logger.debug('register datapath: %016x', datapath.id)
				self.datapaths[datapath.id] = datapath
		elif ev.state == DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				self.logger.debug('unregister datapath: %016x', datapath.id)
				del self.datapaths[datapath.id]

	def _monitor(self):
		while True:
			for dp in self.datapaths.values():
				self._request_stats(dp)
			hub.sleep(10)

	def _request_stats(self, datapath):
		self.logger.debug('send stats request: %016x', datapath.id)
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		req = parser.OFPFlowStatsRequest(datapath)
		datapath.send_msg(req)

		req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
		datapath.send_msg(req)

	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def _flow_stats_reply_handler(self, ev):
		body = ev.msg.body
		dp = ev.msg.datapath
		log_flow_stats(dp, body)

		# self.logger.info('datapath         '
		# 				 'in-port  eth-dst           '
		# 				 'out-port packets  bytes')
		# self.logger.info('---------------- '
		# 				 '-------- ----------------- '
		# 				 '-------- -------- --------')
		# for stat in sorted([flow for flow in body if flow.priority == 1],
		# 				   key=lambda flow: (flow.match['in_port'],
		# 									 flow.match['eth_dst'])):
			# self.logger.info('%016x %8x %17s %8x %8d %8d',
			# 				 ev.msg.datapath.id,
			# 				 stat.match['in_port'], stat.match['eth_dst'],
			# 				 stat.instructions[0].actions[0].port,
			# 				 stat.packet_count, stat.byte_count)

	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def _port_stats_reply_handler(self, ev):
		body = ev.msg.body
		dp = ev.msg.datapath
		log_port_stats(dp, body)

		# self.logger.info('datapath         port     '
		# 				 'rx-pkts  rx-bytes rx-error '
		# 				 'tx-pkts  tx-bytes tx-error')
		# self.logger.info('---------------- -------- '
		# 				 '-------- -------- -------- '
		# 				 '-------- -------- --------')
		# for stat in sorted(body, key=attrgetter('port_no')):
		# 	self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
		# 					 ev.msg.datapath.id, stat.port_no,
		# 					 stat.rx_packets, stat.rx_bytes, stat.rx_errors,
		# 					 stat.tx_packets, stat.tx_bytes, stat.tx_errors)


#------------------ Spanning Tree Code ------------------------

	def delete_flow(self, datapath):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		for dst in self.mac_to_port[datapath.id].keys():
			match = parser.OFPMatch(eth_dst=dst)
			mod = parser.OFPFlowMod(
				datapath, command=ofproto.OFPFC_DELETE,
				out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
				priority=1, match=match)
			datapath.send_msg(mod)

	@set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']
  
		# Capture the current time when packet_in is received
		packet_times[msg.cookie] = time.time()

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		dst = eth.dst
		src = eth.src

		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = in_port

		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
			self.add_flow(datapath, 1, match, actions)

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
		datapath.send_msg(out)
  
		# Calculate response time between packet_in and packet_out
		if msg.cookie in packet_times:
			response_time = (time.time() - packet_times[msg.cookie]) * 1000
			response_times.append(response_time)
			# Remove the timestamp after calculating the response time
			del packet_times[msg.cookie]

	@set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
	def _topology_change_handler(self, ev):
		dp = ev.dp
		dpid_str = dpid_lib.dpid_to_str(dp.id)
		msg = 'Receive topology change event. Flush MAC table.'
		self.logger.debug("[dpid=%s] %s", dpid_str, msg)

		if dp.id in self.mac_to_port:
			self.delete_flow(dp)
			del self.mac_to_port[dp.id]

	@set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
	def _port_state_change_handler(self, ev):
		dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
		of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
					stplib.PORT_STATE_BLOCK: 'BLOCK',
					stplib.PORT_STATE_LISTEN: 'LISTEN',
					stplib.PORT_STATE_LEARN: 'LEARN',
					stplib.PORT_STATE_FORWARD: 'FORWARD'}
		self.logger.debug("[dpid=%s][port=%d] state=%s",
						  dpid_str, ev.port_no, of_state[ev.port_state])
