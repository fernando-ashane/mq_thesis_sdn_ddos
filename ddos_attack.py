from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, CPULimitedHost
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import time
import sys
import os
import csv
import threading

testcase = int(sys.argv[1])
attack_type = int(sys.argv[2])

sim_duration = 180
attack_duration = 60


#---------------------------- Port Rate Monitoring ------------------------------------

# Function to execute ovs-ofctl command and get byte counts for a port
def get_byte_counts(switch_name, port):
	cmd = "ovs-ofctl dump-ports {} {}".format(switch_name, port)
	result = os.popen(cmd).read()
	
	# Parse the RX and TX byte counts
	lines = result.split('\n')
	rx_bytes, tx_bytes = 0, 0
	for line in lines:
		if 'rx pkts' in line:
			rx_bytes = int(line.split('=',2)[2].split(',')[0])
		if 'tx pkts' in line:
			tx_bytes = int(line.split('=')[2].split(',')[0])
	
	return rx_bytes, tx_bytes

# Function to execute ovs-ofctl command and count flow entries for a switch
def get_flow_entry_count(switch_name):
	cmd = "ovs-ofctl dump-flows {}".format(switch_name)
	result = os.popen(cmd).read()

	# Count the number of flow entries by counting the number of lines in the output minus the header
	flow_entries = len(result.splitlines()) - 1  # Subtracting 1 for the header line
	return flow_entries

# Function to calculate packets sent to the controller for a switch
def get_packets_to_controller(switch_name):
	cmd = "ovs-ofctl dump-flows {}".format(switch_name)
	result = os.popen(cmd).read()
	
	# Count flows with action=CONTROLLER and extract packets sent to controller
	packet_count = 0
	for line in result.splitlines():
		if 'CONTROLLER' in line:
			# Extract the number of packets sent to the controller from the flow line
			if 'n_packets' in line:
				packet_count += int(line.split('n_packets=')[1].split(',')[0])
	
	return packet_count

def log_cpu_usage(host):

	top_output = host.cmd('top -bn1 | grep "Cpu(s)"')
	# Extract CPU idle percentage from the output and calculate usage percentage
	cpu_idle = float(top_output.split(",")[3].replace('id', '').strip())
	cpu_usage = 100.0 - cpu_idle
	return cpu_usage

# Function to monitor data rates, flow entries, and controller packets simultaneously and save them to CSV files
def monitor_data_and_flows(switches_ports, server_host, interval, duration, output_file_data, output_file_flows, output_file_cpu):
	start_time = time.time()  # Capture the start time

	with open(output_file_data, mode='w', newline='') as file_data, open(output_file_flows, mode='w', newline='') as file_flows, open(output_file_cpu, 'w', newline='') as file_cpu:
		# CSV writer for data rates
		writer_data = csv.writer(file_data)

		# CSV writer for flow entries and controller packets
		writer_flows = csv.writer(file_flows)

		# Create CSV headers for both files
		header_data = ['Time']
		header_flows = ['Time']  # Header for flow entries and controller rates

		# For each switch, add columns for flow entries and controller packet rate
		for switch in switches_ports.keys():
			header_flows.append(f'{switch}_Flow_Entry_Count')
			header_flows.append(f'{switch}_Controller_Packet_Rate')

		# For each port in the switches, add RX and TX columns in the data CSV
		for switch, ports in switches_ports.items():
			for port in ports:
				header_data.append(f'{switch}_port_{port}_RX_Kbps')
				header_data.append(f'{switch}_port_{port}_TX_Kbps')

		# Write the headers
		writer_data.writerow(header_data)
		writer_flows.writerow(header_flows)

		previous_stats = {}
		previous_controller_packets = {}  # For calculating rate of packets to the controller

		while time.time() - start_time < duration:
			current_time = int(time.time())
			row_data = [current_time]  # Start the row with the timestamp
			row_flows = [current_time]  # Row for flow entries and controller packet rates

			for switch, ports in switches_ports.items():
				# Get the flow entry count for the switch
				flow_entry_count = get_flow_entry_count(switch)

				# Get the number of packets sent to the controller for the switch
				current_controller_packets = get_packets_to_controller(switch)

				# Calculate the rate of packets sent to the controller
				if switch in previous_controller_packets:
					previous_controller, last_time = previous_controller_packets[switch]
					controller_packet_rate = (current_controller_packets - previous_controller) / (current_time - last_time)
				else:
					controller_packet_rate = 0

				# Update previous packet stats for next iteration
				previous_controller_packets[switch] = (current_controller_packets, current_time)

				# Add the flow entry count and controller packet rate to the flows row
				row_flows.append(flow_entry_count)
				row_flows.append(controller_packet_rate)

				for port in ports:
					# Get byte counts at time t2
					rx_bytes_t2, tx_bytes_t2 = get_byte_counts(switch, port)

					# If we already have previous statistics, calculate the rate
					if (switch, port) in previous_stats:
						rx_bytes_t1, tx_bytes_t1, last_time = previous_stats[(switch, port)]
						elapsed_time = current_time - last_time

						# Calculate data rates in kilobits per second (Kbps)
						rx_kbps = ((rx_bytes_t2 - rx_bytes_t1) * 8) / (1000 * elapsed_time)  # Convert bytes to kilobits
						tx_kbps = ((tx_bytes_t2 - tx_bytes_t1) * 8) / (1000 * elapsed_time)  # Convert bytes to kilobits

						# Append the rates to the data row
						row_data.append(rx_kbps)
						row_data.append(tx_kbps)

					else:
						# If it's the first time, append zeros (since there's no prior data)
						row_data.append(0)
						row_data.append(0)

					# Update previous stats for the next iteration
					previous_stats[(switch, port)] = (rx_bytes_t2, tx_bytes_t2, current_time)

			# Write the row for data rates and flow entries for this timestamp
			writer_data.writerow(row_data)
			writer_flows.writerow(row_flows)

			# Sleep for the interval (1 second)
			time.sleep(interval)
#--------------------------------------------------------------------------------

class CustomThreeTierTopo(Topo):
	def build(self):
		# Create Core switches
		core1 = self.addSwitch('s1')
		core2 = self.addSwitch('s2')

		# Create Aggregation switches
		agg1 = self.addSwitch('s3')
		agg2 = self.addSwitch('s4')
		agg3 = self.addSwitch('s5')
		agg4 = self.addSwitch('s6')

		# Create Access switches
		access1 = self.addSwitch('s7')
		access2 = self.addSwitch('s8')
		access3 = self.addSwitch('s9')
		access4 = self.addSwitch('s10')
		access5 = self.addSwitch('s11')
		access6 = self.addSwitch('s12')

		# Create hosts
		h1 = self.addHost('h1')
		h2 = self.addHost('h2')
		h3 = self.addHost('h3')
		h4 = self.addHost('h4')
		h5 = self.addHost('h5')
		h6 = self.addHost('h6')

	
	# Creating links between Core switches
		self.addLink(core1, core2, cls=TCLink, bw=100)
	
		# Creating links between Core and Aggregation switches
		self.addLink(core1, agg1, cls=TCLink, bw=100)
		self.addLink(core1, agg2, cls=TCLink, bw=100)
		self.addLink(core1, agg3, cls=TCLink, bw=100)
		self.addLink(core1, agg4, cls=TCLink, bw=100)

		self.addLink(core2, agg1, cls=TCLink, bw=100)
		self.addLink(core2, agg2, cls=TCLink, bw=100)
		self.addLink(core2, agg3, cls=TCLink, bw=100)
		self.addLink(core2, agg4, cls=TCLink, bw=100)

		# Creating links between Aggregation and Access switches
		self.addLink(agg1, access1, cls=TCLink, bw=100)
		self.addLink(agg1, access2, cls=TCLink, bw=100)
		self.addLink(agg1, access3, cls=TCLink, bw=100)

		self.addLink(agg2, access1, cls=TCLink, bw=100)
		self.addLink(agg2, access2, cls=TCLink, bw=100)
		self.addLink(agg2, access3, cls=TCLink, bw=100)

		self.addLink(agg3, access4, cls=TCLink, bw=100)
		self.addLink(agg3, access5, cls=TCLink, bw=100)
		self.addLink(agg3, access6, cls=TCLink, bw=100)

		self.addLink(agg4, access4, cls=TCLink, bw=100)
		self.addLink(agg4, access5, cls=TCLink, bw=100)
		self.addLink(agg4, access6, cls=TCLink, bw=100)

		# Creating links between Access switches and Hosts
		self.addLink(h1, access1, cls=TCLink, bw=100)
		self.addLink(h2, access2, cls=TCLink, bw=100)
		self.addLink(h3, access3, cls=TCLink, bw=100)
		self.addLink(h4, access4, cls=TCLink, bw=100)
		self.addLink(h5, access5, cls=TCLink, bw=100)
		self.addLink(h6, access6, cls=TCLink, bw=100)


class CustomLeafSpineTopo(Topo):
	def build(self):
		# Create Spine switches
		spine1 = self.addSwitch('s1')
		spine2 = self.addSwitch('s2')
		
		# Create Leaf switches
		leaf1 = self.addSwitch('s3')
		leaf2 = self.addSwitch('s4')
		leaf3 = self.addSwitch('s5')
		leaf4 = self.addSwitch('s6')
		leaf5 = self.addSwitch('s7')
		leaf6 = self.addSwitch('s8')

		# Create hosts
		h1 = self.addHost('h1')
		h2 = self.addHost('h2')
		h3 = self.addHost('h3')
		h4 = self.addHost('h4')
		h5 = self.addHost('h5')
		h6 = self.addHost('h6')	
	
		# Creating links between Core and Aggregation switches
		self.addLink(spine1, leaf1, cls=TCLink, bw=100)
		self.addLink(spine1, leaf2, cls=TCLink, bw=100)
		self.addLink(spine1, leaf3, cls=TCLink, bw=100)
		self.addLink(spine1, leaf4, cls=TCLink, bw=100)
		self.addLink(spine1, leaf5, cls=TCLink, bw=100)
		self.addLink(spine1, leaf6, cls=TCLink, bw=100)
		
		self.addLink(spine2, leaf1, cls=TCLink, bw=100)
		self.addLink(spine2, leaf2, cls=TCLink, bw=100)
		self.addLink(spine2, leaf3, cls=TCLink, bw=100)
		self.addLink(spine2, leaf4, cls=TCLink, bw=100)
		self.addLink(spine2, leaf5, cls=TCLink, bw=100)
		self.addLink(spine2, leaf6, cls=TCLink, bw=100)

		# Creating links between Access switches and Hosts
		self.addLink(h1, leaf1, cls=TCLink, bw=100)
		self.addLink(h2, leaf2, cls=TCLink, bw=100)
		self.addLink(h3, leaf3, cls=TCLink, bw=100)
		self.addLink(h4, leaf4, cls=TCLink, bw=100)
		self.addLink(h5, leaf5, cls=TCLink, bw=100)
		self.addLink(h6, leaf6, cls=TCLink, bw=100)


def ChooseTestcase(testcase):
	if testcase == 1:
		topology = CustomThreeTierTopo()
		switches_ports = {
		  's1': [1,2,3,4,5],
		's2': [1,2,3,4,5],
		's3': [1,2,3,4,5],
		  's4': [1,2,3,4,5],
		's5': [1,2,3,4,5],
		's6': [1,2,3,4,5],
		's7': [1,2,3,4],
		's8': [1,2,3,4],
		's9': [1,2,3,4],
		's10': [1,2,3,4],
		's11': [1,2,3,4],  
		's12': [1,2,3,4],  
	}

	elif testcase == 2:
		topology = CustomLeafSpineTopo()
		switches_ports = {
		  's1': [1,2,3,4,5,6],
		's2': [1,2,3,4,5,6],
		's3': [1,2,3,4],
		  's4': [1,2,3,4],
		's5': [1,2,3,4],
		's6': [1,2,3,4],
		's7': [1,2,3,4],
		's8': [1,2,3,4],
	}
	else:
		raise ValueError("Invalid testcase number.")
	return (topology, switches_ports)

def run():
	setLogLevel('info')
	topo,switches_ports = ChooseTestcase(testcase)
 
 # Create the network and add a remote controller
	c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
	net = Mininet(topo=topo, controller=c0, host=CPULimitedHost, link=TCLink)

	# Start the network
	net.start()

	# Define custom IP and MAC addresses
	custom_ips = {
		'h1': '10.0.0.1',
		'h2': '10.0.0.2',
		'h3': '10.0.0.3',
		'h4': '10.0.0.4',
		'h5': '10.0.0.5',
		'h6': '10.0.0.6'
	}

	custom_macs = {
		'h1': '00:00:00:00:00:01',
		'h2': '00:00:00:00:00:02',
		'h3': '00:00:00:00:00:03',
		'h4': '00:00:00:00:00:04',
		'h5': '00:00:00:00:00:05',
		'h6': '00:00:00:00:00:06'
	}
	
	#Set all interfaces to 100 mbps
	for host in net.hosts:
		for intf in host.intfList():
			intf.config(bw=100)
		 
	for switch in net.switches:
		for intf in switch.intfList():
			if 'lo' not in intf.name:
				intf.config(bw=100)
	
	# Assign custom IP and MAC addresses to hosts
	for host in net.hosts:
		host_name = host.name
		if host_name in custom_ips:
			host.setIP(custom_ips[host_name])
		if host_name in custom_macs:
			host.setMAC(custom_macs[host_name])
   
   # Setting up the server.
	http_server_command = "cd /home/ashane/ddos_project/'Final Model'/web_server && python3 -m http.server 80"
	http_server = net.get('h6')
	http_server.cmd(f'xterm -hold -e "{http_server_command}" &')
 
	time.sleep(90) #time for network to stabilize and STP to take effect.
 
	# Start monitoring data rates, flow entries, and controller packets in a background thread
	interval = 1  # Time interval in seconds for measuring data rates and flow entries
	duration_monitoring = sim_duration  # Monitor for the same duration as the test case
	server_host = net.get('h6')

	# Output files for data rates and flow entries
	output_file_data = f'data_rates_{attack_type}_{testcase}.csv'
	output_file_flows = f'flow_entries_{attack_type}_{testcase}.csv'
	output_file_cpu = f'server_cpu_{attack_type}_{testcase}.csv'

	monitor_thread = threading.Thread(target=monitor_data_and_flows, args=(switches_ports, server_host, interval, duration_monitoring, output_file_data, output_file_flows,output_file_cpu))
	monitor_thread.start()
 #-------------------------------------------------------------------------------------------------------------
 
	
   
	print(f"Starting normal traffic for {sim_duration} seconds")
	
	# Setting up normal traffic monitoring
	traffic_commands = {
		'h1': f'timeout {sim_duration} httping -i 1 -g http://10.0.0.6/topsecret.txt > httping_{attack_type}_{testcase}.csv'
	}
	
	for host_name, command in traffic_commands.items():
		host = net.get(host_name)
		host.cmd(f'xterm -hold -e "{command}" &')
   
   # Wait for 30 seconds before starting attacks.
	print(f"Waiting 30 seconds before starting attack")
	time.sleep(30)
	print(f"Starting attack: Test Case {testcase} for {attack_duration} seconds")
    
    #For controller-targeted ICMP flood attack
    if attack_type == 1:
        {
    commands_ddos = {
        'h2': f"timeout {attack_duration} hping3 --icmp --flood --rand-source x.x.x.x --rand-dest -I eth0",
        'h3': f"timeout {attack_duration} hping3 --icmp --flood --rand-source x.x.x.x --rand-dest -I eth0",
        'h5': f"timeout {attack_duration} hping3 --icmp --flood --rand-source x.x.x.x --rand-dest -I eth0"
    }
        }
        
    #For network-targeted UDP flood attack
    elif attack_type == 2:
                { 
	commands_ddos = {
		'h2': f"timeout {attack_duration} hping3 --udp --flood --rand-source 10.0.0.4",
		'h3': f"timeout {attack_duration} hping3 --udp --flood --rand-source 10.0.0.6",
		'h5': f"timeout {attack_duration} hping3 --udp --flood --rand-source 10.0.0.1"
	}
        }
    
    #For server-targeted TCP SYN attack            
    elif attack_type == 3:
                {
	commands_ddos = {
		'h2': f"timeout {attack_duration} hping3 --syn --flood --spoof 10.0.0.21 10.0.0.6",
		'h3': f"timeout {attack_duration} hping3 --syn --flood --spoof 10.0.0.22 10.0.0.6",
		'h5': f"timeout {attack_duration} hping3 --syn --flood --spoof 10.0.0.22 10.0.0.6"
	}
        }

	for host_name, command in commands_ddos.items():
		host = net.get(host_name)
		host.cmd(f'xterm -hold -e "{command}" &')
   
   # Start the Mininet CLI
	CLI(net)
 
if __name__ == '__main__':
    print(f'Attack type is {attack_type}')
	print(f'Testcase is {testcase}')
	run()
