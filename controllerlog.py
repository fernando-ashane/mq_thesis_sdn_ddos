import psutil
import time
import csv
import os
import subprocess

# Configuration
RYU_PROCESS_NAME = 'ryu-manager'
LOG_INTERVAL = 1  # seconds
CSV_FILE_PATH = 'controllerlog.csv'  # Change this to your desired path
DURATION = 200  # Duration to run the logging in seconds (2 minutes)
CPU_LIMIT = 50  # Limit the CPU usage to 30%

def find_ryu_process():
	"""Find the Ryu controller process by name."""
	for process in psutil.process_iter(['pid', 'name']):
		if RYU_PROCESS_NAME in process.info['name']:
			return process
	return None

def apply_cpu_limit(pid, limit):
	"""Apply a CPU limit to the process using cpulimit."""
	try:
		subprocess.Popen(['sudo', 'cpulimit', '--pid', str(pid), '--limit', str(limit)])
		print(f'Applied {limit}% CPU limit to process with PID {pid}')
	except Exception as e:
		print(f'Failed to apply CPU limit: {e}')

def log_usage():
	"""Log the CPU and memory usage of the Ryu process."""
	# Check if the CSV file exists
	file_exists = os.path.isfile(CSV_FILE_PATH)

	with open(CSV_FILE_PATH, mode='a') as file:
		writer = csv.writer(file)

		# Write the header if the file is new
		if not file_exists:
			writer.writerow(['Timestamp', 'CPU_Usage (%)', 'Memory_Usage (MB)'])
	
		time.sleep(80)
		start_time = time.time()
		while (time.time() - start_time) < DURATION:
			ryu_process = find_ryu_process()
			if ryu_process:
				timestamp = int(time.time())  # Get the current time in epoch format
				cpu_usage = ryu_process.cpu_percent(interval=1)
				memory_usage = ryu_process.memory_info().rss / (1024 * 1024)  # Convert bytes to MB

				writer.writerow([timestamp, cpu_usage, memory_usage])
				#print(f'{timestamp} - CPU: {cpu_usage}% - Memory: {memory_usage}MB')
			else:
				print('Ryu controller process not found. Retrying in the next interval.')

			# Sleep for the log interval (already waited 1 second for cpu_percent)
			time.sleep(LOG_INTERVAL - 1)

if __name__ == '__main__':
	# Find the Ryu process
	ryu_process = find_ryu_process()
	if ryu_process:
		pid = ryu_process.pid

		# Apply CPU limit before starting logging
		apply_cpu_limit(pid, CPU_LIMIT)

		# Start logging
		log_usage()
	else:
		print('Ryu controller process not found. Please make sure it is running.')
	print("Logging done")
