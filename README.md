This repository contains the code used in our research project to create network topologies on Mininet, simulate various DDoS attack scenarios, and collect performance metrics for each test case.

Files

    ddos_attack.py: Creates the network topology, initiates specified attack scenarios, and records performance metrics. Users can define topology and attack type via command-line arguments.
    sdn_controller.py: A modified Ryu controller implementation with added Spanning Tree Protocol (STP) support and functionality to measure controller response time.
    controllerlog.py: Collects data on the controller's CPU utilization throughout each simulation.
