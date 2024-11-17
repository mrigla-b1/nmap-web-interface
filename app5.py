import subprocess
from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)

# Store scan results in a dictionary (optional, can be used for further analysis)
scan_results = {}

# Regular expression to validate IPv4 addresses
ip_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

# Function to validate IP address
def validate_ip(ip):
    if ip_regex.match(ip):
        return all(0 <= int(part) <= 255 for part in ip.split('.'))
    return False

def run_nmap_scan_port(ip, scan_type, scan_speed, port=None):
    try:
        # Validate IP address before running the scan
        if not validate_ip(ip):
            raise ValueError("Invalid IP address")

        # Base command
        command = ['nmap']
        
        # Add scan type
        if scan_type:
            command.append(scan_type)
        
        # Add scan speed
        if scan_speed:
            command.append(f'-{scan_speed}')
        
        # Add port if specified
        if port and port.strip():
            command.append(f'-p{port}')
        
        # Add target IP
        command.append(ip)
        
        # Add sudo if using OS detection
        if scan_type == '-O':
            command.insert(0, 'sudo')
        
        print(f"Executing command: {' '.join(command)}")  # Debug print
        
        # Run the scan
        result = subprocess.check_output(command, text=True)
        return result
    
    except subprocess.CalledProcessError as e:
        print(f"Scan error: {str(e)}")  # Debug print
        raise Exception(f"Scan failed: {e.output}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")  # Debug print
        raise

#********************************************************* port scan no version ***********************************************
@app.route('/port_scan')
def port_scan_page():
    return render_template('scan_port.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    try:
        # Get JSON data from request
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        
        ip = data.get('ip', '').strip()
        scan_type = data.get('scanType', '-sS').strip()
        scan_speed = data.get('scanSpeed', 'T4').strip()
        port = data.get('port', '').strip()
        
        # Validate IP
        if not ip or not validate_ip(ip):
            return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400
        
        
        result = run_nmap_scan_port(ip, scan_type, scan_speed, port)
        print(result)
        
        return jsonify({
            'status': 'completed',
            'ip': ip,
            'result': result
        })
    
    except Exception as e:
        print(f"Error in start_scan: {str(e)}")  # Debug print
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

#********************************************************************** network HOST Scan ***********************************************************************************************
@app.route('/scanNetwork', methods=['GET'])
def scan_network_page():
    return render_template('scan_network_with_type_time.html')

@app.route('/scanNetwork', methods=['POST'])
def scan_network():
    try:
        data = request.get_json()
        ip = data.get('ip', '192.168.1.0/24')
        scan_type = data.get('scan_type', '-sn')
        timing_option = data.get('timing_option', '-T3')  # Default to T3 if not provided

        
        command = ['nmap', scan_type, timing_option, ip]

        
        result = subprocess.check_output(command, text=True)
        
        # Parse Nmap output to find active hosts
        active_hosts = []
        for line in result.split('\n'):
            if "Nmap scan report for" in line:
                ip_address = line.split(' ')[-1]
                active_hosts.append(ip_address)

        
        return jsonify({'status': 'completed', 'active_hosts': active_hosts})
    
    except subprocess.CalledProcessError as e:
        
        return jsonify({'status': 'error', 'message': f"Error scanning network: {e.output}"}), 500

#*************************************************************************port scan with version *****************************************************************************************
def run_nmap_scan(ip, scan_speed, port):
    try:
        # Validate IP address before running the scan
        if not validate_ip(ip):
            raise ValueError("Invalid IP address")

        
        command = ['nmap', '-sV', f'-{scan_speed}', ip]
        
       
        if port:
            command.append(f'-p {port}')
        
        
        result = subprocess.check_output(command, text=True)
        scan_results[ip] = result  # Store the result
        return result
    except subprocess.CalledProcessError as e:
        
        error_message = f"Error scanning {ip}:\n{e.output}"
        scan_results[ip] = error_message
        return error_message

@app.route('/port_scan_with_service_version', methods=['GET'])
def scan_port_service():
    return render_template('scan_port_with_version.html')

@app.route('/scan_port_service', methods=['POST'])
def start_scan_with_version():
    try:
        
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400

       
        ip = data.get('ip', '').strip()
        scan_speed = data.get('scanSpeed', 'T4')  # Default scan speed if not provided
        port = data.get('port', '').strip()  # Optional field, so default is empty string

       
        if not ip or not validate_ip(ip):
            return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400

        
        scan_result = run_nmap_scan(ip, scan_speed, port)

       
        return jsonify({'status': 'completed', 'ip': ip, 'result': scan_result})

    except KeyError as e:
        
        return jsonify({'status': 'error', 'message': f'Missing form field: {str(e)}'}), 400

    except Exception as e:
        
        print("Error during scan:", e)  # Log to server output
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/')
def rootind():
    return render_template('index.html')


@app.route('/userfriendly')
def welcome():
    return render_template('welcome.html')


#***************************************************** OS *****************************************************************************************************

def run_os_scan(ip):
    try:
        # Construct the Nmap command for OS detection
        command =  ['nmap', '-sS', '-O', '-T5', ip]
        
 
        result = subprocess.check_output(command, text=True)
        
       
        device_type = re.search(r"Device type: (.*)", result)
        running_os = re.search(r"Running \(JUST GUESSING\): (.*)", result)
        os_cpe = re.search(r"OS CPE: (.*)", result)
        os_guesses = re.search(r"Aggressive OS guesses: (.*)", result)
        network_distance = re.search(r"Network Distance: (.*)", result)

        
        os_details = {
            "device_type": device_type.group(1) if device_type else "N/A",
            "running_os": running_os.group(1) if running_os else "N/A",
            "os_cpe": os_cpe.group(1) if os_cpe else "N/A",
            "os_guesses": os_guesses.group(1) if os_guesses else "N/A",
            "network_distance": network_distance.group(1) if network_distance else "N/A"
        }

        return os_details
    except subprocess.CalledProcessError as e:
        return {"error": f"Error scanning {ip}: {e.output}"}


@app.route('/os_scan', methods=['GET'])
def os_scan_page():
    return render_template('os_scan.html')

@app.route('/os_scan', methods=['POST'])
def start_os_scan():
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        if not validate_ip(ip):
            raise ValueError("Invalid IP address")

        if not ip:
            return jsonify({'status': 'error', 'message': 'IP address is required'}), 400

        
        os_details = run_os_scan(ip)
        
        return jsonify({'status': 'completed', 'ip': ip, 'os_details': os_details})

    except Exception as e:
        print("Error during scan:", e)
        return jsonify({'status': 'error', 'message': str(e)}), 500

#*********************************************************************************Advanced Scan ********************************************************************************
import concurrent.futures
executor = concurrent.futures.ThreadPoolExecutor()
scan_results = {}

@app.route('/advanced')
def advanced():
    return render_template('advancedScan.html')

@app.route('/advancedscan', methods=['POST'])
def advanced_scan():
    ip = request.form['ip']
    port = request.form.get('port', '')
    technique = request.form.get('technique', '')
    speed = request.form.get('speed', '')
    verbosity = request.form.get('verbosity', '')
    script = request.form.get('script', '')

    command_options = [technique, speed, verbosity]
    if port:
        command_options.extend(['-p', port])
    if script:
        command_options.extend(['--script', script])

    # Initiate the scan
    future = executor.submit(run_nmap_scan_avenced, ip, command_options)
    scan_results[ip] = None
    return jsonify({"status": "started", "ip": ip})

@app.route('/result/<ip>', methods=['GET'])
def result(ip):
    if ip in scan_results and scan_results[ip] is not None:
        # Convert results to a string format for easier handling on the frontend
        result_str = "\n\n".join(f"{addr}:\n{res}" for addr, res in scan_results[ip].items())
        return jsonify({"status": "completed", "result": result_str})
    return jsonify({"status": "in-progress"})

def run_nmap_scan_avenced(ip, command_options):
    try:
        ip_addresses = ip.split()
        results = {}

        for address in ip_addresses:
            command = ['nmap', '-T5', '-sV', address] + command_options
            raw_result = subprocess.check_output(command, text=True)
            results[address] = raw_result

        scan_results[ip] = results

    except subprocess.CalledProcessError as e:
        scan_results[ip] = f"Error scanning {ip}:\n{e.output}"




#*********************************************************************************** MAIN *********************************************************************************************


if __name__ == '__main__':
    app.run(debug=True)

