#Modified version of the software from - https://github.com/FaheemAlvii/iptablesgui-remote
#Thanks to FaheemAlvii for the original work.


from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import paramiko
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key

# Example server details (replace with your actual servers)
SERVERS = [
    {'name': 'ServerName', 'host': 'ipadress', 'port': 22, 'username': 'root', 'key_filename': 'filename.ppk'},
]

# Dummy user data for demonstration (replace with a real authentication method)
USER_CREDENTIALS = {
    'username': 'admin',
    'password': '123456'  # Never hardcode passwords in a real app
}


# Function to execute shell commands over SSH
def execute_ssh_command(host, port, username, key_filename, command):
    try:
        # Check if key file exists
        if not os.path.exists(key_filename):
            logging.error(f"Key file not found: {key_filename}")
            raise FileNotFoundError(f"Private key file not found: {key_filename}")
        
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Automatically add host key (for simplicity)

        # Connect to the server using private key
        ssh.connect(host, port=port, username=username, key_filename=key_filename)

        # Execute the command
        stdin, stdout, stderr = ssh.exec_command(command)

        # Read the output
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()

        # Close the connection
        ssh.close()

        if error:
            return error
        return output
    except Exception as e:
        logging.error(f"SSH command failed: {str(e)}")
        return str(e)


# Function to get iptables rules from a remote server
def get_iptables_rules(host, port, username, key_filename):
    command = "sudo iptables -S"
    return execute_ssh_command(host, port, username, key_filename, command)



# Function to add a rule on a remote server
def add_iptables_rule(host, port, username, key_filename, rule):
    command = f"sudo iptables {rule}"
    return execute_ssh_command(host, port, username, key_filename, command)


# Function to delete a rule on a remote server
def delete_iptables_rule(host, port, username, key_filename, rule):
    if rule.startswith('-A'):
        rule_to_delete = rule.replace('-A', '-D', 1)  # Replace only the first '-A' with '-D'
    else:
        rule_to_delete = f"-D {rule}"
    command = f"sudo iptables {rule_to_delete}"
    return execute_ssh_command(host, port, username, key_filename, command)


# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('index'))  # Redirect to the main page if already logged in

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        logging.info(f"Login attempt: {username}")

        if username == USER_CREDENTIALS['username'] and password == USER_CREDENTIALS['password']:
            session['logged_in'] = True
            logging.info(f"Login successful: {username}")
            return redirect(url_for('index'))  # Redirect to the main page on successful login
        else:
            logging.warning(f"Login failed for user: {username}")
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')


# Route to the main page (only accessible if logged in)
@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    return render_template('index.html', servers=SERVERS)


# Route to log out
@app.route('/logout')
def logout():
    session.pop('logged_in', None)  # Remove the login session
    return redirect(url_for('login'))


@app.route('/connect/<server_name>', methods=['GET'])
def connect_to_server(server_name):
    if 'logged_in' not in session:
        return jsonify({"message": "Unauthorized"}), 403  # Return unauthorized if not logged in

    server = next((s for s in SERVERS if s['name'] == server_name), None)
    if not server:
        return jsonify({"message": "Server not found"}), 404

    # Simulate SSH connection and fetching rules
    try:
        logging.info(f"Connecting to server: {server['name']} ({server['host']}:{server['port']})")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(server['host'], port=server['port'], username=server['username'], key_filename=server['key_filename'])
        logging.info(f"Successfully connected to {server['name']}")

        # Get the current iptables rules from the server
        stdin, stdout, stderr = client.exec_command("sudo iptables -S")
        rules = stdout.read().decode().strip()
        client.close()
        logging.info(f"Successfully fetched iptables rules from {server['name']}")

        return jsonify({"rules": rules})

    except Exception as e:
        logging.error(f"Error connecting to {server['name']}: {str(e)}")
        return jsonify({"message": f"Error connecting to server: {str(e)}"}), 500


@app.route('/rules/<server_name>', methods=['POST'])
def manage_rules(server_name):
    if 'logged_in' not in session:
        return jsonify({"message": "Unauthorized"}), 403  # Return unauthorized if not logged in

    # Find the server details
    server = next((s for s in SERVERS if s['name'] == server_name), None)
    if not server:
        return jsonify({"message": "Server not found"}), 404

    # Get the rule and action from the request
    data = request.json
    action = data.get('action')
    rule = data.get('rule')

    # Handle SSH connection
    try:
        logging.info(f"Processing action '{action}' on server: {server['name']} ({server['host']}:{server['port']})")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(server['host'], port=server['port'], username=server['username'], key_filename=server['key_filename'])
        logging.info(f"Connected to {server['name']}")

        # Fetch rules
        if action == 'fetch':
            stdin, stdout, stderr = client.exec_command("sudo iptables -S")
            rules = stdout.read().decode().splitlines()
            client.close()
            logging.info(f"Fetched rules from {server['name']}")
            return jsonify({"rules": rules}), 200

        # Add rule
        if action == 'add':
            stdin, stdout, stderr = client.exec_command(f"sudo iptables {rule}")
            client.close()
            logging.info(f"Added rule on {server['name']}: {rule}")
            return jsonify({"message": f"Successfully added rule: {rule}"}), 200

        # Delete rule
        elif action == 'delete':
            if rule.startswith('-A'):
                # Delete rule: -A CHAIN rule_spec -> -D CHAIN rule_spec
                rule_parts = rule[3:].strip()  # Remove '-A '
                stdin, stdout, stderr = client.exec_command(f"sudo iptables -D {rule_parts}")
                client.close()
                logging.info(f"Deleted rule on {server['name']}: {rule}")
                return jsonify({"message": f"Successfully deleted rule: {rule}"}), 200
            elif rule.startswith('-N'):
                # Delete chain: -N CHAIN_NAME -> -X CHAIN_NAME
                chain_name = rule[3:].strip()  # Remove '-N '
                stdin, stdout, stderr = client.exec_command(f"sudo iptables -X {chain_name}")
                client.close()
                logging.info(f"Deleted chain on {server['name']}: {rule}")
                return jsonify({"message": f"Successfully deleted chain: {rule}"}), 200
            elif rule.startswith('-P'):
                # Reset policy: -P CHAIN POLICY -> -P CHAIN ACCEPT (default)
                policy_parts = rule[3:].strip()  # Remove '-P '
                stdin, stdout, stderr = client.exec_command(f"sudo iptables -P {policy_parts.split()[0]} ACCEPT")
                client.close()
                logging.info(f"Reset policy on {server['name']}: {rule}")
                return jsonify({"message": f"Successfully reset policy: {rule}"}), 200
            else:
                logging.warning(f"Delete failed on {server['name']}: Unknown rule type")
                return jsonify({"message": "Unknown rule type, cannot delete"}), 400

        # Edit rule (delete old, add new)
        elif action == 'edit':
            old_rule, new_rule = rule.split(" -> ")
            if old_rule.startswith('-A'):
                # Edit append rule: delete old, add new
                old_rule_parts = old_rule[3:].strip()
                new_rule_parts = new_rule[3:].strip() if new_rule.startswith('-A') else new_rule.strip()
                stdin, stdout, stderr = client.exec_command(f"sudo iptables -D {old_rule_parts}")
                stdin, stdout, stderr = client.exec_command(f"sudo iptables -A {new_rule_parts}")
                client.close()
                logging.info(f"Edited rule on {server['name']}: {old_rule} -> {new_rule}")
                return jsonify({"message": f"Successfully edited rule: {old_rule} -> {new_rule}"}), 200
            elif old_rule.startswith('-N'):
                # Can't directly edit a chain, need to delete and recreate
                old_chain = old_rule[3:].strip()
                new_chain = new_rule[3:].strip() if new_rule.startswith('-N') else new_rule.strip()
                stdin, stdout, stderr = client.exec_command(f"sudo iptables -X {old_chain}")
                stdin, stdout, stderr = client.exec_command(f"sudo iptables -N {new_chain}")
                client.close()
                logging.info(f"Edited chain on {server['name']}: {old_rule} -> {new_rule}")
                return jsonify({"message": f"Successfully edited chain: {old_rule} -> {new_rule}"}), 200
            elif old_rule.startswith('-P'):
                # Edit policy
                policy_parts = old_rule[3:].strip()
                new_policy_parts = new_rule[3:].strip() if new_rule.startswith('-P') else new_rule.strip()
                stdin, stdout, stderr = client.exec_command(f"sudo iptables -P {new_policy_parts}")
                client.close()
                logging.info(f"Edited policy on {server['name']}: {old_rule} -> {new_rule}")
                return jsonify({"message": f"Successfully edited policy: {old_rule} -> {new_rule}"}), 200
            else:
                logging.warning(f"Edit failed on {server['name']}: Unknown rule type")
                return jsonify({"message": "Unknown rule type, cannot edit"}), 400

        elif action == 'save_and_restart':
            stdin, stdout, stderr = client.exec_command(f"iptables-save > /etc/iptables/rules.v4 && systemctl restart iptables")
            client.close()
            logging.info(f"Saved and restarted iptables on {server['name']}")
            return jsonify({"message": f"Successfully added rule: {rule}"}), 200

        return jsonify({'error': 'Unknown action'}), 400

    except Exception as e:
        logging.error(f"Error on {server['name']} during action '{action}': {str(e)}")
        return jsonify({"message": f"Error connecting to server or applying iptables rule: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
