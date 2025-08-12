## List Listening Ports

This script lists the network ports that are currently open and being listened to on the system, providing a JSON-formatted output for integration with security tools like OSSEC/Wazuh.

### Overview

The `List-Listening-Ports` script scans the system for open network ports and generates a JSON report detailing the service or application associated with each port. This information is crucial for security audits and identifying potential unauthorized services.

### Script Details

#### Core Features

1. **Port Scanning**: Scans the system for open and listening network ports.
2. **Service Detection**: Identifies the service or application associated with each open port.
3. **JSON Output**: Generates a structured JSON report for integration with security tools.
4. **Logging Framework**: Provides detailed logs for script execution.
5. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
./List-Listening-Ports
```

#### Parameters

| Parameter | Type   | Default Value                  | Description                                      |
|-----------|--------|--------------------------------|--------------------------------------------------|
| `ARLog`   | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output            |
| `LogPath` | string | `/tmp/List-Listening-Ports.log` | Path for detailed execution logs                |
| `LogMaxKB`| int    | 100                            | Maximum log file size in KB before rotation     |
| `LogKeep` | int    | 5                              | Number of rotated log files to retain           |

#### Example Invocation

```bash
# Run the script
./List-Listening-Ports
```

### Script Execution Flow

#### 1. Initialization Phase
- Clears the active response log file.
- Rotates the detailed log file if it exceeds the size limit.
- Logs the start of the script execution.

#### 2. Port Scanning
- Scans the system for open and listening network ports using `netstat` or `ss`.
- Identifies the service or application associated with each open port.

#### 3. JSON Output Generation
- Formats the scanned ports and associated services into a JSON array.
- Writes the JSON result to the active response log.

#### 4. Completion Phase
- Logs the duration of the script execution.
- Outputs the final JSON result.

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "List-Listening-Ports",
  "data": [
    {
      "protocol": "tcp",
      "port": 22,
      "service": "sshd",
      "status": "listening"
    },
    {
      "protocol": "udp",
      "port": 53,
      "service": "dns",
      "status": "listening"
    }
  ],
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access network port information.
- Validate the JSON output for compatibility with your security tools.
- Test the script in isolated environments before production use.

#### Security Considerations
- Ensure the script runs with minimal privileges.
- Protect the output log files.

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has access to network port information.
2. **Empty Results**: Verify that there are open and listening ports on the system.
3. **Log File Issues**: Check write permissions for the log paths.

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ./List-Listening-Ports
```

### Contributing

When modifying this script:
1. Maintain the network port scanning and JSON output structure.
2. Follow Shell scripting best practices.
3. Document any additional functionality.
4. Test thoroughly in isolated environments.

## Unblock-IP

This script unblocks a specified IP address using UFW (Uncomplicated Firewall), providing a JSON-formatted output for integration with security tools like OSSEC/Wazuh.

### Overview

The `Unblock-IP` script checks if an IP address is currently blocked by UFW and removes the deny rule if present. It logs all actions and outputs the result in JSON format for active response workflows.

### Script Details

#### Core Features

1. **IP Unblocking**: Removes UFW deny rules for a specified IP address.
2. **Status Reporting**: Reports whether the IP was unblocked, not blocked, or if an error occurred.
3. **JSON Output**: Generates a structured JSON report for integration with security tools.
4. **Logging Framework**: Provides detailed logs for script execution.
5. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
ARG1="1.2.3.4" ./Unblock-IP
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `ARG1`    | string | The IP address to unblock (required) |
| `LOG`     | string | `/var/ossec/active-response/active-responses.log` (output JSON log) |
| `LogPath` | string | `/tmp/Unblock-IP.log` (detailed execution log) |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

### Script Execution Flow

#### 1. Initialization Phase
- Rotates the detailed log file if it exceeds the size limit
- Clears the active response log file
- Logs the start of the script execution

#### 2. Unblock Logic
- Checks if the IP is provided
- Checks if the IP is currently blocked by UFW
- Removes the deny rule if present
- Logs the result and status

#### 3. JSON Output Generation
- Formats the result into a JSON object
- Writes the JSON result to the active response log

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Unblock-IP",
  "ip": "1.2.3.4",
  "status": "unblocked",
  "reason": "IP unblocked successfully",
  "copilot_soar": true
}
```

#### Error Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Unblock-IP",
  "ip": "",
  "status": "error",
  "reason": "No IP provided",
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to manage UFW rules
- Validate the JSON output for compatibility with your security tools
- Test the script in isolated environments

#### Security Considerations
- Ensure minimal required privileges
- Protect the output log files

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has privileges to modify UFW rules
2. **Missing IP**: Provide the IP address via the `ARG1` environment variable
3. **Log File Issues**: Check write permissions

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ARG1="1.2.3.4" ./Unblock-IP
```

### Contributing

When modifying this script:
1. Maintain the IP unblocking and JSON output structure
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
