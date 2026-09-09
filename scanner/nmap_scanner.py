import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os


# ============================================================
# NMAP SCAN TYPES
# ============================================================

SCAN_TYPES = {

    "tcp_connect": {
        "name": "TCP Connect Scan",
        "command": ["-sT"],
        "timeout": 120
    },

    "syn": {
        "name": "SYN (Stealth) Scan",
        "command": ["-sS"],
        "timeout": 120
    },

    "udp": {
        "name": "UDP Scan",
        "command": ["-sU"],
        "timeout": 300
    },

    "ping": {
        "name": "Ping Scan",
        "command": ["-sn"],
        "timeout": 60
    },

    "version": {
        "name": "Version Detection",
        "command": ["-sV"],
        "timeout": 180
    },

    "os": {
        "name": "OS Detection",
        "command": ["-O"],
        "timeout": 180
    },

    "aggressive": {
        "name": "Aggressive Scan",
        "command": ["-A"],
        "timeout": 300
    },

    "service": {
        "name": "Service Discovery",
        "command": ["-sV", "-sC"],
        "timeout": 180
    },

    "fast": {
        "name": "Fast Scan",
        "command": ["-F"],
        "timeout": 60
    },

    "full_tcp": {
        "name": "Full TCP Port Scan",
        "command": ["-p-"],
        "timeout": 300
    }
}


# ============================================================
# HELPER: CLEAN XML VALUE
# ============================================================

def get_attribute(element, attribute, default=""):

    if element is None:
        return default

    return element.get(
        attribute,
        default
    )


# ============================================================
# HELPER: PARSE SCRIPT
# ============================================================

def parse_script(script):

    if script is None:
        return None

    return {
        "id": script.get(
            "id",
            "unknown"
        ),

        "output": script.get(
            "output",
            ""
        )
    }


# ============================================================
# SCAN TARGET
# ============================================================

def scan_target(
    target,
    scan_type="tcp_connect"
):

    # ========================================================
    # VALIDATE SCAN TYPE
    # ========================================================

    if scan_type not in SCAN_TYPES:

        return {
            "error": "Invalid scan type."
        }

    scan_config = SCAN_TYPES[
        scan_type
    ]

    scan_name = scan_config["name"]

    scan_arguments = scan_config["command"]

    timeout = scan_config["timeout"]


    # ========================================================
    # TEMPORARY XML FILE
    # ========================================================

    temp_file = tempfile.NamedTemporaryFile(
        suffix=".xml",
        delete=False
    )

    xml_path = temp_file.name

    temp_file.close()


    # ========================================================
    # NMAP COMMAND
    # ========================================================

    command = [
        "nmap",
        *scan_arguments,
        "-oX",
        xml_path,
        target
    ]


    try:

        # ====================================================
        # RUN NMAP
        # ====================================================

        result = subprocess.run(

            command,

            capture_output=True,

            text=True,

            timeout=timeout

        )


    except subprocess.TimeoutExpired:

        # ----------------------------------------------------
        # Remove temporary file
        # ----------------------------------------------------

        if os.path.exists(xml_path):

            os.remove(xml_path)

        return {

            "error": (
                f"Nmap scan timed out after "
                f"{timeout} seconds."
            )

        }


    except FileNotFoundError:

        if os.path.exists(xml_path):

            os.remove(xml_path)

        return {

            "error": (
                "Nmap was not found. "
                "Make sure Nmap is installed "
                "and added to PATH."
            )

        }


    except Exception as error:

        if os.path.exists(xml_path):

            os.remove(xml_path)

        return {

            "error": str(error)

        }


    # ========================================================
    # NORMAL TERMINAL OUTPUT
    # ========================================================

    raw_output = result.stdout.strip()


    # ========================================================
    # NMAP ERROR
    # ========================================================

    if result.returncode != 0:

        error_message = (

            result.stderr.strip()

            or raw_output

            or "Nmap scan failed."

        )

        if os.path.exists(xml_path):

            os.remove(xml_path)

        return {

            "error": error_message,

            "raw_output": raw_output

        }


    # ========================================================
    # READ XML
    # ========================================================

    try:

        with open(
            xml_path,
            "r",
            encoding="utf-8"
        ) as file:

            xml_data = file.read()


        root = ET.fromstring(
            xml_data
        )


    except Exception as error:

        if os.path.exists(xml_path):

            os.remove(xml_path)

        return {

            "error": (
                f"Unable to parse Nmap output: "
                f"{error}"
            ),

            "raw_output": raw_output

        }


    finally:

        if os.path.exists(xml_path):

            os.remove(xml_path)


    # ========================================================
    # HOST
    # ========================================================

    host = root.find(
        ".//host"
    )

    if host is None:

        return {

            "error": "No host information found.",

            "raw_output": raw_output

        }


    # ========================================================
    # HOST STATUS
    # ========================================================

    host_state = "unknown"

    status = host.find(
        "status"
    )

    if status is not None:

        host_state = status.get(
            "state",
            "unknown"
        )


    # ========================================================
    # HOST ADDRESSES
    # ========================================================

    addresses = []

    for address in host.findall(
        "address"
    ):

        addresses.append({

            "address": address.get(
                "addr",
                ""
            ),

            "type": address.get(
                "addrtype",
                ""
            ),

            "vendor": address.get(
                "vendor",
                ""
            )

        })


    # ========================================================
    # HOSTNAME
    # ========================================================

    hostnames = []

    hostnames_element = host.find(
        "hostnames"
    )

    if hostnames_element is not None:

        for hostname in hostnames_element.findall(
            "hostname"
        ):

            hostnames.append(
                hostname.get(
                    "name",
                    ""
                )
            )


    # ========================================================
    # HOST UPTIME
    # ========================================================

    uptime = None

    uptime_element = host.find(
        "uptime"
    )

    if uptime_element is not None:

        uptime = {

            "seconds": uptime_element.get(
                "seconds",
                ""
            ),

            "lastboot": uptime_element.get(
                "lastboot",
                ""
            )

        }


    # ========================================================
    # PORTS
    # ========================================================

    ports = []

    ports_element = host.find(
        "ports"
    )

    if ports_element is not None:

        for port in ports_element.findall(
            "port"
        ):

            state_element = port.find(
                "state"
            )

            service_element = port.find(
                "service"
            )

            state = get_attribute(
                state_element,
                "state",
                "unknown"
            )

            service = "unknown"

            product = ""

            version_number = ""

            extra_info = ""

            cpe = ""


            # ------------------------------------------------
            # SERVICE INFORMATION
            # ------------------------------------------------

            if service_element is not None:

                service = service_element.get(
                    "name",
                    "unknown"
                )

                product = service_element.get(
                    "product",
                    ""
                )

                version_number = service_element.get(
                    "version",
                    ""
                )

                extra_info = service_element.get(
                    "extrainfo",
                    ""
                )


                cpe_element = service_element.find(
                    "cpe"
                )

                if cpe_element is not None:

                    cpe = cpe_element.text or ""


            # ------------------------------------------------
            # VERSION STRING
            # ------------------------------------------------

            version = "unknown"

            if product and version_number:

                version = (
                    f"{product} "
                    f"{version_number}"
                )

            elif product:

                version = product

            elif version_number:

                version = version_number

            elif extra_info:

                version = extra_info


            # ------------------------------------------------
            # PORT SCRIPTS
            # ------------------------------------------------

            port_scripts = []

            for script in port.findall(
                "script"
            ):

                parsed_script = parse_script(
                    script
                )

                if parsed_script:

                    port_scripts.append(
                        parsed_script
                    )


            # ------------------------------------------------
            # SAVE PORT
            # ------------------------------------------------

            ports.append({

                "port": port.get(
                    "portid",
                    ""
                ),

                "protocol": port.get(
                    "protocol",
                    ""
                ),

                "state": state,

                "service": service,

                "product": product,

                "version": version,

                "extra_info": extra_info,

                "cpe": cpe,

                "scripts": port_scripts

            })


    # ========================================================
    # OS DETECTION
    # ========================================================

    os_matches = []

    os_element = host.find(
        "os"
    )

    if os_element is not None:

        for osmatch in os_element.findall(
            "osmatch"
        ):

            os_matches.append({

                "name": osmatch.get(
                    "name",
                    "Unknown"
                ),

                "accuracy": osmatch.get(
                    "accuracy",
                    "Unknown"
                ),

                "line": osmatch.get(
                    "line",
                    ""
                ),

                "osclasses": []

            })


    # ========================================================
    # OS CLASS
    # ========================================================

    os_classes = []

    if os_element is not None:

        for osclass in os_element.findall(
            ".//osclass"
        ):

            cpes = []

            for cpe in osclass.findall(
                "cpe"
            ):

                if cpe.text:

                    cpes.append(
                        cpe.text
                    )


            os_classes.append({

                "type": osclass.get(
                    "type",
                    "Unknown"
                ),

                "vendor": osclass.get(
                    "vendor",
                    "Unknown"
                ),

                "family": osclass.get(
                    "osfamily",
                    "Unknown"
                ),

                "generation": osclass.get(
                    "osgen",
                    "Unknown"
                ),

                "accuracy": osclass.get(
                    "accuracy",
                    "Unknown"
                ),

                "cpe": cpes

            })


    # ========================================================
    # DEVICE TYPE
    # ========================================================

    device_type = "Unknown"

    if os_classes:

        device_type = os_classes[0][
            "type"
        ]


    # ========================================================
    # RUNNING OS
    # ========================================================

    running_os = "Unknown"

    if os_matches:

        running_os = os_matches[0][
            "name"
        ]


    # ========================================================
    # TRACEROUTE
    # ========================================================

    traceroute = []

    trace = host.find(
        "trace"
    )

    if trace is not None:

        for hop in trace.findall(
            "hop"
        ):

            traceroute.append({

                "ttl": hop.get(
                    "ttl",
                    "?"
                ),

                "ip": hop.get(
                    "ipaddr",
                    "?"
                ),

                "hostname": hop.get(
                    "host",
                    ""
                ),

                "rtt": hop.get(
                    "rtt",
                    ""
                )

            })


    # ========================================================
    # NSE HOST SCRIPT RESULTS
    # ========================================================

    scripts = []

    for script in host.findall(
        ".//hostscript/script"
    ):

        parsed_script = parse_script(
            script
        )

        if parsed_script:

            scripts.append(
                parsed_script
            )


    # ========================================================
    # GENERAL SCRIPT RESULTS
    # ========================================================

    if not scripts:

        for script in host.findall(
            ".//script"
        ):

            parsed_script = parse_script(
                script
            )

            if parsed_script:

                scripts.append(
                    parsed_script
                )


    # ========================================================
    # NMAP RUNTIME
    # ========================================================

    scan_time = ""

    runstats = root.find(
        ".//runstats"
    )

    if runstats is not None:

        finished = runstats.find(
            "finished"
        )

        if finished is not None:

            scan_time = finished.get(
                "timestr",
                ""
            )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "target": target,

        "scan_type": scan_type,

        "scan_name": scan_name,

        "host_state": host_state,

        "addresses": addresses,

        "hostnames": hostnames,

        "uptime": uptime,

        "ports": ports,

        "os": os_matches,

        "os_classes": os_classes,

        "device_type": device_type,

        "running_os": running_os,

        "traceroute": traceroute,

        "scripts": scripts,

        "scan_time": scan_time,

        "raw_output": raw_output

    }


# ============================================================
# TERMINAL TEST
# ============================================================

if __name__ == "__main__":

    target = input(
        "Enter authorized target: "
    ).strip()


    print(
        "\nAvailable Scan Types:\n"
    )


    scan_list = list(
        SCAN_TYPES.keys()
    )


    for number, scan_type in enumerate(
        scan_list,
        start=1
    ):

        print(
            f"{number}. "
            f"{SCAN_TYPES[scan_type]['name']} "
            f"({SCAN_TYPES[scan_type]['timeout']}s timeout)"
        )


    choice = input(
        "\nSelect scan type (1-10): "
    )


    try:

        scan_type = scan_list[
            int(choice) - 1
        ]

    except (
        ValueError,
        IndexError
    ):

        print(
            "Invalid scan type."
        )

        exit()


    print(
        f"\nStarting "
        f"{SCAN_TYPES[scan_type]['name']}..."
    )


    print(
        f"Timeout: "
        f"{SCAN_TYPES[scan_type]['timeout']} seconds"
    )


    results = scan_target(
        target,
        scan_type
    )


    print("\n")


    if "error" in results:

        print(
            "ERROR:",
            results["error"]
        )

    else:

        print(
            results["raw_output"]
        )