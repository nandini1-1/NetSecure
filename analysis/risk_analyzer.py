# ============================================================
# NETSECURE - SECURITY RISK ANALYZER
# ============================================================

def analyze_scan(results):

    ports = results.get("ports", [])

    findings = []

    total_risk = 0


    # ========================================================
    # RISK DEFINITIONS
    # ========================================================

    high_risk_ports = {
        21: (
            "FTP",
            "FTP may transmit credentials and data without encryption.",
            "Use SFTP/FTPS or disable FTP if it is not required."
        ),

        23: (
            "Telnet",
            "Telnet transmits communication without strong encryption.",
            "Disable Telnet and use SSH instead."
        ),

        445: (
            "SMB",
            "SMB exposure can increase the attack surface of a system.",
            "Restrict SMB access to trusted networks."
        ),

        3389: (
            "RDP",
            "Remote Desktop exposed to a network can increase remote attack risk.",
            "Restrict RDP using firewall rules, VPN, and strong authentication."
        ),

        5900: (
            "VNC",
            "VNC provides remote access and should not normally be publicly exposed.",
            "Restrict VNC access and use secure remote-access controls."
        )
    }


    medium_risk_ports = {
        22: (
            "SSH",
            "SSH provides remote administrative access.",
            "Verify that SSH is required and restrict access to trusted hosts."
        ),

        80: (
            "HTTP",
            "HTTP does not encrypt web traffic by itself.",
            "Use HTTPS with properly configured TLS."
        ),

        8080: (
            "HTTP Alternate",
            "An alternate HTTP service may expose a web application.",
            "Verify the application and restrict unnecessary access."
        ),

        8443: (
            "HTTPS Alternate",
            "An alternate HTTPS service may expose an administrative or application interface.",
            "Verify the service and ensure TLS is correctly configured."
        ),

        3306: (
            "MySQL",
            "A database service exposed to the network can increase attack surface.",
            "Restrict database access to trusted systems."
        ),

        5432: (
            "PostgreSQL",
            "A database service exposed to the network can increase attack surface.",
            "Restrict PostgreSQL access to trusted systems."
        )
    }


    low_risk_ports = {
        53: (
            "DNS",
            "DNS is commonly required for network name resolution.",
            "Ensure DNS access is restricted appropriately."
        ),

        443: (
            "HTTPS",
            "HTTPS provides encrypted web communication when TLS is configured correctly.",
            "Keep TLS configuration and certificates up to date."
        )
    }


    # ========================================================
    # ANALYZE EACH PORT
    # ========================================================

    for port_info in ports:

        try:
            port = int(port_info.get("port"))
        except (ValueError, TypeError):
            continue


        state = port_info.get(
            "state",
            "unknown"
        ).lower()

        protocol = port_info.get(
            "protocol",
            "tcp"
        ).lower()

        service = port_info.get(
            "service",
            "unknown"
        )

        product = port_info.get(
            "product",
            ""
        )

        version = port_info.get(
            "version",
            "unknown"
        )


        # ----------------------------------------------------
        # Ignore closed ports
        # ----------------------------------------------------

        if state != "open":
            continue


        # ====================================================
        # DETERMINE RISK
        # ====================================================

        severity = "LOW"
        points = 3

        reason = (
            "An open port increases the network attack surface."
        )

        recommendation = (
            "Verify that the service is required "
            "and restrict access when possible."
        )


        # ----------------------------------------------------
        # HIGH-RISK PORT
        # ----------------------------------------------------

        if port in high_risk_ports:

            service_name, reason, recommendation = (
                high_risk_ports[port]
            )

            severity = "HIGH"
            points = 15


        # ----------------------------------------------------
        # MEDIUM-RISK PORT
        # ----------------------------------------------------

        elif port in medium_risk_ports:

            service_name, reason, recommendation = (
                medium_risk_ports[port]
            )

            severity = "MEDIUM"
            points = 8


        # ----------------------------------------------------
        # LOW-RISK PORT
        # ----------------------------------------------------

        elif port in low_risk_ports:

            service_name, reason, recommendation = (
                low_risk_ports[port]
            )

            severity = "LOW"
            points = 2


        # ----------------------------------------------------
        # Unknown / Other Service
        # ----------------------------------------------------

        else:

            service_name = service


        # ====================================================
        # UDP RISK
        # ====================================================

        if protocol == "udp":

            points += 3

            if severity == "LOW":

                severity = "MEDIUM"

            reason += (
                " UDP services should be reviewed carefully "
                "because they do not use the TCP handshake."
            )


        # ====================================================
        # VERSION INFORMATION
        # ====================================================

        if product:

            detected_product = product

        else:

            detected_product = service


        # ====================================================
        # CREATE FINDING
        # ====================================================

        finding = {

            "port": port,

            "protocol": protocol,

            "severity": severity,

            "service": service,

            "product": detected_product,

            "version": version,

            "reason": reason,

            "recommendation": recommendation,

            "risk_points": points

        }


        findings.append(finding)

        total_risk += points


    # ========================================================
    # SECURITY SCORE
    # ========================================================

    # Start with perfect score
    security_score = 100

    security_score -= total_risk

    # Never go below zero
    security_score = max(
        0,
        security_score
    )


    # ========================================================
    # RISK LEVEL
    # ========================================================

    if security_score >= 90:

        risk_level = "LOW"

    elif security_score >= 70:

        risk_level = "MEDIUM"

    elif security_score >= 40:

        risk_level = "HIGH"

    else:

        risk_level = "CRITICAL"


    # ========================================================
    # FINDING COUNTS
    # ========================================================

    critical_count = len([

        f for f in findings

        if f["severity"] == "CRITICAL"

    ])


    high_count = len([

        f for f in findings

        if f["severity"] == "HIGH"

    ])


    medium_count = len([

        f for f in findings

        if f["severity"] == "MEDIUM"

    ])


    low_count = len([

        f for f in findings

        if f["severity"] == "LOW"

    ])


    # ========================================================
    # SUMMARY
    # ========================================================

    if not findings:

        summary = (
            "No open ports were identified during the scan. "
            "The target has a minimal exposed network surface "
            "based on this scan."
        )

    elif risk_level == "CRITICAL":

        summary = (
            "The scan identified significant network exposure. "
            "Immediate review of exposed services is recommended."
        )

    elif risk_level == "HIGH":

        summary = (
            "The scan identified several services that may "
            "increase the target's network attack surface."
        )

    elif risk_level == "MEDIUM":

        summary = (
            "The scan identified services that should be "
            "reviewed and restricted where appropriate."
        )

    else:

        summary = (
            "The scan identified limited network exposure. "
            "Continue monitoring and maintain secure configurations."
        )


    # ========================================================
    # FINAL ANALYSIS
    # ========================================================

    return {

        "score": security_score,

        "risk_level": risk_level,

        "total_findings": len(findings),

        "critical": critical_count,

        "high": high_count,

        "medium": medium_count,

        "low": low_count,

        "summary": summary,

        "findings": findings

    }