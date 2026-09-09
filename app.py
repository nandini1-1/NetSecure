from flask import (
    Flask,
    render_template,
    request,
    send_file,
    session
)

from scanner.nmap_scanner import (
    scan_target,
    SCAN_TYPES
)

from database.database import (
    save_scan,
    get_all_scans,
    get_scan_by_id,
    init_database
)

from analysis.risk_analyzer import analyze_scan

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.enums import TA_CENTER

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

import ipaddress
import re
import json
import secrets


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = "NETSECURE_CHANGE_THIS_SECRET_KEY"


# ============================================================
# BROWSER CLIENT ID
# ============================================================

def get_client_id():

    """
    Creates a unique anonymous ID for each browser.

    No login or username is required.

    The ID is stored in the Flask session cookie.
    """

    if "client_id" not in session:

        session["client_id"] = secrets.token_hex(32)

    return session["client_id"]


# ============================================================
# GET USER-FACING SCAN NUMBER
# ============================================================

def get_display_scan_number(
    scan_id,
    client_id
):

    """
    Converts the internal SQLite ID into a simple
    user-facing scan number.

    Example:

        Internal SQLite IDs:
            44
            45
            46

        User-facing numbers:
            1
            2
            3

    The database ID is NOT changed.
    """

    scans = get_all_scans(
        client_id
    )

    for number, scan in enumerate(
        scans,
        start=1
    ):

        if int(scan["id"]) == int(scan_id):

            return number

    return 1


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(target):

    target = target.strip()

    # --------------------------------------------------------
    # Remove HTTP / HTTPS
    # --------------------------------------------------------

    target = re.sub(
        r"^https?://",
        "",
        target,
        flags=re.IGNORECASE
    )

    # --------------------------------------------------------
    # Remove trailing slash
    # --------------------------------------------------------

    target = target.rstrip("/")

    # --------------------------------------------------------
    # Empty target
    # --------------------------------------------------------

    if not target:

        return (
            False,
            "Please enter a target.",
            target
        )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    try:

        ipaddress.ip_address(target)

        return (
            True,
            "",
            target
        )

    except ValueError:

        pass

    # --------------------------------------------------------
    # DOMAIN / HOSTNAME
    # --------------------------------------------------------

    hostname_pattern = (
        r"^(?=.{1,253}$)"
        r"([a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )

    if not re.match(
        hostname_pattern,
        target
    ):

        return (
            False,
            "Invalid IP address or hostname.",
            target
        )

    return (
        True,
        "",
        target
    )


# ============================================================
# HOME / DASHBOARD
# ============================================================

@app.route("/")
def home():

    get_client_id()

    return render_template(
        "index.html",
        scan_types=SCAN_TYPES
    )


# ============================================================
# NMAP SCAN
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    # --------------------------------------------------------
    # Get browser ID
    # --------------------------------------------------------

    client_id = get_client_id()

    # --------------------------------------------------------
    # Get target
    # --------------------------------------------------------

    target = request.form.get(
        "target",
        ""
    ).strip()

    # --------------------------------------------------------
    # Get scan type
    # --------------------------------------------------------

    scan_type = request.form.get(
        "scan_type",
        "tcp_connect"
    )

    # ========================================================
    # VALIDATE SCAN TYPE
    # ========================================================

    if scan_type not in SCAN_TYPES:

        return render_template(
            "results.html",
            target=target,
            results={
                "error": "Invalid scan type."
            }
        )

    # ========================================================
    # VALIDATE TARGET
    # ========================================================

    valid, message, cleaned_target = (
        validate_target(target)
    )

    if not valid:

        return render_template(
            "results.html",
            target=target,
            results={
                "error": message
            }
        )

    # ========================================================
    # RUN NMAP SCAN
    # ========================================================

    results = scan_target(
        cleaned_target,
        scan_type
    )

    # ========================================================
    # HANDLE NMAP ERROR
    # ========================================================

    if "error" in results:

        return render_template(
            "results.html",
            target=cleaned_target,
            results=results
        )

    # ========================================================
    # COUNT OPEN PORTS
    # ========================================================

    open_ports = len([

        port

        for port in results.get(
            "ports",
            []
        )

        if port.get(
            "state"
        ) == "open"

    ])

    # ========================================================
    # SECURITY RISK ANALYSIS
    # ========================================================

    security_analysis = analyze_scan(
        results
    )

    results["security"] = (
        security_analysis
    )

    # ========================================================
    # SAVE SCAN
    # ========================================================

    save_scan(

        target=cleaned_target,

        open_ports=open_ports,

        status="Completed",

        scan_type=scan_type,

        results=results,

        client_id=client_id

    )

    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    return render_template(

        "results.html",

        target=cleaned_target,

        results=results

    )


# ============================================================
# NMAP COMMANDS / LEARNING MODE
# ============================================================

@app.route("/nmap-commands")
def nmap_commands():

    return render_template(
        "nmap_commands.html"
    )


# ============================================================
# REPORTS
# ============================================================

@app.route("/reports")
def reports():

    return render_template(

        "reports.html",

        scan=None,

        results=None

    )


# ============================================================
# INDIVIDUAL REPORT
# ============================================================

@app.route(
    "/reports/<int:scan_id>"
)
def report_detail(scan_id):

    # --------------------------------------------------------
    # Get browser ID
    # --------------------------------------------------------

    client_id = get_client_id()

    # --------------------------------------------------------
    # Get only this browser's scan
    # --------------------------------------------------------

    scan = get_scan_by_id(
        scan_id,
        client_id
    )

    # --------------------------------------------------------
    # Report not found
    # --------------------------------------------------------

    if scan is None:

        return render_template(

            "reports.html",

            scan=None,

            results=None

        )

    # --------------------------------------------------------
    # Convert sqlite3.Row to dictionary
    # --------------------------------------------------------

    scan = dict(scan)

    # --------------------------------------------------------
    # Get user-facing number
    # --------------------------------------------------------

    scan["display_id"] = get_display_scan_number(
        scan_id,
        client_id
    )

    # ========================================================
    # LOAD SAVED RESULTS
    # ========================================================

    results = None

    if scan.get("results"):

        try:

            results = json.loads(
                scan["results"]
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            results = None

    # ========================================================
    # DISPLAY REPORT
    # ========================================================

    return render_template(

        "reports.html",

        scan=scan,

        results=results

    )


# ============================================================
# PDF WATERMARK
# ============================================================

def add_pdf_watermark(
    canvas,
    document
):

    """
    Adds a light diagonal NETSECURE watermark
    to every PDF page.
    """

    page_width, page_height = A4

    # ========================================================
    # WATERMARK
    # ========================================================

    canvas.saveState()

    canvas.translate(
        page_width / 2,
        page_height / 2
    )

    canvas.rotate(35)

    canvas.setFillColorRGB(
        0.88,
        0.88,
        0.88
    )

    canvas.setFont(
        "Helvetica-Bold",
        55
    )

    canvas.drawCentredString(
        0,
        0,
        "NETSECURE"
    )

    canvas.restoreState()

    # ========================================================
    # FOOTER
    # ========================================================

    canvas.saveState()

    canvas.setFillColor(
        colors.grey
    )

    canvas.setFont(
        "Helvetica",
        7
    )

    canvas.drawCentredString(

        page_width / 2,

        20,

        (
            "NetSecure • Network Security Assessment Tool "
            f"• Page {doc_page_number(canvas)}"
        )

    )

    canvas.restoreState()


# ============================================================
# PDF PAGE NUMBER
# ============================================================

def doc_page_number(canvas):

    try:

        return canvas.getPageNumber()

    except Exception:

        return ""


# ============================================================
# PDF REPORT
# ============================================================

@app.route(
    "/reports/<int:scan_id>/pdf"
)
def download_pdf(scan_id):

    # --------------------------------------------------------
    # Get browser ID
    # --------------------------------------------------------

    client_id = get_client_id()

    # --------------------------------------------------------
    # Get only this browser's report
    # --------------------------------------------------------

    scan = get_scan_by_id(
        scan_id,
        client_id
    )

    # --------------------------------------------------------
    # Report not found
    # --------------------------------------------------------

    if scan is None:

        return (
            "Report not found.",
            404
        )

    # --------------------------------------------------------
    # Convert sqlite3.Row to dictionary
    # --------------------------------------------------------

    scan = dict(scan)

    # --------------------------------------------------------
    # IMPORTANT:
    # Get user-facing scan number.
    #
    # This prevents filenames such as:
    # NetSecure_Report_44.pdf
    #
    # Instead the user gets:
    # NetSecure_Report_1.pdf
    # --------------------------------------------------------

    display_scan_number = get_display_scan_number(
        scan_id,
        client_id
    )

    # ========================================================
    # LOAD SAVED RESULTS
    # ========================================================

    results = {}

    if scan.get("results"):

        try:

            results = json.loads(
                scan["results"]
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            results = {}

    # ========================================================
    # CREATE PDF IN MEMORY
    # ========================================================

    pdf_buffer = BytesIO()

    document = SimpleDocTemplate(

        pdf_buffer,

        pagesize=A4,

        rightMargin=40,

        leftMargin=40,

        topMargin=40,

        bottomMargin=40

    )

    # ========================================================
    # PDF STYLES
    # ========================================================

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(

        "ReportTitle",

        parent=styles["Title"],

        alignment=TA_CENTER,

        fontSize=22,

        spaceAfter=10

    )

    subtitle_style = ParagraphStyle(

        "ReportSubtitle",

        parent=styles["Heading2"],

        alignment=TA_CENTER,

        fontSize=13,

        spaceAfter=20

    )

    heading_style = ParagraphStyle(

        "ReportHeading",

        parent=styles["Heading2"],

        fontSize=15,

        spaceBefore=15,

        spaceAfter=10

    )

    normal_style = ParagraphStyle(

        "ReportNormal",

        parent=styles["BodyText"],

        fontSize=9,

        leading=13

    )

    footer_style = ParagraphStyle(

        "Footer",

        parent=styles["BodyText"],

        alignment=TA_CENTER,

        fontSize=8

    )

    story = []

    # ========================================================
    # TITLE
    # ========================================================

    story.append(

        Paragraph(
            "NetSecure",
            title_style
        )

    )

    story.append(

        Paragraph(
            "Network Security Assessment Report",
            subtitle_style
        )

    )

    story.append(

        Paragraph(
            f"Scan #{display_scan_number}",
            normal_style
        )

    )

    story.append(
        Spacer(1, 10)
    )

    # ========================================================
    # SCAN INFORMATION
    # ========================================================

    story.append(

        Paragraph(
            "Scan Information",
            heading_style
        )

    )

    scan_info = [

        [
            "Scan Number",
            str(display_scan_number)
        ],

        [
            "Target",

            str(
                scan.get(
                    "target",
                    results.get(
                        "target",
                        "Unknown"
                    )
                )
            )
        ],

        [
            "Scan Type",

            str(
                results.get(
                    "scan_name",
                    scan.get(
                        "scan_type",
                        "Unknown"
                    )
                )
            )
        ],

        [
            "Status",

            str(
                scan.get(
                    "status",
                    "Unknown"
                )
            )
        ],

        [
            "Open Ports",

            str(
                scan.get(
                    "open_ports",
                    0
                )
            )
        ]

    ]

    scan_table = Table(

        scan_info,

        colWidths=[
            130,
            350
        ]

    )

    scan_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            )

        ])

    )

    story.append(
        scan_table
    )

    # ========================================================
    # SECURITY ASSESSMENT
    # ========================================================

    security = results.get(
        "security",
        {}
    )

    if security:

        story.append(

            Paragraph(
                "Security Risk Assessment",
                heading_style
            )

        )

        security_info = [

            [
                "Security Score",
                f'{security.get("score", 0)}/100'
            ],

            [
                "Risk Level",
                security.get(
                    "risk_level",
                    "Unknown"
                )
            ],

            [
                "Total Findings",
                str(
                    security.get(
                        "total_findings",
                        0
                    )
                )
            ],

            [
                "Critical",
                str(
                    security.get(
                        "critical",
                        0
                    )
                )
            ],

            [
                "High",
                str(
                    security.get(
                        "high",
                        0
                    )
                )
            ],

            [
                "Medium",
                str(
                    security.get(
                        "medium",
                        0
                    )
                )
            ],

            [
                "Low",
                str(
                    security.get(
                        "low",
                        0
                    )
                )
            ]

        ]

        security_table = Table(

            security_info,

            colWidths=[
                160,
                320
            ]

        )

        security_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold"
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )

            ])

        )

        story.append(
            security_table
        )

        # ====================================================
        # RISK SUMMARY
        # ====================================================

        story.append(

            Paragraph(
                "Risk Summary",
                heading_style
            )

        )

        summary = security.get(
            "summary",
            "No security summary available."
        )

        story.append(

            Paragraph(
                str(summary),
                normal_style
            )

        )

        # ====================================================
        # SECURITY FINDINGS
        # ====================================================

        findings = security.get(
            "findings",
            []
        )

        if findings:

            story.append(

                Paragraph(
                    "Security Findings",
                    heading_style
                )

            )

            for number, finding in enumerate(
                findings,
                start=1
            ):

                story.append(

                    Paragraph(

                        (
                            f"<b>Finding {number}: "
                            f"Port {finding.get('port', 'N/A')}/"
                            f"{finding.get('protocol', 'tcp').upper()}</b>"
                        ),

                        normal_style

                    )

                )

                finding_data = [

                    [
                        "Severity",
                        str(
                            finding.get(
                                "severity",
                                "Unknown"
                            )
                        )
                    ],

                    [
                        "Service",
                        str(
                            finding.get(
                                "service",
                                "Unknown"
                            )
                        )
                    ],

                    [
                        "Product",
                        str(
                            finding.get(
                                "product",
                                "Unknown"
                            )
                        )
                    ],

                    [
                        "Version",
                        str(
                            finding.get(
                                "version",
                                "Unknown"
                            )
                        )
                    ],

                    [
                        "Risk Points",
                        str(
                            finding.get(
                                "risk_points",
                                0
                            )
                        )
                    ]

                ]

                finding_table = Table(

                    finding_data,

                    colWidths=[
                        120,
                        360
                    ]

                )

                finding_table.setStyle(

                    TableStyle([

                        (
                            "BACKGROUND",
                            (0, 0),
                            (0, -1),
                            colors.whitesmoke
                        ),

                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            colors.grey
                        ),

                        (
                            "FONTNAME",
                            (0, 0),
                            (0, -1),
                            "Helvetica-Bold"
                        ),

                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP"
                        )

                    ])

                )

                story.append(
                    finding_table
                )

                story.append(
                    Spacer(1, 6)
                )

                story.append(

                    Paragraph(

                        (
                            "<b>Why this matters:</b> "
                            + str(
                                finding.get(
                                    "reason",
                                    "Not available."
                                )
                            )
                        ),

                        normal_style

                    )

                )

                story.append(
                    Spacer(1, 5)
                )

                story.append(

                    Paragraph(

                        (
                            "<b>Recommended Fix:</b> "
                            + str(
                                finding.get(
                                    "recommendation",
                                    "Review this service."
                                )
                            )
                        ),

                        normal_style

                    )

                )

                story.append(
                    Spacer(1, 15)
                )

    # ========================================================
    # DETECTED PORTS
    # ========================================================

    ports = results.get(
        "ports",
        []
    )

    if ports:

        story.append(

            Paragraph(
                "Detected Ports and Services",
                heading_style
            )

        )

        port_data = [

            [
                "Port",
                "Protocol",
                "State",
                "Service",
                "Version"
            ]

        ]

        for port in ports:

            port_data.append([

                str(
                    port.get(
                        "port",
                        "N/A"
                    )
                ),

                str(
                    port.get(
                        "protocol",
                        "N/A"
                    )
                ).upper(),

                str(
                    port.get(
                        "state",
                        "Unknown"
                    )
                ),

                str(
                    port.get(
                        "service",
                        "Unknown"
                    )
                ),

                str(
                    port.get(
                        "version",
                        "Unknown"
                    )
                )

            ])

        port_table = Table(

            port_data,

            colWidths=[
                55,
                65,
                70,
                100,
                190
            ],

            repeatRows=1

        )

        port_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )

            ])

        )

        story.append(
            port_table
        )

    # ========================================================
    # OS DETECTION
    # ========================================================

    if results.get("os"):

        story.append(

            Paragraph(
                "Operating System Detection",
                heading_style
            )

        )

        os_data = [

            [
                "Operating System",
                "Accuracy"
            ]

        ]

        for os_match in results["os"]:

            os_data.append([

                str(
                    os_match.get(
                        "name",
                        "Unknown"
                    )
                ),

                str(
                    os_match.get(
                        "accuracy",
                        "Unknown"
                    )
                ) + "%"

            ])

        os_table = Table(

            os_data,

            colWidths=[
                380,
                100
            ],

            repeatRows=1

        )

        os_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                )

            ])

        )

        story.append(
            os_table
        )

    # ========================================================
    # RAW NMAP OUTPUT
    # ========================================================

    raw_output = results.get(
        "raw_output",
        ""
    )

    if raw_output:

        story.append(
            PageBreak()
        )

        story.append(

            Paragraph(
                "Raw Nmap Output",
                heading_style
            )

        )

        raw_output = (
            str(raw_output)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        story.append(

            Paragraph(

                (
                    "<font name='Courier' size='7'>"
                    + raw_output.replace(
                        "\n",
                        "<br/>"
                    )
                    + "</font>"
                ),

                normal_style

            )

        )

    # ========================================================
    # FOOTER CONTENT
    # ========================================================

    story.append(
        Spacer(1, 25)
    )

    story.append(

        Paragraph(

            "NetSecure • Network Security Assessment Tool",

            footer_style

        )

    )

    # ========================================================
    # BUILD PDF WITH WATERMARK
    # ========================================================

    document.build(

        story,

        onFirstPage=add_pdf_watermark,

        onLaterPages=add_pdf_watermark

    )

    pdf_buffer.seek(0)

    # ========================================================
    # DOWNLOAD PDF
    # ========================================================

    return send_file(

        pdf_buffer,

        as_attachment=True,

        download_name=(
            f"NetSecure_Report_{display_scan_number}.pdf"
        ),

        mimetype="application/pdf"

    )


# ============================================================
# SCAN HISTORY
# ============================================================

@app.route("/history")
def history():

    # --------------------------------------------------------
    # Get this browser's ID
    # --------------------------------------------------------

    client_id = get_client_id()

    # --------------------------------------------------------
    # Get only this browser's scans
    # --------------------------------------------------------

    scans = get_all_scans(
        client_id
    )

    # --------------------------------------------------------
    # Create user-facing serial numbers
    # --------------------------------------------------------

    history_scans = []

    for number, scan in enumerate(
        scans,
        start=1
    ):

        scan_data = dict(scan)

        # Real SQLite ID remains untouched.
        scan_data["display_id"] = number

        history_scans.append(
            scan_data
        )

    # --------------------------------------------------------
    # Display history
    # --------------------------------------------------------

    return render_template(

        "history.html",

        scans=history_scans

    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # Initialize database
    # --------------------------------------------------------

    init_database()

    # --------------------------------------------------------
    # Start Flask development server
    # --------------------------------------------------------

    app.run(
        debug=True
    )