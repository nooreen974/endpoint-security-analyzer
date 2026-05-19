import os
import platform
import subprocess
import psutil

# =========================================================
# CLEAR SCREEN
# =========================================================

os.system("cls" if os.name == "nt" else "clear")

# =========================================================
# HEADER
# =========================================================

print("\n")

print("=" * 60)

print("WINDOWS ENDPOINT SECURITY ANALYZER")

print("=" * 60)

# =========================================================
# OS INFORMATION
# =========================================================

print("\nSYSTEM INFORMATION")

print("-" * 60)

print(f"Operating System : {platform.system()}")

print(f"Release          : {platform.release()}")

print(f"Version          : {platform.version()}")

print(f"Machine          : {platform.machine()}")

# =========================================================
# SECURITY PRODUCT DETECTION
# =========================================================

print("\n")

print("=" * 60)

print("SECURITY PRODUCT DETECTION")

print("=" * 60)

security_products = {

    "Windows Defender": [
        "WinDefend"
    ],

    "Carbon Black": [
        "CbDefense",
        "Parity",
        "CarbonBlack"
    ],

    "CrowdStrike": [
        "CSFalconService"
    ],

    "SentinelOne": [
        "SentinelAgent"
    ],

    "Palo Alto Cortex": [
        "Cortex XDR",
        "cyserver"
    ]
}

detected_products = []

# =========================================================
# CHECK SERVICES
# =========================================================

try:

    services = psutil.win_service_iter()

    service_names = []

    for service in services:

        try:

            service_info = service.as_dict()

            service_names.append(
                service_info["name"]
            )

        except:

            pass

    for product, indicators in security_products.items():

        for indicator in indicators:

            for service_name in service_names:

                if indicator.lower() in service_name.lower():

                    detected_products.append(product)

                    break

except Exception as error:

    print(f"Error detecting services: {error}")

# =========================================================
# DISPLAY PRODUCTS
# =========================================================

if detected_products:

    for product in set(detected_products):

        print(f"[DETECTED] {product}")

else:

    print("No known security products detected.")

# =========================================================
# FIREWALL STATUS
# =========================================================

print("\n")

print("=" * 60)

print("FIREWALL STATUS")

print("=" * 60)

try:

    firewall_output = subprocess.check_output(

        "netsh advfirewall show allprofiles",

        shell=True,

        text=True
    )

    if "ON" in firewall_output:

        print("Windows Firewall : ENABLED")

    else:

        print("Windows Firewall : DISABLED")

except Exception as error:

    print(f"Error checking firewall: {error}")

# =========================================================
# WINDOWS DEFENDER STATUS
# =========================================================

print("\n")

print("=" * 60)

print("WINDOWS DEFENDER STATUS")

print("=" * 60)

try:

    defender_status = subprocess.check_output(

        'powershell Get-MpComputerStatus',

        shell=True,

        text=True
    )

    print("Windows Defender detected.")

except:

    print("Unable to retrieve Defender status.")

# =========================================================
# RUNNING SECURITY SERVICES
# =========================================================

print("\n")

print("=" * 60)

print("RUNNING SECURITY SERVICES")

print("=" * 60)

try:

    services = psutil.win_service_iter()

    for service in services:

        try:

            info = service.as_dict()

            service_name = info["name"]

            service_status = info["status"]

            keywords = [

                "defend",
                "carbon",
                "crowd",
                "sentinel",
                "cortex",
                "security",
                "falcon"
            ]

            for keyword in keywords:

                if keyword.lower() in service_name.lower():

                    print(

                        f"{service_name:<35} : "

                        f"{service_status}"
                    )

                    break

        except:

            pass

except Exception as error:

    print(f"Error checking services: {error}")

# =========================================================
# DRIVER INFORMATION
# =========================================================

print("\n")

print("=" * 60)

print("FILTER DRIVERS")

print("=" * 60)

try:

    driver_output = subprocess.check_output(

        "fltmc",

        shell=True,

        text=True
    )

    print(driver_output)

except Exception as error:

    print(f"Error retrieving drivers: {error}")

# =========================================================
# NETWORK CONNECTIONS
# =========================================================

print("\n")

print("=" * 60)

print("ACTIVE NETWORK CONNECTIONS")

print("=" * 60)

try:

    connections = psutil.net_connections()

    count = 0

    for connection in connections:

        if connection.raddr:

            print(

                f"Local: {connection.laddr.ip}:{connection.laddr.port}"

                f"  -->  "

                f"Remote: {connection.raddr.ip}:{connection.raddr.port}"
            )

            count += 1

        if count >= 10:

            break

except Exception as error:

    print(f"Error checking network connections: {error}")

# =========================================================
# EVENT LOG CHECK
# =========================================================

print("\n")

print("=" * 60)

print("RECENT SYSTEM ERRORS")

print("=" * 60)

try:

    event_command = (

        'powershell "Get-EventLog -LogName System '

        '-Newest 5 -EntryType Error"'
    )

    event_logs = subprocess.check_output(

        event_command,

        shell=True,

        text=True
    )

    print(event_logs)

except Exception as error:

    print(f"Error retrieving logs: {error}")

# =========================================================
# RECOMMENDATIONS
# =========================================================

print("\n")

print("=" * 60)

print("RECOMMENDATIONS")

print("=" * 60)

if len(detected_products) > 1:

    print(

        "- Multiple security products detected."

    )

    print(

        "- Verify exclusions and policy overlaps."
    )

print(

    "- Review stopped security services."
)

print(

    "- Investigate repeated system errors."
)

print(

    "- Review filter drivers for conflicts."
)

print("\nAnalysis completed.")
