import json
import requests
import os
import subprocess
import platform

# Function to retrieve installed applications on Windows
def get_installed_apps_windows():
    import winreg as reg
    apps = []
    reg_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    for reg_path in reg_paths:
        try:
            key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, reg_path)
            for i in range(reg.QueryInfoKey(key)[0]):
                sub_key_name = reg.EnumKey(key, i)
                sub_key = reg.OpenKey(key, sub_key_name)
                try:
                    app_name = reg.QueryValueEx(sub_key, "DisplayName")[0]
                    app_version = reg.QueryValueEx(sub_key, "DisplayVersion")[0]
                    apps.append({"name": app_name, "version": app_version})
                except Exception as e:
                    continue
        except Exception as e:
            continue
    return apps

# Function to retrieve installed applications on macOS
def get_installed_apps_macos():
    apps = []
    process = subprocess.Popen(["system_profiler", "SPApplicationsDataType"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode('utf-8').split("\n")
    for line in output:
        if "Location: /Applications" in line:
            name = line.split("/Applications/")[1].strip()
            apps.append({"name": name, "version": "unknown"})
    return apps

# Function to retrieve installed applications on Linux
def get_installed_apps_linux():
    apps = []
    process = subprocess.Popen(["dpkg-query", "-W", "-f='${Package} ${Version}\n'"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    output = stdout.decode('utf-8').split("\n")
    for line in output:
        if line:
            parts = line.split()
            if len(parts) == 2:
                apps.append({"name": parts[0].strip("'"), "version": parts[1]})
    return apps

# Determine the OS and retrieve the installed applications
os_type = platform.system()
if os_type == "Windows":
    installed_apps = get_installed_apps_windows()
elif os_type == "Darwin":
    installed_apps = get_installed_apps_macos()
elif os_type == "Linux":
    installed_apps = get_installed_apps_linux()
else:
    raise Exception("Unsupported OS")

# Download and load the recent CVE data
cve_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
cve_file = "nvdcve-1.1-recent.json.gz"
response = requests.get(cve_url)
with open(cve_file, 'wb') as file:
    file.write(response.content)

# Unzip the file if necessary
import gzip
with gzip.open(cve_file, 'rb') as f_in:
    with open('nvdcve-1.1-recent.json', 'wb') as f_out:
        f_out.write(f_in.read())

# Load the CVE data
with open('nvdcve-1.1-recent.json') as f:
    cve_data = json.load(f)

# Function to check if an application is affected by a CVE
def is_affected(app_name, app_version, cve_item):
    description = cve_item['cve']['description']['description_data'][0]['value']
    if app_name.lower() in description.lower():
        return True
    return False

# Check each application against the CVE data
for app in installed_apps:
    app_name = app['name']
    app_version = app['version']
    for item in cve_data['CVE_Items']:
        if is_affected(app_name, app_version, item):
            print(f"Application '{app_name}' version '{app_version}' is affected by {item['cve']['CVE_data_meta']['ID']}")

