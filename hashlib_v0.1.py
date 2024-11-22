import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import hashlib
import requests
import os

url = "https://www.virustotal.com/api/v3/files/{}"
api_key = "*"

hybrid_url = "https://hybrid-analysis.com/api/v2/search/hash"
hybrid_api_key = "*"

all_engines = ["Kaspersky", "AhnLab-V3", "FireEye", "ALYac", "CrowdStrike"]
files_to_scan = []
current_index = 0
index = 1

def calculate_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def scan_file_with_virustotal(md5_hash):
    headers = {"x-apikey": api_key}
    response = requests.get(url.format(md5_hash), headers=headers)
    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return {"error": {"code": response.status_code, "message": "Virustotal API Error"}}

def scan_file_with_hybrid_analysis(md5_hash):
    headers = {
        "accept": "application/json",
        "api-key": hybrid_api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "hash": md5_hash
    }
    response = requests.post(hybrid_url, headers=headers, data=data)
    if response.status_code == 200:
        hybrid_result = response.json()
        return hybrid_result
    else:
        return {"error": {"code": response.status_code, "message": "Hybrid Analysis API Error"}}

def scan_next_file():
    global files_to_scan, current_index, all_engines
    if current_index < len(files_to_scan):
        file_path = files_to_scan[current_index]
        file_name = os.path.basename(file_path)
        file_md5 = calculate_md5(file_path)

        virustotal_result = scan_file_with_virustotal(file_md5)
        hybrid_results = scan_file_with_hybrid_analysis(file_md5)

        file_info = {
            "file_name": file_name,
            "file_md5": file_md5,
        }
        handle_results(file_info, virustotal_result, hybrid_results)

        current_index += 1
        root.after(100, scan_next_file)

def handle_results(file_info, virustotal_result, hybrid_results):
    global tableview, index

    if virustotal_result and "data" in virustotal_result:
        data = virustotal_result["data"]
        attributes = data.get("attributes", {})
        last_analysis = attributes.get("last_analysis_results", {})

        file_info.update({
            "total_votes": attributes.get('total_votes', ''),
        })

        for engine, scan_result in last_analysis.items():
            category = scan_result.get('category', '')
            result = scan_result.get('result', '')
            file_info[engine] = f"{category} / {result}"

        for hybrid_result in hybrid_results:
            if hybrid_result:
                av_detect = hybrid_result.get('av_detect', '')
                threat_level = hybrid_result.get('threat_level', '')
                verdict = hybrid_result.get('verdict', '')

                file_info.update({
                    "Hybrid_AV_Detect": av_detect,
                    "Hybrid_Threat_Level": threat_level,
                    "Hybrid_Verdict": verdict,
                })

                values = [
                    index,
                    file_info['file_name'],
                    file_info['file_md5'],
                    hybrid_result.get('av_detect', ''),
                    hybrid_result.get('threat_level', ''),
                    hybrid_result.get('verdict', ''),
                    file_info.get('total_votes', ''),
                    file_info.get('error_code', ''),
                    file_info.get('Kaspersky', ''),
                    file_info.get('AhnLab-V3', ''),
                    file_info.get('FireEye', ''),
                    file_info.get('ALYac', ''),
                    file_info.get('CrowdStrike', '')
                ]
                tableview.insert("", "end", values=values)
                index += 1
            else:
                values = [
                    index,
                    file_info['file_name'],
                    file_info['file_md5'],
                    '',
                    '',
                    '',
                    '',
                    'Not Found',
                    '',
                    '',
                    '',
                    '',
                    ''
                ]
                tableview.insert("", "end", values=values)
                index += 1
    else:
        values = [
            index,
            file_info['file_name'],
            file_info['file_md5'],
            '',
            '',
            '',
            '',
            'Not Found',
            '',
            '',
            '',
            '',
            ''
        ]
        tableview.insert("", "end", values=values)
        index += 1

def select_folder():
    global files_to_scan, current_index
    folder_selected = filedialog.askdirectory()
    folder_path.delete(0, tk.END)
    folder_path.insert(tk.END, folder_selected)

    files_to_scan = [os.path.join(folder_selected, file) for file in os.listdir(folder_selected)]
    current_index = 0

def scan_folder():
    scan_next_file()

root = tk.Tk()
root.title("VirusTotal File Scanner")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

folder_label = tk.Label(frame, text="Select Folder:")
folder_label.grid(row=0, column=0)

folder_path = tk.Entry(frame, width=50)
folder_path.grid(row=0, column=1)

browse_button = tk.Button(frame, text="Browse", command=select_folder)
browse_button.grid(row=0, column=2)

scan_button = tk.Button(frame, text="Scan Folder", command=scan_folder)
scan_button.grid(row=0, column=3)

result_print_frame = tk.LabelFrame(root, text="검색 결과")
result_print_frame.pack(side="top", fill="both", expand=True)

result_frame = tk.Frame(result_print_frame)
result_frame.pack(side="top", fill="both", expand=True)

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

scrollbar = tk.Scrollbar(result_frame)
scrollbar.pack(side="right", fill="y")

tableview = ttk.Treeview(result_frame, columns=["index", "file_name", "file_md5", "Hybrid_Verdict",
                                                "Hybrid_AV_Detect", "Hybrid_Threat_Level",
                                                "total_votes", "error_code",
                                                "Kaspersky", "AhnLab-V3", "FireEye",
                                                "ALYac", "CrowdStrike"],
                         displaycolumns=["index", "file_name", "file_md5", "Hybrid_Verdict",
                                         "Hybrid_AV_Detect", "Hybrid_Threat_Level",
                                         "total_votes", "error_code",
                                         "Kaspersky", "AhnLab-V3", "FireEye",
                                         "ALYac", "CrowdStrike"],
                         height=20, yscrollcommand=scrollbar.set)

tableview.pack(fill="both", expand=True)

tableview.column("#0", width=0, stretch=tk.NO)

tableview.column("index", width=15, anchor="center")
tableview.heading("index", text="No.", anchor="center")

tableview.column("file_name", width=80, anchor="center")
tableview.heading("file_name", text="파일명", anchor="center")

tableview.column("file_md5", width=80, anchor="center")
tableview.heading("file_md5", text="MD5", anchor="center")

tableview.column("Hybrid_Verdict", width=80, anchor="center")
tableview.heading("Hybrid_Verdict", text="Hybrid_VD", anchor="center")

tableview.column("Hybrid_AV_Detect", width=80, anchor="center")
tableview.heading("Hybrid_AV_Detect", text="Hybrid_AV", anchor="center")

tableview.column("Hybrid_Threat_Level", width=80, anchor="center")
tableview.heading("Hybrid_Threat_Level", text="Hybrid_Threat", anchor="center")

tableview.column("total_votes", width=80, anchor="center")
tableview.heading("total_votes", text="Total AV", anchor="center")

tableview.column("error_code", width=80, anchor="center")
tableview.heading("error_code", text="Error", anchor="center")

tableview.column("Kaspersky", width=80, anchor="center")
tableview.heading("Kaspersky", text="Kaspersky", anchor="center")

tableview.column("AhnLab-V3", width=80, anchor="center")
tableview.heading("AhnLab-V3", text="AhnLab-V3", anchor="center")

tableview.column("FireEye", width=80, anchor="center")
tableview.heading("FireEye", text="FireEye", anchor="center")

tableview.column("ALYac", width=80, anchor="center")
tableview.heading("ALYac", text="ALYac", anchor="center")

tableview.column("CrowdStrike", width=80, anchor="center")
tableview.heading("CrowdStrike", text="CrowdStrike", anchor="center")

scrollbar.config(command=tableview.yview)

root.mainloop()
