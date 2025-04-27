import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import csv
from collections import Counter

EXCLUDED_PROCESSES = [
    'procmon64.exe',
    'explorer.exe',
    'System Idle Process',
    'System',
    'services.exe',
    'csrss.exe',
    'wininit.exe',
    'svchost.exe',
    'VBoxService.exe',
    'VBoxTray.exe',
    'conhost.exe',
    'lsass.exe',
    'smss.exe',
    'winlogon.exe',
    'spoolsv.exe',
    'taskhostw.exe',
    'SearchIndexer.exe',
    'backgroundTaskHost.exe',
    'fontdrvhost.exe',
    'dwm.exe',
    'WmiPrvSE.exe',
    'sihost.exe',
    'RuntimeBroker.exe',
    'ctfmon.exe',
    'audiodg.exe',
    'rundll32.exe',
    'dllhost.exe',
    'appinfo.exe',
    'msdtc.exe',
    'SettingSyncHost.exe',
    'SearchFilterHost.exe',
    'SearchProtocolHost.exe',
    'ShellExperienceHost.exe',
    'StartMenuExperienceHost.exe',
    'SecurityHealthService.exe',
    'ApplicationFrameHost.exe',
    'Microsoft.Photos.exe',
    'sppsvc.exe',
    'WUDFHost.exe',
    'dasHost.exe',
    'msmpeng.exe',
    'MpCmdRun.exe',
]
FILE_CREATION_OPS = ['CreateFile', 'WriteFile']
REGISTRY_OPS = ['RegCreateKey', 'RegSetValue', 'RegDeleteValue', 'RegDeleteKey', 'RegQueryValue', 'RegQueryKey', 'RegOpenKey']

class FileDropperTracker(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File & Registry Dropper Tracker")
        self.geometry("1200x700")

        self.tab_control = ttk.Notebook(self)
        self.file_tab = ttk.Frame(self.tab_control)
        self.reg_tab = ttk.Frame(self.tab_control)
        self.summary_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.file_tab, text='File Activity')
        self.tab_control.add(self.reg_tab, text='Registry Modifications')
        self.tab_control.add(self.summary_tab, text='Summary')
        self.tab_control.pack(expand=1, fill='both')

        self.file_data = []
        self.reg_data = []

        self.create_file_tab()
        self.create_reg_tab()
        self.create_summary_tab()

    def create_file_tab(self):
        self.file_frame = ttk.Frame(self.file_tab)
        self.file_frame.pack(fill='both', expand=True)

        self.file_search_var = tk.StringVar()
        file_search_frame = ttk.Frame(self.file_frame)
        file_search_frame.pack(fill='x')
        ttk.Entry(file_search_frame, textvariable=self.file_search_var).pack(side='left', fill='x', expand=True)
        ttk.Button(file_search_frame, text="Search", command=self.search_file_activity).pack(side='left')

        self.file_tree = ttk.Treeview(self.file_frame, columns=('Process', 'Path', 'Operation'), show='headings')
        for col in self.file_tree["columns"]:
            self.file_tree.heading(col, text=col)
            self.file_tree.column(col, width=300)
        self.file_tree.pack(side='left', fill='both', expand=True)
        file_scroll = ttk.Scrollbar(self.file_frame, orient='vertical', command=self.file_tree.yview)
        self.file_tree.configure(yscroll=file_scroll.set)
        file_scroll.pack(side='right', fill='y')

        file_buttons = ttk.Frame(self.file_tab)
        file_buttons.pack(side='bottom', fill='x')
        ttk.Button(file_buttons, text="Load Procmon CSV", command=self.load_procmon_csv).pack(side='left', padx=5, pady=5)
        ttk.Button(file_buttons, text="Export File Report (.csv)", command=self.export_file_report).pack(side='left', padx=5)

    def create_reg_tab(self):
        self.reg_frame = ttk.Frame(self.reg_tab)
        self.reg_frame.pack(fill='both', expand=True)

        self.reg_search_var = tk.StringVar()
        reg_search_frame = ttk.Frame(self.reg_frame)
        reg_search_frame.pack(fill='x')
        ttk.Entry(reg_search_frame, textvariable=self.reg_search_var).pack(side='left', fill='x', expand=True)
        ttk.Button(reg_search_frame, text="Search", command=self.search_registry_mods).pack(side='left')

        self.reg_tree = ttk.Treeview(self.reg_frame, columns=('Process', 'Operation', 'Path'), show='headings')
        for col in self.reg_tree["columns"]:
            self.reg_tree.heading(col, text=col)
            self.reg_tree.column(col, width=300)
        self.reg_tree.pack(side='left', fill='both', expand=True)
        reg_scroll = ttk.Scrollbar(self.reg_frame, orient='vertical', command=self.reg_tree.yview)
        self.reg_tree.configure(yscroll=reg_scroll.set)
        reg_scroll.pack(side='right', fill='y')

        reg_buttons = ttk.Frame(self.reg_tab)
        reg_buttons.pack(side='bottom', fill='x')
        ttk.Button(reg_buttons, text="Export Registry Report (.csv)", command=self.export_registry_report).pack(side='left', padx=5, pady=5)

    def create_summary_tab(self):
        self.summary_table = ttk.Treeview(self.summary_tab, columns=("Process", "File Ops", "Registry Ops"), show='headings')
        for col in self.summary_table["columns"]:
            self.summary_table.heading(col, text=col)
            self.summary_table.column(col, width=300)
        self.summary_table.pack(fill='both', expand=True)

    def refresh_summary_tab(self):
        from collections import Counter
        self.summary_table.delete(*self.summary_table.get_children())

        file_counter = Counter(entry[0] for entry in self.file_data)
        reg_counter = Counter(entry[0] for entry in self.reg_data)
        all_procs = sorted(set(file_counter.keys()).union(reg_counter.keys()))

        for proc in all_procs:
            file_count = file_counter.get(proc, 0)
            reg_count = reg_counter.get(proc, 0)
            self.summary_table.insert("", "end", values=(proc, file_count, reg_count))

    def load_procmon_csv(self):
        filepath = filedialog.askopenfilename(title="Select Procmon CSV", filetypes=[("CSV files", "*.csv")])
        if not filepath:
            return
        try:
            with open(filepath, newline='', encoding='utf-8', errors='ignore') as csvfile:
                reader = csv.DictReader(csvfile)
                if not reader.fieldnames:
                    messagebox.showerror("Error", "CSV headers not found.")
                    return

                self.file_data.clear()
                self.reg_data.clear()
                self.file_tree.delete(*self.file_tree.get_children())
                self.reg_tree.delete(*self.reg_tree.get_children())

                for row in reader:
                    process = str(row.get("Process Name", "")).strip()
                    operation = str(row.get("Operation", "")).strip()
                    path = str(row.get("Path", "")).strip()

                    process_lc = process.lower()
                    operation_lc = operation.lower()

                    if process_lc in [p.lower() for p in EXCLUDED_PROCESSES]:
                        continue

                    if any(op.lower() in operation_lc for op in REGISTRY_OPS):
                        entry = (process, operation, path)
                        self.reg_data.append(entry)
                        self.reg_tree.insert("", "end", values=entry)

                    elif any(keyword in operation_lc for keyword in ['create', 'write', 'acquire']) and not any(reg in operation_lc for reg in ['regcreate', 'regset', 'regdelete']):
                        entry = (process, path, operation)
                        self.file_data.append(entry)
                        self.file_tree.insert("", "end", values=entry)

                self.refresh_summary_tab()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse CSV: {e}")

    def search_file_activity(self):
        query = self.file_search_var.get().lower()
        self.file_tree.delete(*self.file_tree.get_children())
        for entry in self.file_data:
            if any(query in str(val).lower() for val in entry):
                self.file_tree.insert("", "end", values=entry)

    def search_registry_mods(self):
        query = self.reg_search_var.get().lower()
        self.reg_tree.delete(*self.reg_tree.get_children())
        for entry in self.reg_data:
            if any(query in str(val).lower() for val in entry):
                self.reg_tree.insert("", "end", values=entry)

    def export_file_report(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", title="Save File Report", filetypes=[("CSV files", "*.csv")])
        if not filename:
            return
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Process', 'Path', 'Operation'])
                for row in self.file_data:
                    writer.writerow(row)
            messagebox.showinfo("Success", "File report exported successfully!")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save report: {e}")

    def export_registry_report(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", title="Save Registry Report", filetypes=[("CSV files", "*.csv")])
        if not filename:
            return
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Process', 'Operation', 'Path'])
                for row in self.reg_data:
                    writer.writerow(row)
            messagebox.showinfo("Success", "Registry report exported successfully!")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save registry report: {e}")

if __name__ == "__main__":
    app = FileDropperTracker()
    app.mainloop()