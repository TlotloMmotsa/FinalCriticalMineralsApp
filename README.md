# FinalCriticalMineralsApp
#!/usr/bin/env python3



import os
import hashlib
import webbrowser
import pandas as pd
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk

# -----------------------
# Detect OneDrive or use script directory
# -----------------------
HOME = os.path.expanduser("~")
DEFAULT_ONEDRIVE = os.path.join(HOME, "OneDrive")
if os.path.exists(DEFAULT_ONEDRIVE):
    BASE_DIR = DEFAULT_ONEDRIVE
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# -----------------------
# File paths (absolute)
# -----------------------
COUNTRIES_CSV = os.path.join(BASE_DIR, "countries.csv")
MINERALS_CSV = os.path.join(BASE_DIR, "minerals.csv")
PRODUCTION_CSV = os.path.join(BASE_DIR, "production_stats.csv")
ROLES_CSV = os.path.join(BASE_DIR, "roles.csv")
USERS_CSV = os.path.join(BASE_DIR, "users.csv")
SITES_CSV = os.path.join(BASE_DIR, "sites.csv")
MAP_HTML = os.path.join(BASE_DIR, "updatedmap1.html")

# -----------------------
# Utilities: passwords & users
# -----------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed

def load_users_df():
    if os.path.exists(USERS_CSV):
        try:
            return pd.read_csv(USERS_CSV, dtype=str).fillna("")
        except Exception:
            return pd.DataFrame(columns=["UserID","Username","PasswordHash","RoleID","Email"])
    else:
        # create empty users file
        empty = pd.DataFrame(columns=["UserID","Username","PasswordHash","RoleID","Email"])
        empty.to_csv(USERS_CSV, index=False)
        return empty

def save_users_df(df: pd.DataFrame):
    df.to_csv(USERS_CSV, index=False)

# -----------------------
# Load application CSVs safely
# -----------------------
def safe_read_csv(path, expected_cols=None):
    """Read CSV; if missing return empty DataFrame with expected columns (if given)."""
    if not os.path.exists(path):
        if expected_cols:
            return pd.DataFrame(columns=expected_cols)
        return pd.DataFrame()
    try:
        df = pd.read_csv(path)
        if expected_cols:
            for c in expected_cols:
                if c not in df.columns:
                    df[c] = None
        return df
    except Exception:
        if expected_cols:
            return pd.DataFrame(columns=expected_cols)
        return pd.DataFrame()

countries_df = safe_read_csv(COUNTRIES_CSV, ["CountryID","CountryName","GDP_BillionUSD","MiningRevenue_BillionUSD","KeyProjects"])
minerals_df = safe_read_csv(MINERALS_CSV, ["MineralID","MineralName","Description","MarketPriceUSD_per_tonne"])
production_df = safe_read_csv(PRODUCTION_CSV, ["StatID","Year","CountryID","MineralID","Production_tonnes","ExportValue_BillionUSD"])
roles_df = safe_read_csv(ROLES_CSV, ["RoleID","RoleName","Permissions"])
users_df = load_users_df()
sites_df = safe_read_csv(SITES_CSV, ["SiteID","SiteName","CountryName","MineralName","Latitude","Longitude","Production_tonnes"])

# -----------------------
# Ensure required roles exist (Administrator, Investor, Researcher)
# -----------------------
def ensure_roles():
    global roles_df
    required = [
        {"RoleID": 1, "RoleName": "Administrator", "Permissions": "Full access"},
        {"RoleID": 2, "RoleName": "Investor", "Permissions": "View data & charts"},
        {"RoleID": 3, "RoleName": "Researcher", "Permissions": "View & export data"},
    ]
    existing_names = set(roles_df['RoleName'].astype(str).tolist()) if not roles_df.empty else set()
    if not roles_df.shape[0]:
        roles_df = pd.DataFrame(required)
        roles_df.to_csv(ROLES_CSV, index=False)
        return
    added = False
    for r in required:
        if r['RoleName'] not in existing_names:
            roles_df = pd.concat([roles_df, pd.DataFrame([r])], ignore_index=True)
            added = True
    if added:
        roles_df.to_csv(ROLES_CSV, index=False)

ensure_roles()
# reload roles_df to ensure consistent dtypes
roles_df = safe_read_csv(ROLES_CSV, ["RoleID","RoleName","Permissions"])

# -----------------------
# Main Application
# -----------------------
class MineralsApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("African Critical Minerals App")
        self.geometry("1100x700")
        self.minsize(900,600)

        self.current_user = None

        # Top bar
        top = ttk.Frame(self)
        top.pack(side="top", fill="x")
        ttk.Label(top, text="🌍 African Critical Minerals", font=("Segoe UI", 14, "bold")).pack(side="left", padx=10, pady=8)
        self.user_label = ttk.Label(top, text="Not logged in", font=("Segoe UI", 10))
        self.user_label.pack(side="right", padx=10)

        # Notebook
        self.notebook = ttk.Notebook(self)
        self.login_frame = ttk.Frame(self.notebook)
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.map_frame = ttk.Frame(self.notebook)
        self.analytics_frame = ttk.Frame(self.notebook)
        self.profiles_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.login_frame, text="Login / Sign up")
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.notebook.add(self.map_frame, text="Map")
        self.notebook.add(self.analytics_frame, text="Analytics")
        self.notebook.add(self.profiles_frame, text="Profiles")
        self.notebook.pack(fill="both", expand=True)

        # Build tabs
        self.build_login_tab()
        self.build_dashboard_tab()
        self.build_map_tab()
        self.build_analytics_tab()
        self.build_profiles_tab()

        # disable tabs until login
        self.set_tabs_state('disabled')

        # bind tab change for map auto-open
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    # -----------------------
    # Login Tab (original system preserved)
    # -----------------------
    def build_login_tab(self):
        frm = self.login_frame
        for w in frm.winfo_children():
            w.destroy()

        wrapper = ttk.Frame(frm, padding=20)
        wrapper.pack(fill='both', expand=True)

        left = ttk.Frame(wrapper)
        left.pack(side='left', fill='both', expand=True, padx=(0,10))
        ttk.Label(left, text="Login", font=("Segoe UI", 12, "bold")).pack(anchor='w', pady=(0,10))
        ttk.Label(left, text="Username").pack(anchor='w')
        self.login_username = ttk.Entry(left)
        self.login_username.pack(anchor='w', fill='x', pady=(0,6))
        ttk.Label(left, text="Password").pack(anchor='w')
        self.login_password = ttk.Entry(left, show='*')
        self.login_password.pack(anchor='w', fill='x', pady=(0,8))
        ttk.Button(left, text="Login", command=self.perform_login).pack(anchor='w', pady=(6,6))

        right = ttk.Frame(wrapper)
        right.pack(side='left', fill='both', expand=True, padx=(10,0))
        ttk.Label(right, text="Sign up", font=("Segoe UI", 12, "bold")).pack(anchor='w', pady=(0,10))
        ttk.Label(right, text="Username").pack(anchor='w')
        self.signup_username = ttk.Entry(right)
        self.signup_username.pack(anchor='w', fill='x', pady=(0,6))
        ttk.Label(right, text="Email").pack(anchor='w')
        self.signup_email = ttk.Entry(right)
        self.signup_email.pack(anchor='w', fill='x', pady=(0,6))
        ttk.Label(right, text="Password").pack(anchor='w')
        self.signup_password = ttk.Entry(right, show='*')
        self.signup_password.pack(anchor='w', fill='x', pady=(0,6))
        ttk.Label(right, text="Select Role").pack(anchor='w')

        # Ensure roles list includes Administrator, Investor, Researcher
        role_names = roles_df['RoleName'].astype(str).tolist() if not roles_df.empty else ["Administrator","Investor","Researcher"]
        # ensure ordering: Administrator, Investor, Researcher
        ordered = []
        for r in ["Administrator", "Investor", "Researcher"]:
            if r in role_names and r not in ordered:
                ordered.append(r)
        for r in role_names:
            if r not in ordered:
                ordered.append(r)
        self.signup_role_var = tk.StringVar(value=ordered[0])
        self.signup_role_combo = ttk.Combobox(right, values=ordered, state='readonly', textvariable=self.signup_role_var)
        self.signup_role_combo.pack(anchor='w', fill='x', pady=(0,6))
        ttk.Button(right, text="Create account", command=self.perform_signup).pack(anchor='w', pady=(6,6))

    def perform_signup(self):
        username = self.signup_username.get().strip()
        email = self.signup_email.get().strip()
        password = self.signup_password.get().strip()
        role_name = self.signup_role_var.get().strip()

        if not username or not password or not role_name:
            messagebox.showwarning("Missing info", "Please provide username, password and select a role.")
            return

        users = load_users_df()
        if username in users['Username'].values:
            messagebox.showerror("Exists", "Username already exists. Pick another one.")
            return

        role_row = roles_df[roles_df['RoleName'] == role_name]
        if role_row.empty:
            # fallback to Researcher role
            role_row = roles_df[roles_df['RoleName'] == "Researcher"]
            if role_row.empty:
                role_id = 3
            else:
                role_id = int(role_row.iloc[0]['RoleID'])
        else:
            role_id = int(role_row.iloc[0]['RoleID'])

        new_id = 1 if users.shape[0] == 0 else int(users['UserID'].astype(int).max()) + 1
        hashed = hash_password(password)
        new_row = {'UserID': new_id, 'Username': username, 'PasswordHash': hashed, 'RoleID': role_id, 'Email': email}
        users = pd.concat([users, pd.DataFrame([new_row])], ignore_index=True)
        save_users_df(users)
        messagebox.showinfo("Account created", f"Account for '{username}' created. You can now login.")
        # clear fields
        self.signup_username.delete(0,'end')
        self.signup_password.delete(0,'end')
        self.signup_email.delete(0,'end')

    def perform_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        if not username or not password:
            messagebox.showwarning("Missing", "Please enter username and password.")
            return

        users = load_users_df()
        user_row = users[users['Username'] == username]
        if user_row.empty:
            messagebox.showerror("No user", "User not found. Please sign up first.")
            return
        user_row = user_row.iloc[0]
        if not verify_password(password, user_row['PasswordHash']):
            messagebox.showerror("Invalid", "Incorrect password.")
            return

        role_row = roles_df[roles_df['RoleID'] == int(user_row['RoleID'])]
        role_name = role_row.iloc[0]['RoleName'] if not role_row.empty else 'User'
        self.current_user = {
            'user_id': int(user_row['UserID']),
            'username': user_row['Username'],
            'role': role_name,
            'role_id': int(user_row['RoleID'])
        }
        self.user_label.config(text=f"Logged in as: {self.current_user['username']} ({self.current_user['role']})")
        messagebox.showinfo("Welcome", f"Welcome, {self.current_user['username']} ({self.current_user['role']})")
        self.set_tabs_state('normal')
        self.notebook.select(self.dashboard_frame)
        # refresh views
        self.refresh_dashboard()
        self.refresh_analytics()
        self.refresh_profiles()

    # -----------------------
    # Dashboard
    # -----------------------
    def build_dashboard_tab(self):
        frm = self.dashboard_frame
        for w in frm.winfo_children():
            w.destroy()
        header = ttk.Frame(frm, padding=8)
        header.pack(fill='x')
        ttk.Label(header, text="Dashboard Overview", font=("Segoe UI", 12, "bold")).pack(side='left')
        ttk.Button(header, text="Refresh", command=self.refresh_dashboard).pack(side='right')
        body = ttk.Frame(frm, padding=10)
        body.pack(fill='both', expand=True)
        self.metrics_text = ScrolledText(body, width=35, height=15, state='disabled')
        self.metrics_text.pack(side='left', padx=(0,10))
        chart_col = ttk.Frame(body)
        chart_col.pack(side='left', fill='both', expand=True)
        self.dashboard_fig = Figure(figsize=(6,4), dpi=100)
        self.dashboard_ax = self.dashboard_fig.add_subplot(111)
        self.dashboard_canvas = FigureCanvasTkAgg(self.dashboard_fig, master=chart_col)
        self.dashboard_canvas.get_tk_widget().pack(fill='both', expand=True)

    def refresh_dashboard(self):
        # summary metrics
        try:
            total_countries = countries_df.shape[0]
            total_minerals = minerals_df.shape[0]
            total_production = int(production_df['Production_tonnes'].fillna(0).sum())
            total_export = float(production_df['ExportValue_BillionUSD'].fillna(0).sum())
        except Exception:
            total_countries = total_minerals = total_production = total_export = 0

        self.metrics_text.config(state='normal')
        self.metrics_text.delete('1.0','end')
        self.metrics_text.insert('end', f"Countries: {total_countries}\n")
        self.metrics_text.insert('end', f"Minerals: {total_minerals}\n")
        self.metrics_text.insert('end', f"Total Production: {total_production:,} tonnes\n")
        self.metrics_text.insert('end', f"Total Export Value: ${total_export:.1f}B\n\n")
        self.metrics_text.insert('end', "Key Projects:\n")
        for _, row in countries_df.iterrows():
            self.metrics_text.insert('end', f" - {row.CountryName}: {row.KeyProjects}\n")
        self.metrics_text.config(state='disabled')

        # chart
        merged = production_df.merge(countries_df, on='CountryID', how='left').merge(minerals_df, on='MineralID', how='left')
        if merged.empty:
            self.dashboard_ax.clear()
            self.dashboard_ax.text(0.5,0.5,"No production data", ha='center')
        else:
            pivot = merged.pivot_table(index='CountryName', columns='MineralName', values='Production_tonnes', aggfunc='sum', fill_value=0)
            self.dashboard_ax.clear()
            pivot.plot(kind='bar', stacked=True, ax=self.dashboard_ax)
            self.dashboard_ax.set_ylabel("Production (tonnes)")
            self.dashboard_ax.set_title("Mineral Production by Country")
            self.dashboard_ax.legend(title='Mineral', bbox_to_anchor=(1.05,1), loc='upper left')
        self.dashboard_canvas.draw()

    # -----------------------
    # Map tab (UNCHANGED behavior: open map HTML silently; do not modify map generation)
    # -----------------------
    def build_map_tab(self):
        frm = self.map_frame
        for w in frm.winfo_children():
            w.destroy()
        ttk.Label(frm, text="🗺️ Interactive Map", font=("Segoe UI", 12, "bold")).pack(pady=10)
        ttk.Label(frm, text="This will open your map HTML in your default browser.").pack(pady=5)
        ttk.Button(frm, text="Open Map in Browser", command=self.render_map).pack(pady=8)
        ttk.Button(frm, text="🔙 Back to Dashboard", command=lambda: self.notebook.select(self.dashboard_frame)).pack(pady=6)

    def render_map(self):
        """
        Open MAP_HTML in the default browser. Behavior purposely unchanged:
        - If the file exists it will open silently.
        - If not found, show an error (so user can place the correct map file).
        Note: per instruction, do NOT change map generation logic.
        """
        if os.path.exists(MAP_HTML):
            try:
                webbrowser.open("file://" + os.path.abspath(MAP_HTML))
            except Exception as e:
                messagebox.showerror("Browser Error", f"Could not open map in browser.\n{e}")
        else:
            messagebox.showerror("Missing Map File", f"{os.path.basename(MAP_HTML)} not found in the app directory ({BASE_DIR}).\nPlace the file there or restore it and try again.")

    # -----------------------
    # Analytics tab (single matplotlib graph)
    # -----------------------
    def build_analytics_tab(self):
        frm = self.analytics_frame
        for w in frm.winfo_children():
            w.destroy()
        header = ttk.Frame(frm, padding=8)
        header.pack(fill='x')
        ttk.Label(header, text="Mineral Analytics", font=("Segoe UI", 12, "bold")).pack(side='left')
        body = ttk.Frame(frm, padding=10)
        body.pack(fill='both', expand=True)
        left = ttk.Frame(body, width=220)
        left.pack(side='left', fill='y', padx=(0,10))
        ttk.Label(left, text="Select Mineral").pack(anchor='w')
        self.mineral_listbox = tk.Listbox(left, height=8, exportselection=False)
        for m in minerals_df['MineralName'].tolist():
            self.mineral_listbox.insert('end', m)
        self.mineral_listbox.pack(fill='y')
        self.mineral_listbox.bind("<<ListboxSelect>>", lambda e: self.refresh_analytics())
        ttk.Button(left, text="Show Analysis", command=self.refresh_analytics).pack(pady=(8,0))
        chart_col = ttk.Frame(body)
        chart_col.pack(side='left', fill='both', expand=True)
        self.analytics_fig = Figure(figsize=(7,5), dpi=100)
        self.analytics_ax = self.analytics_fig.add_subplot(111)
        self.analytics_canvas = FigureCanvasTkAgg(self.analytics_fig, master=chart_col)
        toolbar = NavigationToolbar2Tk(self.analytics_canvas, chart_col)
        toolbar.update()
        self.analytics_canvas.get_tk_widget().pack(fill='both', expand=True)

    def refresh_analytics(self):
        sel = self.mineral_listbox.curselection()
        if not sel:
            self.analytics_ax.clear()
            self.analytics_ax.text(0.5, 0.5, "Select a mineral to show trends", ha='center')
            self.analytics_canvas.draw()
            return
        mineral = self.mineral_listbox.get(sel[0])
        df = production_df.merge(countries_df, on='CountryID', how='left').merge(minerals_df, on='MineralID', how='left')
        mineral_df = df[df['MineralName'] == mineral]
        self.analytics_ax.clear()
        if mineral_df.empty:
            self.analytics_ax.text(0.5,0.5,"No data", ha='center')
        else:
            for country in mineral_df['CountryName'].unique():
                country_data = mineral_df[mineral_df['CountryName'] == country].sort_values('Year')
                self.analytics_ax.plot(country_data['Year'], country_data['Production_tonnes'], marker='o', label=country)
            self.analytics_ax.set_title(f"Production Trends - {mineral}")
            self.analytics_ax.set_xlabel("Year")
            self.analytics_ax.set_ylabel("Production (tonnes)")
            self.analytics_ax.legend(fontsize='small')
        self.analytics_canvas.draw()

    
    # Profiles tab (centered)
    
    def build_profiles_tab(self):
        frm = self.profiles_frame
        for w in frm.winfo_children():
            w.destroy()
        ttk.Label(frm, text="🌍 Country Profiles", font=("Segoe UI", 12, "bold")).pack(pady=10)
        frame_center = ttk.Frame(frm)
        frame_center.pack(expand=True)
        self.country_listbox = tk.Listbox(frame_center, height=10)
        for c in countries_df['CountryName'].tolist():
            self.country_listbox.insert('end', c)
        self.country_listbox.grid(row=0, column=0, padx=15, pady=10)
        ttk.Button(frame_center, text="Show Profile", command=self.refresh_profiles).grid(row=1, column=0, pady=10)
        self.profile_info = ScrolledText(frame_center, height=20, width=60, state='disabled', font=("Segoe UI", 10))
        self.profile_info.grid(row=0, column=1, rowspan=2, padx=15, pady=10)

    def refresh_profiles(self):
        sel = self.country_listbox.curselection()
        if not sel:
            messagebox.showinfo("No country selected", "Please select a country from the list.")
            return
        country = self.country_listbox.get(sel[0])
        row = countries_df[countries_df['CountryName'] == country]
        if row.empty:
            messagebox.showerror("Not found", "Country not found in countries.csv")
            return
        row = row.iloc[0]
        cid = row.get('CountryID', None)
        country_production = production_df[production_df['CountryID'] == cid].merge(minerals_df, on='MineralID', how='left') if cid is not None else pd.DataFrame()
        self.profile_info.config(state='normal')
        self.profile_info.delete('1.0','end')
        self.profile_info.insert('end', f"🏳️  {row['CountryName']}\n\n")
        self.profile_info.insert('end', f"💰  GDP: {row.get('GDP_BillionUSD','N/A')} B USD\n")
        self.profile_info.insert('end', f"⛏️  Mining Revenue: {row.get('MiningRevenue_BillionUSD','N/A')} B USD\n\n")
        self.profile_info.insert('end', f"📈  Key Project: {row.get('KeyProjects','N/A')}\n\n")
        self.profile_info.insert('end', "Production details:\n")
        if not country_production.empty:
            for _, r in country_production.iterrows():
                prod = int(r['Production_tonnes']) if pd.notna(r.get('Production_tonnes')) else 'N/A'
                self.profile_info.insert('end', f" - {r.get('MineralName','Unknown')}: {prod:,} tonnes\n")
        else:
            self.profile_info.insert('end', "No production data.\n")
        self.profile_info.tag_configure("center", justify="center")
        self.profile_info.tag_add("center", "1.0", "end")
        self.profile_info.config(state='disabled')

    
    # Utility / login helpers
    
    def set_tabs_state(self, state='normal'):
        for i in range(1, self.notebook.index('end')):
            try:
                self.notebook.tab(i, state=state)
            except tk.TclError:
                pass

    def on_tab_change(self, event):
        selected_tab = event.widget.tab(event.widget.select(), "text")
        if selected_tab.lower() == "map":
            # silently open map when tab selected
            self.render_map()


# Run application

if __name__ == "__main__":
    app = MineralsApp()
    app.mainloop()
