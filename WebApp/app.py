import os
import json
import sqlite3
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash

# Flask app configuration
app = Flask(__name__)
app.secret_key = "smartids_super_secret_key"

COLUMNS_41 = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']
NUMERIC_COLS = [c for c in COLUMNS_41 if c not in CATEGORICAL_COLS]

# Path configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(os.path.dirname(BASE_DIR), "DataMining")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# 1. Database Initialization
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            total_connections INTEGER NOT NULL,
            attack_connections INTEGER NOT NULL,
            mode TEXT NOT NULL,
            created_at TEXT NOT NULL,
            class_counts TEXT,
            sample_rows TEXT,
            model_used TEXT,
            avg_confidence REAL,
            execution_time REAL,
            recommendations TEXT
        )
    ''')
    # Dynamic schema migration
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(history)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'model_used' not in columns:
        conn.execute("ALTER TABLE history ADD COLUMN model_used TEXT")
    if 'avg_confidence' not in columns:
        conn.execute("ALTER TABLE history ADD COLUMN avg_confidence REAL")
    if 'execution_time' not in columns:
        conn.execute("ALTER TABLE history ADD COLUMN execution_time REAL")
    if 'recommendations' not in columns:
        conn.execute("ALTER TABLE history ADD COLUMN recommendations TEXT")
    conn.commit()
    conn.close()

init_db()

# 2. Loading Model & Preprocessors
# Global caches
model_binary = None
model_multiclass = None
scaler = None
encoder = None
feature_info = None

def load_models():
    global model_binary, model_multiclass, scaler, encoder, feature_info
    global MODEL_DIR
    try:
        # Auto-detect if models are in 'models' subdirectory
        binary_path = os.path.join(MODEL_DIR, "model_binary.pkl")
        if not os.path.exists(binary_path):
            subfolder_path = os.path.join(MODEL_DIR, "models")
            if os.path.exists(os.path.join(subfolder_path, "model_binary.pkl")):
                MODEL_DIR = subfolder_path
                print(f"Dynamic redirection: loading models from subfolder '{MODEL_DIR}'")
        
        model_binary = joblib.load(os.path.join(MODEL_DIR, "model_binary.pkl"))
        model_multiclass = joblib.load(os.path.join(MODEL_DIR, "model_multiclass.pkl"))
        scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
        encoder = joblib.load(os.path.join(MODEL_DIR, "encoder.pkl"))
        try:
            feature_info = joblib.load(os.path.join(MODEL_DIR, "feature_columns.pkl"))
        except Exception as e:
            feature_info = None
            print(f"Note: feature_columns.pkl fallback: {e}")
        print(f"Loaded binary model type: {model_binary.__class__.__name__}")
        print(f"Loaded multiclass model type: {model_multiclass.__class__.__name__}")
        print("All models and preprocessors loaded successfully!")
        return True
    except Exception as e:
        print(f"Error loading models: {e}")
        return False

# 3. PDF Generator Function
from fpdf import FPDF

class SecurityReportPDF(FPDF):
    def __init__(self, filename, date_str, mode, total, normal, attacks, rate, model_used, avg_confidence, execution_time, recommendations):
        super().__init__()
        self.filename = filename
        self.date_str = date_str
        self.mode = "Multiclasse (5 Categories)" if mode == "multiclass" else "Binaire (Normal / Attaque)"
        self.total = total
        self.normal = normal
        self.attacks = attacks
        self.rate = rate
        self.model_used = model_used
        self.avg_confidence = avg_confidence
        self.execution_time = execution_time
        self.recommendations = recommendations

    def header(self):
        # Draw background and title banner
        self.set_fill_color(241, 245, 249) # light slate gray background
        self.rect(0, 0, 210, 40, 'F')
        
        # Draw Vector Shield Logo
        self.set_draw_color(2, 132, 199) # primary blue
        self.set_line_width(1.0)
        
        # Shield lines
        self.line(18, 12, 25, 9)   # Top left
        self.line(25, 9, 32, 12)   # Top right
        self.line(18, 12, 18, 22)  # Left edge
        self.line(32, 12, 32, 22)  # Right edge
        self.line(18, 22, 25, 29)  # Bottom left to point
        self.line(32, 22, 25, 29)  # Bottom right to point
        
        # Draw checkmark inside shield
        self.line(22, 20, 24, 22)
        self.line(24, 22, 28, 17)
        
        # Brand Text
        self.set_text_color(2, 132, 199) # primary blue
        self.set_font('helvetica', 'B', 20)
        self.text(42, 21, 'SmartIDS')
        
        self.set_text_color(100, 116, 139) # slate gray text
        self.set_font('helvetica', 'B', 9)
        self.text(42, 27, 'INTRUSION DETECTION SYSTEM')
        
        # Right aligned Date
        self.set_font('helvetica', 'I', 9)
        self.text(145, 23, f'Genere le {self.date_str}')
        self.ln(35)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} | SmartIDS Intrusion Detection System', align='C')

    def build_body(self, sample_rows):
        self.set_text_color(15, 23, 42) # slate-900
        self.set_font('helvetica', 'B', 14)
        self.cell(0, 10, '1. Resume de l\'analyse')
        self.ln(12)
        
        # Meta info table
        self.set_font('helvetica', '', 10)
        self.cell(55, 8, 'Nom du fichier :', 1)
        self.cell(0, 8, f' {self.filename}', 1)
        self.ln(8)
        self.cell(55, 8, 'Mode de classification :', 1)
        self.cell(0, 8, f' {self.mode}', 1)
        self.ln(8)
        self.cell(55, 8, 'Modele Machine Learning :', 1)
        self.cell(0, 8, f' {self.model_used}', 1)
        self.ln(8)
        self.cell(55, 8, 'Lignes analysees :', 1)
        self.cell(0, 8, f' {self.total}', 1)
        self.ln(8)
        self.cell(55, 8, 'Connexions normales :', 1)
        self.cell(0, 8, f' {self.normal}', 1)
        self.ln(8)
        self.cell(55, 8, 'Menaces/Attaques detectees :', 1)
        self.cell(0, 8, f' {self.attacks}', 1)
        self.ln(8)
        self.cell(55, 8, 'Taux de menace global :', 1)
        self.cell(0, 8, f' {self.rate:.2f}%', 1)
        self.ln(8)
        self.cell(55, 8, 'Confiance moyenne :', 1)
        self.cell(0, 8, f' {self.avg_confidence:.2f}%', 1)
        self.ln(8)
        self.cell(55, 8, 'Temps de prediction :', 1)
        self.cell(0, 8, f' {self.execution_time:.4f} sec', 1)
        self.ln(8)
        
        self.ln(8)
        
        # Section 2: Threat evaluation
        self.set_font('helvetica', 'B', 14)
        self.cell(0, 10, '2. Evaluation de la Menace')
        self.ln(12)
        
        self.set_font('helvetica', '', 10)
        if self.attacks > 0:
            status_text = f"ATTENTION: Le systeme a detecte {self.attacks} anomalies reseau suspectes ({self.rate:.2f}% du total) dans le fichier {self.filename}. Des paquets hostiles ont ete bloques pour proteger l'infrastructure."
            self.set_text_color(185, 28, 28) # Red text
        else:
            status_text = "SUCCES: Aucun comportement hostile n'a ete detecte lors de cette analyse. Le trafic reseau est considere comme normal et securise."
            self.set_text_color(22, 163, 74) # Green text
            
        self.multi_cell(0, 6, status_text, border=1)
        self.set_text_color(15, 23, 42) # reset
        
        self.ln(8)
        
        # Section 3: Recommendations
        if self.attacks > 0 and self.recommendations:
            self.set_font('helvetica', 'B', 14)
            self.cell(0, 10, '3. Actions correctives & Recommandations')
            self.ln(12)
            self.set_font('helvetica', '', 10)
            for rec in self.recommendations:
                self.multi_cell(0, 6, f"- {rec}")
                self.ln(2)
            self.ln(6)
            
        # Section 4: Samples table
        sec_num = '4' if (self.attacks > 0 and self.recommendations) else '3'
        self.set_font('helvetica', 'B', 14)
        self.cell(0, 10, f'{sec_num}. Echantillon d\'anomalies et flux reseau')
        self.ln(12)
        
        # Table headers
        self.set_font('helvetica', 'B', 9)
        self.set_fill_color(220, 220, 220)
        self.cell(20, 8, 'Idx', 1, 0, 'C', fill=True)
        self.cell(25, 8, 'Protocole', 1, 0, 'C', fill=True)
        self.cell(30, 8, 'Service', 1, 0, 'C', fill=True)
        self.cell(20, 8, 'Flag', 1, 0, 'C', fill=True)
        self.cell(25, 8, 'Src Bytes', 1, 0, 'C', fill=True)
        self.cell(25, 8, 'Dst Bytes', 1, 0, 'C', fill=True)
        self.cell(45, 8, 'Resultat', 1, 0, 'C', fill=True)
        self.ln(8)
        
        # Rows
        self.set_font('helvetica', '', 9)
        for row in sample_rows:
            self.cell(20, 7, f"#{row['index']}", 1, 0, 'C')
            self.cell(25, 7, f"{row['protocol']}", 1, 0, 'C')
            self.cell(30, 7, f"{row['service']}", 1, 0, 'C')
            self.cell(20, 7, f"{row['flag']}", 1, 0, 'C')
            self.cell(25, 7, f"{row['src_bytes']}", 1, 0, 'C')
            self.cell(25, 7, f"{row['dst_bytes']}", 1, 0, 'C')
            
            # Text color depending on normal vs attack
            pred = row['prediction']
            if pred.lower() == 'normal':
                self.set_text_color(0, 150, 50)
            else:
                self.set_text_color(200, 0, 50)
            self.cell(45, 7, f"{pred.upper()}", 1, 0, 'C')
            self.set_text_color(15, 23, 42) # reset
            self.ln(7)

def generate_pdf_report(history_id):
    conn = get_db_connection()
    row = conn.execute('SELECT * FROM history WHERE id = ?', (history_id,)).fetchone()
    conn.close()
    
    if not row:
        return None
        
    filename = row['filename']
    date_str = row['created_at']
    mode = row['mode']
    total = row['total_connections']
    attacks = row['attack_connections']
    normal = row['total_connections'] - row['attack_connections']
    rate = (attacks / total * 100) if total > 0 else 0
    sample_rows = json.loads(row['sample_rows'])
    
    # Load migrated columns safely
    try:
        model_used = row['model_used'] if row['model_used'] else "Gradient Boosting (Binaire) / Gradient Boosting (Multiclasse)"
    except:
        model_used = "Gradient Boosting (Binaire) / Gradient Boosting (Multiclasse)"
        
    try:
        avg_confidence = row['avg_confidence'] if row['avg_confidence'] is not None else 100.0
    except:
        avg_confidence = 100.0
        
    try:
        execution_time = row['execution_time'] if row['execution_time'] is not None else 0.0
    except:
        execution_time = 0.0
        
    try:
        recommendations = json.loads(row['recommendations']) if row['recommendations'] else []
    except:
        recommendations = []
    
    pdf = SecurityReportPDF(filename, date_str, mode, total, normal, attacks, rate, model_used, avg_confidence, execution_time, recommendations)
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.build_body(sample_rows[:15]) # limit to 15 in the PDF
    
    pdf_filename = f"report_{history_id}.pdf"
    pdf_filepath = os.path.join(REPORT_FOLDER, pdf_filename)
    pdf.output(pdf_filepath)
    return pdf_filename

# 4. Routes
@app.route('/')
def index():
    if model_binary is None:
        load_models()
        
    binary_model_name = "Gradient Boosting" if "GradientBoosting" in str(model_binary.__class__.__name__) else ("Decision Tree" if "DecisionTree" in str(model_binary.__class__.__name__) else str(model_binary.__class__.__name__)) if model_binary is not None else "Non chargé"
    multiclass_model_name = "Gradient Boosting" if "GradientBoosting" in str(model_multiclass.__class__.__name__) else ("Decision Tree" if "DecisionTree" in str(model_multiclass.__class__.__name__) else str(model_multiclass.__class__.__name__)) if model_multiclass is not None else "Non chargé"

    # Load dashboard stats
    conn = get_db_connection()
    rows = conn.execute('SELECT * FROM history').fetchall()
    
    total_files = len(rows)
    total_connections = 0
    total_attacks = 0
    threat_percentages = []
    
    # Timeline data for chart
    timeline_labels = []
    timeline_data = []
    
    # Multiclass global distribution
    global_classes = {'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0}
    
    # Chronological order of last 7 runs
    for r in list(rows)[-7:]:
        rate = (r['attack_connections'] / r['total_connections'] * 100) if r['total_connections'] > 0 else 0
        try:
            dt = datetime.strptime(r['created_at'], "%Y-%m-%d %H:%M:%S")
            label = dt.strftime("%d/%m %H:%M")
        except:
            label = r['created_at'].split()[0]
        timeline_labels.append(label)
        timeline_data.append(round(rate, 1))
        
    for r in rows:
        total_connections += r['total_connections']
        total_attacks += r['attack_connections']
        if r['total_connections'] > 0:
            threat_percentages.append(r['attack_connections'] / r['total_connections'] * 100)
            
        # Accumulate multiclass stats
        if r['class_counts']:
            try:
                counts = json.loads(r['class_counts'])
                for k, v in counts.items():
                    if k in global_classes:
                        global_classes[k] += v
            except:
                pass
            
    avg_threat_rate = np.mean(threat_percentages) if threat_percentages else 0.0
    
    stats = {
        'total_files': total_files,
        'total_connections': total_connections,
        'total_attacks': total_attacks,
        'avg_threat_rate': avg_threat_rate
    }
    
    # Fetch 5 most recent scans
    recent_scans = conn.execute('SELECT * FROM history ORDER BY id DESC LIMIT 5').fetchall()
    conn.close()
    
    # Load model performance stats from CSVs
    models_bin_performance = []
    models_multi_performance = []
    
    try:
        csv_bin_path = os.path.join(MODEL_DIR, "results_binary.csv")
        if not os.path.exists(csv_bin_path):
            csv_bin_path = os.path.join(os.path.dirname(MODEL_DIR), "outputs", "results_binary.csv")
        if not os.path.exists(csv_bin_path):
            csv_bin_path = os.path.join(MODEL_DIR, "outputs", "results_binary.csv")
            
        if os.path.exists(csv_bin_path):
            df_bin = pd.read_csv(csv_bin_path)
            models_bin_performance = df_bin.to_dict(orient='records')
    except Exception as e:
        print(f"Error loading results_binary.csv: {e}")
        
    try:
        csv_multi_path = os.path.join(MODEL_DIR, "results_multiclass.csv")
        if not os.path.exists(csv_multi_path):
            csv_multi_path = os.path.join(os.path.dirname(MODEL_DIR), "outputs", "results_multiclass.csv")
        if not os.path.exists(csv_multi_path):
            csv_multi_path = os.path.join(MODEL_DIR, "outputs", "results_multiclass.csv")
            
        if os.path.exists(csv_multi_path):
            df_multi = pd.read_csv(csv_multi_path)
            models_multi_performance = df_multi.to_dict(orient='records')
    except Exception as e:
        print(f"Error loading results_multiclass.csv: {e}")
    
    return render_template('index.html', 
                           stats=stats, 
                           timeline_labels=timeline_labels,
                           timeline_data=timeline_data,
                           global_classes=global_classes,
                           recent_scans=recent_scans,
                           models_bin_performance=models_bin_performance,
                           models_multi_performance=models_multi_performance,
                           binary_model_name=binary_model_name,
                           multiclass_model_name=multiclass_model_name)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    # Make sure models are loaded
    if model_binary is None:
        load_models()
        
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("Aucun fichier trouve")
            return redirect(request.url)
            
        file = request.files['file']
        mode = request.form.get('mode', 'binary')
        
        if file.filename == '':
            flash("Aucun fichier selectionne")
            return redirect(request.url)
            
        if file:
            filename = file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # Load CSV without headers
                # We expect standard KDD format (43 columns or 41 columns)
                df = pd.read_csv(filepath, header=None)
                
                # If df has 43 columns, slice to 41 features
                if df.shape[1] == 43:
                    df_features = df.iloc[:, :41]
                elif df.shape[1] == 41:
                    df_features = df
                else:
                    flash(f"Format de fichier invalide. Attendu 41 ou 43 colonnes, recu {df.shape[1]} colonnes.")
                    return redirect(request.url)
                
                # Assign standard feature names
                df_features.columns = COLUMNS_41
                
                # Preprocess
                X_num_df = df_features[NUMERIC_COLS]
                encoded_cat = encoder.transform(df_features[CATEGORICAL_COLS])
                encoded_cat_df = pd.DataFrame(
                    encoded_cat,
                    columns=encoder.get_feature_names_out(CATEGORICAL_COLS),
                    index=df_features.index
                )
                X_num_scaled = pd.DataFrame(
                    scaler.transform(X_num_df),
                    columns=NUMERIC_COLS,
                    index=df_features.index
                )
                X = pd.concat([X_num_scaled, encoded_cat_df], axis=1)
                
                # Predictions
                import time
                start_time = time.time()
                
                # 1. Binary prediction
                preds_bin = model_binary.predict(X)
                numeric_preds = []
                for p in preds_bin:
                    if isinstance(p, str):
                        numeric_preds.append(1 if p.lower() == 'attack' else 0)
                    else:
                        numeric_preds.append(int(p))
                
                total_connections = len(numeric_preds)
                attack_connections = int(sum(numeric_preds))
                
                # 2. Pipeline prediction: call multiclass only if attack detected
                preds_multi = []
                confidences = []
                sample_rows = []
                has_proba_bin = hasattr(model_binary, "predict_proba")
                has_proba_multi = hasattr(model_multiclass, "predict_proba")
                
                if has_proba_bin:
                    proba_bin_all = model_binary.predict_proba(X)
                
                attack_indices = [i for i, val in enumerate(numeric_preds) if val == 1]
                if attack_indices:
                    X_attacks = X.iloc[attack_indices]
                    preds_multi_attacks = model_multiclass.predict(X_attacks)
                    if has_proba_multi:
                        proba_multi_attacks = model_multiclass.predict_proba(X_attacks)
                        classes_multi = list(model_multiclass.classes_)
                
                attack_ptr = 0
                for idx, is_att in enumerate(numeric_preds):
                    if is_att == 1:
                        p_multi = str(preds_multi_attacks[attack_ptr])
                        if p_multi.lower() == 'normal':
                            p_multi = 'DoS' # Fallback
                        preds_multi.append(p_multi)
                        
                        conf = 100.0
                        if has_proba_multi:
                            try:
                                c_idx = classes_multi.index(p_multi)
                                conf = float(proba_multi_attacks[attack_ptr][c_idx] * 100)
                            except:
                                conf = float(np.max(proba_multi_attacks[attack_ptr]) * 100)
                        elif has_proba_bin:
                            conf = float(proba_bin_all[idx][1] * 100)
                        confidences.append(conf)
                        attack_ptr += 1
                    else:
                        preds_multi.append("Normal")
                        conf = 100.0
                        if has_proba_bin:
                            conf = float(proba_bin_all[idx][0] * 100)
                        confidences.append(conf)
                        
                execution_time = time.time() - start_time
                avg_confidence = float(np.mean(confidences)) if confidences else 100.0
                
                # Assign labels depending on request mode
                if mode == 'binary':
                    predictions_labels = ['Attack' if p == 1 else 'Normal' for p in numeric_preds]
                else:
                    predictions_labels = preds_multi
                
                # Compute global multi-class distribution counts
                unique_labels, counts = np.unique(preds_multi, return_counts=True)
                class_counts = {str(k): int(v) for k, v in zip(unique_labels, counts)}
                
                # Recommendations mapping
                detected_classes = set(preds_multi)
                detected_attacks = [c for c in detected_classes if c.lower() != 'normal']
                recommendations_map = {
                    'DoS': [
                        "Bloquer l'adresse IP source suspecte au niveau du pare-feu.",
                        "Inspecter les ports cibles pour détecter une saturation de bande passante.",
                        "Activer les règles de limitation de débit (Rate Limiting).",
                        "Surveiller la charge processeur et la mémoire des serveurs impactés."
                    ],
                    'Probe': [
                        "Identifier et consigner l'adresse IP effectuant les scans de ports.",
                        "Fermer les ports inutilisés identifiés dans l'analyse.",
                        "Activer les règles IDS de rejet des scans de type Ping/SYN.",
                        "Activer la protection contre le balayage de ports (port-scan blocker)."
                    ],
                    'R2L': [
                        "Forcer le renouvellement des mots de passe des comptes ciblés.",
                        "Activer et exiger l'authentification multifacteur (MFA).",
                        "Restreindre l'accès à distance aux adresses IP explicitement autorisées.",
                        "Vérifier les connexions SSH/FTP actives et les clés d'accès."
                    ],
                    'U2R': [
                        "Révoquer immédiatement les privilèges administrateur des comptes suspects.",
                        "Appliquer les derniers correctifs de sécurité système et noyau.",
                        "Auditer les journaux d'exécution (`auditd`/`syslog`) à la recherche de failles d'escalade.",
                        "Lancer un scan d'intégrité complet des fichiers système."
                    ]
                }
                recs = []
                for att in detected_attacks:
                    recs.extend(recommendations_map.get(att, []))
                if not recs:
                    recs = ["Trafic réseau sain. Aucune action requise."]
                deduped_recs = []
                for r in recs:
                    if r not in deduped_recs:
                        deduped_recs.append(r)
                        
                model_used_binary = str(model_binary.__class__.__name__)
                model_used_multi = str(model_multiclass.__class__.__name__)
                model_used = f"{model_used_binary} (Binaire) / {model_used_multi} (Multiclasse)"
                
                # Create sample rows for display
                limit = min(10, total_connections)
                for idx in range(limit):
                    sample_rows.append({
                        'index': idx + 1,
                        'protocol': str(df_features.iloc[idx]['protocol_type']),
                        'service': str(df_features.iloc[idx]['service']),
                        'flag': str(df_features.iloc[idx]['flag']),
                        'src_bytes': int(df_features.iloc[idx]['src_bytes']),
                        'dst_bytes': int(df_features.iloc[idx]['dst_bytes']),
                        'prediction': predictions_labels[idx]
                    })
                
                # Save to history db with migrated schema
                created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO history (
                        filename, total_connections, attack_connections, mode, created_at, 
                        class_counts, sample_rows, model_used, avg_confidence, execution_time, recommendations
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    filename, total_connections, attack_connections, mode, created_at, 
                    json.dumps(class_counts), json.dumps(sample_rows), model_used, 
                    avg_confidence, execution_time, json.dumps(deduped_recs)
                ))
                history_id = cursor.lastrowid
                conn.commit()
                conn.close()
                
                # Clean up uploaded file
                if os.path.exists(filepath):
                    os.remove(filepath)
                
                return redirect(url_for('result_details', history_id=history_id))
                
            except Exception as e:
                import traceback
                traceback.print_exc()
                # Cleanup if error
                if os.path.exists(filepath):
                    os.remove(filepath)
                flash(f"Erreur lors de l'analyse : {e}")
                return redirect(request.url)
                
    return render_template('upload.html')

@app.route('/result/<int:history_id>')
def result_details(history_id):
    conn = get_db_connection()
    row = conn.execute('SELECT * FROM history WHERE id = ?', (history_id,)).fetchone()
    conn.close()
    
    if not row:
        flash("Resultat introuvable")
        return redirect(url_for('index'))
        
    total_connections = row['total_connections']
    attack_connections = row['attack_connections']
    normal_connections = total_connections - attack_connections
    threat_percentage = (attack_connections / total_connections * 100) if total_connections > 0 else 0
    
    class_counts = json.loads(row['class_counts']) if row['class_counts'] else None
    sample_rows = json.loads(row['sample_rows'])
    
    return render_template('result.html', 
                           history_id=history_id,
                           filename=row['filename'],
                           mode=row['mode'],
                           total_connections=total_connections,
                           attack_connections=attack_connections,
                           normal_connections=normal_connections,
                           threat_percentage=threat_percentage,
                           class_counts=class_counts,
                           sample_rows=sample_rows)

@app.route('/history')
def history():
    conn = get_db_connection()
    rows = conn.execute('SELECT * FROM history ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('history.html', history_entries=rows)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/download_report/<int:history_id>')
def download_report(history_id):
    pdf_filename = f"report_{history_id}.pdf"
    pdf_filepath = os.path.join(REPORT_FOLDER, pdf_filename)
    
    # Generate report if not exists
    if not os.path.exists(pdf_filepath):
        res = generate_pdf_report(history_id)
        if not res:
            flash("Impossible de generer le rapport")
            return redirect(url_for('history'))
            
    return send_from_directory(REPORT_FOLDER, pdf_filename, as_attachment=True)

@app.route('/delete_entry/<int:entry_id>')
def delete_entry(entry_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM history WHERE id = ?', (entry_id,))
    conn.commit()
    conn.close()
    
    # Clean up associated report file if exists
    pdf_filepath = os.path.join(REPORT_FOLDER, f"report_{entry_id}.pdf")
    if os.path.exists(pdf_filepath):
        os.remove(pdf_filepath)
        
    flash("Rapport supprime de l'historique.")
    return redirect(url_for('history'))

@app.route('/clear_history', methods=['POST'])
def clear_history():
    conn = get_db_connection()
    conn.execute('DELETE FROM history')
    conn.commit()
    conn.close()
    
    # Clean all pdfs in report folder
    for filename in os.listdir(REPORT_FOLDER):
        filepath = os.path.join(REPORT_FOLDER, filename)
        if os.path.isfile(filepath) and filename.endswith('.pdf'):
            os.remove(filepath)
            
    flash("Historique complet supprime.")
    return redirect(url_for('history'))
@app.route('/predict_single', methods=['GET', 'POST'])
def predict_single():
    if model_binary is None:
        load_models()
        
    result = None
    form_data = {}
    
    # Pre-populate defaults for the form display
    default_vals = {
        'duration': 0,
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'src_bytes': 0,
        'dst_bytes': 0,
        'count': 1,
        'srv_count': 1,
        'same_srv_rate': 1.0,
        'dst_host_srv_count': 1
    }
    
    if request.method == 'POST':
        try:
            # Extract features from form
            form_data = {
                'duration': int(request.form.get('duration', default_vals['duration'])),
                'protocol_type': str(request.form.get('protocol_type', default_vals['protocol_type'])),
                'service': str(request.form.get('service', default_vals['service'])),
                'flag': str(request.form.get('flag', default_vals['flag'])),
                'src_bytes': int(request.form.get('src_bytes', default_vals['src_bytes'])),
                'dst_bytes': int(request.form.get('dst_bytes', default_vals['dst_bytes'])),
                'count': int(request.form.get('count', default_vals['count'])),
                'srv_count': int(request.form.get('srv_count', default_vals['srv_count'])),
                'same_srv_rate': float(request.form.get('same_srv_rate', default_vals['same_srv_rate'])),
                'dst_host_srv_count': int(request.form.get('dst_host_srv_count', default_vals['dst_host_srv_count']))
            }
            
            # Construct full 41-feature dictionary
            full_record = {}
            for col in COLUMNS_41:
                if col in form_data:
                    full_record[col] = form_data[col]
                else:
                    # sensical defaults for the rest
                    if col in ['land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 
                               'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 
                               'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
                               'num_outbound_cmds', 'is_host_login', 'is_guest_login']:
                        full_record[col] = 0
                    elif col in ['serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 
                                 'diff_srv_rate', 'srv_diff_host_rate']:
                        full_record[col] = 0.0
                    elif col in ['dst_host_count']:
                        full_record[col] = 100
                    elif col in ['dst_host_same_srv_rate']:
                        full_record[col] = 0.5
                    elif col in ['dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
                                 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 
                                 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
                                 'dst_host_srv_rerror_rate']:
                        full_record[col] = 0.0
                    else:
                        full_record[col] = 0
            
            # Create a 1-row DataFrame matching the expected format
            df_single = pd.DataFrame([full_record])
            
            # Preprocess
            X_num_df = df_single[NUMERIC_COLS]
            encoded_cat = encoder.transform(df_single[CATEGORICAL_COLS])
            encoded_cat_df = pd.DataFrame(
                encoded_cat,
                columns=encoder.get_feature_names_out(CATEGORICAL_COLS),
                index=df_single.index
            )
            X_num_scaled = pd.DataFrame(
                scaler.transform(X_num_df),
                columns=NUMERIC_COLS,
                index=df_single.index
            )
            X = pd.concat([X_num_scaled, encoded_cat_df], axis=1)
            
            # Predictions
            import time
            start_time = time.time()
            
            # 1. Binaire prediction
            pred_bin = model_binary.predict(X)[0]
            if isinstance(pred_bin, str):
                is_attack = (pred_bin.lower() == 'attack')
            else:
                is_attack = (int(pred_bin) == 1)
            
            # 2. Pipeline & Confidence
            confidence = 100.0
            if is_attack:
                pred_multi = model_multiclass.predict(X)[0]
                if str(pred_multi).lower() == 'normal':
                    pred_multi = 'DoS'
                
                if hasattr(model_multiclass, "predict_proba"):
                    proba_multi = model_multiclass.predict_proba(X)[0]
                    classes = model_multiclass.classes_
                    try:
                        class_idx = list(classes).index(pred_multi)
                        confidence = float(proba_multi[class_idx] * 100)
                    except:
                        confidence = float(np.max(proba_multi) * 100)
                elif hasattr(model_binary, "predict_proba"):
                    proba_bin = model_binary.predict_proba(X)[0]
                    confidence = float(proba_bin[1] * 100)
            else:
                pred_multi = 'Normal'
                if hasattr(model_binary, "predict_proba"):
                    proba_bin = model_binary.predict_proba(X)[0]
                    confidence = float(proba_bin[0] * 100)
            
            prediction_time = time.time() - start_time
            
            # 3. Risk Level
            if not is_attack:
                risk_level = "Safe"
                risk_color = "success"
            else:
                if str(pred_multi) in ['DoS', 'U2R']:
                    risk_level = "Critical"
                    risk_color = "danger"
                else:
                    risk_level = "Medium"
                    risk_color = "warning"
            
            # 4. Recommendations mapping
            recommendations_map = {
                'Normal': ["Trafic réseau sain. Aucune action requise."],
                'DoS': [
                    "Bloquer l'adresse IP source suspecte au niveau du pare-feu.",
                    "Inspecter les ports cibles pour détecter une saturation de bande passante.",
                    "Activer les règles de limitation de débit (Rate Limiting).",
                    "Surveiller la charge processeur et la mémoire des serveurs impactés."
                ],
                'Probe': [
                    "Identifier et consigner l'adresse IP effectuant les scans de ports.",
                    "Fermer les ports inutilisés identifiés dans l'analyse.",
                    "Activer les règles IDS de rejet des scans de type Ping/SYN.",
                    "Activer la protection contre le balayage de ports (port-scan blocker)."
                ],
                'R2L': [
                    "Forcer le renouvellement des mots de passe des comptes ciblés.",
                    "Activer et exiger l'authentification multifacteur (MFA).",
                    "Restreindre l'accès à distance aux adresses IP explicitement autorisées.",
                    "Vérifier les connexions SSH/FTP actives et les clés d'accès."
                ],
                'U2R': [
                    "Révoquer immédiatement les privilèges administrateur des comptes suspects.",
                    "Appliquer les derniers correctifs de sécurité système et noyau.",
                    "Auditer les journaux d'exécution (`auditd`/`syslog`) à la recherche de failles d'escalade.",
                    "Lancer un scan d'intégrité complet des fichiers système."
                ]
            }
            recommendations = recommendations_map.get(pred_multi, ["Inspecter les logs de connexion suspectes."])
            
            result = {
                'prediction_binary': 'Attack' if is_attack else 'Normal',
                'prediction_multiclass': str(pred_multi),
                'status': 'safe' if not is_attack else 'danger',
                'confidence': round(confidence, 2),
                'prediction_time': round(prediction_time, 4),
                'risk_level': risk_level,
                'risk_color': risk_color,
                'recommendations': recommendations
            }
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            flash(f"Erreur de traitement du formulaire : {e}")
            
    # Extraire dynamiquement toutes les options supportees par le modele depuis l'encodeur One-Hot
    protocols = list(encoder.categories_[0]) if encoder is not None else ['tcp', 'udp', 'icmp']
    services = list(encoder.categories_[1]) if encoder is not None else ['http', 'private', 'smtp', 'domain', 'ftp', 'ftp_data', 'other']
    flags = list(encoder.categories_[2]) if encoder is not None else ['SF', 'S0', 'REJ', 'RSTR']
            
    return render_template('predict_single.html', 
                           result=result, 
                           form_data=form_data, 
                           defaults=default_vals,
                           protocols=protocols,
                           services=services,
                           flags=flags)


if __name__ == '__main__':
    # Initial load of models
    load_models()
    app.run(debug=True, use_reloader=False)
