# BIHSO auditd anomaly detection

Projekt studencki: wykrywanie anomalii w logach auditd systemu Linux.

Porownywane metody:
- detekcja regulowa,
- Isolation Forest,
- Local Outlier Factor.

Najwazniejsze pliki:
- `data/raw/auditd_sample.log` - przykladowe logi auditd,
- `data/labels.csv` - etykiety 0/1 dla zgrupowanych zdarzen,
- `generowanie_logow.py` - generator odtwarzajacy `auditd_sample.log` i `labels.csv`,
- `src/audit_parser.py` - parser pojedynczych linii i grupowanie po `audit_id`,
- `src/rules.py` - reguly detekcji,
- `src/features.py` - cechy dla modeli ML,
- `src/ml_detector.py` - modele ML,
- `notebooks/presentation.ipynb` - notebook prezentacyjny.

Uruchomienie:

```powershell
.\.venv\Scripts\jupyter.exe lab
```

Notebook uzywa zdarzen zgrupowanych, dlatego liczba rekordow jest mniejsza niz liczba linii w pliku logow.

Ponowne wygenerowanie danych:

```powershell
.\.venv\Scripts\python.exe generowanie_logow.py
```
