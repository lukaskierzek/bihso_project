# BIHSO auth.log anomaly detection

Projekt studencki: wykrywanie anomalii w rzeczywistych logach uwierzytelniania Linux.

Porownywane metody:
- detekcja regulowa,
- Isolation Forest,
- Local Outlier Factor.

Najwazniejsze pliki:
- `data/raw/auth_all_real.log` - rzeczywiste logi uwierzytelniania Linux,
- `src/auth_parser.py` - parser logow auth.log/syslog,
- `src/log_record.py` - model rekordu auth.log,
- `src/rules.py` - proste reguly detekcji,
- `src/features.py` - cechy dla modeli ML,
- `src/ml_detector.py` - modele ML,
- `src/preprocessing.py` - automatyczne etykietowanie, statystyki i metryki,
- `notebooks/presentation.ipynb` - notebook prezentacyjny.

Projekt nie wymaga recznego pliku etykiet. Etykieta `anomaly=1` jest nadawana automatycznie dla jednoznacznie podejrzanych zdarzen, m.in. `Failed password`, `Invalid user`, `authentication failure` i brute-force SSH. Zdarzenia takie jak poprawne logowania, zwykle sudo, sesje uzytkownikow i CRON sa traktowane jako `anomaly=0`, o ile nie spelniaja reguly podejrzanej.

Uruchomienie notebooka:

```powershell
.\.venv\Scripts\jupyter.exe lab
```

Szybki test pipeline:

```powershell
.\.venv\Scripts\python.exe -c "from config import RAW_LOG_PATH; from src.log_loader import load_logs; from src.auth_parser import parse_lines_grouped; print(len(parse_lines_grouped(load_logs(RAW_LOG_PATH))))"
```
