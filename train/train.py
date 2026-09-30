import numpy as np
import pandas as pd
import os
import pickle
import sklearn

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

data = pd.read_csv('data/UNSW-NB15_1.csv', header=None, low_memory=False)
data.columns = data.columns.astype(str)

TARGET = '48'

USE_FEATURES = [
    '3', '4', '6', '40', '41', '42', '43', '44', '45', '46', '48',
]

data = data[USE_FEATURES]

data['3'] = pd.to_numeric(data['3'], errors='coerce')
data = data.dropna(subset=['3'])
data['3'] = data['3'].astype(int)

y = data[TARGET].astype(int)
X = data.drop(columns=[TARGET])

# group rare protos (<0.1% freq) into 'other'
for col in [c for c in ('4',) if c in X.columns]:
    freq = data[col].value_counts(normalize=True)
    rare = freq[freq < 0.001].index
    X[col] = X[col].replace(rare, 'other')
    print(f"  {col}: grouped {len(rare)} rare categories -> 'other'")

Xn = X.select_dtypes(include='number')
Xs = pd.DataFrame(StandardScaler().fit_transform(Xn), columns=Xn.columns)

redundant = set()


def vif_scores(df):
    try:
        inv = np.linalg.inv(df.corr().to_numpy())
        return dict(zip(df.columns, np.diag(inv)))
    except np.linalg.LinAlgError:
        return dict(zip(df.columns, np.full(len(df.columns), np.inf)))


corr = Xs.corr().abs().to_numpy()
upper = np.triu(np.ones(corr.shape, dtype=bool), k=1)
_, drop_idx = np.where((corr > 0.9) & upper)
redundant.update(Xs.columns[c] for c in drop_idx)

# VIF > 10 indicates severe multicollinearity
Xs = Xs.drop(columns=list(redundant))
while True:
    vifs = vif_scores(Xs)
    worst = max(vifs, key=vifs.get)
    if not np.isinf(vifs[worst]) and vifs[worst] <= 10:
        break
    redundant.add(worst)
    Xs = Xs.drop(columns=[worst])

print(f"redundant cols dropped: {sorted(redundant, key=int)}")
X = X.drop(columns=list(redundant))

X = pd.get_dummies(X, columns=[c for c in ('4',) if c in X.columns], dtype=np.int8)

print(X.head(5))

# fit scaler on train only to avoid leakage into test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

impute = X_train.median().to_dict()
print(f"\nimpute medians for {len(impute)} features")

scaler = StandardScaler()
X_train = pd.DataFrame(scaler.fit_transform(X_train),
                       columns=X.columns, index=X_train.index)
X_test = pd.DataFrame(scaler.transform(X_test),
                      columns=X.columns, index=X_test.index)

print(f"X_train: {X_train.shape} | X_test: {X_test.shape}")
print(f"attack rate — train: {y_train.mean():.3f} | test: {y_test.mean():.3f}")
print(f"scaled check — mean|.| max: {abs(X_train.mean()).max():.6f}, "
      f"std range: {X_train.std().min():.3f}..{X_train.std().max():.3f}")

def make_clf(oob=False):
    return RandomForestClassifier(
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
        oob_score=oob,
    )


clf = make_clf(oob=True)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

report = classification_report(y_test, y_pred,
                               target_names=['normal', 'attack'],
                               output_dict=True)
p_attack = report['attack']['precision']
r_attack = report['attack']['recall']
f1_attack = report['attack']['f1-score']

print(f"\nOOB score: {clf.oob_score_:.4f}")
print(pd.DataFrame(report).transpose().round(4).to_string())
print("confusion matrix:\n", confusion_matrix(y_test, y_pred))

importances = pd.Series(clf.feature_importances_, index=X.columns)
print("top 10 features:\n", importances.sort_values(ascending=False).head(10).round(4).to_string())

# ablation guard: only runs when those cols survived selection
abl_cols = [c for c in ('9', '36', '15') if c in X.columns]
if abl_cols:
    clf_abl = make_clf()
    clf_abl.fit(X_train.drop(columns=abl_cols), y_train)
    y_pred_abl = clf_abl.predict(X_test.drop(columns=abl_cols))

    print(f"\n--- ablation: dropped {abl_cols} ---")
    print(classification_report(y_test, y_pred_abl, target_names=['normal', 'attack']))
    print("confusion matrix:\n", confusion_matrix(y_test, y_pred_abl))
    importances_abl = pd.Series(clf_abl.feature_importances_,
                                index=X.columns.drop(abl_cols))
    print("top 5 features after ablation:\n",
          importances_abl.sort_values(ascending=False).head(5).round(4).to_string())
else:
    print("\n--- ablation skipped: abl_cols not in feature set ---")


bundle = {
    'model': clf,
    'scaler': scaler,
    'features': list(X.columns),
    'redundant_dropped': sorted(redundant, key=int),
    'rare_threshold': 0.001,
    'metrics': {
        'test_precision': float(p_attack),
        'test_recall': float(r_attack),
        'test_f1': float(f1_attack),
    },
    'impute': impute,
    'thresholds': {
        'critical': 0.9,
        'high': 0.7,
        'medium': 0.5,
    },
    'window_seconds': 30,
    'sklearn_version': sklearn.__version__,
}

path = 'model_rf.pkl'
with open(path, 'wb') as f:
    pickle.dump(bundle, f)
print(f"\nsaved {os.path.getsize(path)} bytes → {path}")
