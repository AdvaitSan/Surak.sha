import fitz
import os
import joblib
import re
import pandas as pd
import PyPDF2

svm= joblib.load('models/svm_pdf.pkl')
scaler=joblib.load('models/scaler.pkl')


def header_obj(col):
    match = re.search('%PDF-\d*.?\d*', col)
    return 1 if match else 0



def predict_pdf_malware(pdf_path):
    # Extract features
    features_df = extract_pdf_features(pdf_path)


    columns_to_keep = scaler.get_feature_names_out()
    trained_model = svm

    # Convert header to 0/1
    features_df['header'] = features_df['header'].apply(lambda col: header_obj(str(col)))

    # Add missing columns
    for col in columns_to_keep:
        if col not in features_df.columns:
            features_df[col] = 0

    # Reorder columns
    features_df = features_df[columns_to_keep]

    # Scale
    features_scaled = scaler.transform(features_df)

    # Predict
    return trained_model.predict(features_scaled)[0]



def extract_pdf_features(pdf_path):
    features = {}

    # File size
    features['pdfsize'] = os.path.getsize(pdf_path)

    # Open with PyMuPDF
    doc = fitz.open(pdf_path)
    features['pages'] = len(doc)
    features['metadata size'] = len(doc.metadata) if doc.metadata else 0
    features['title characters'] = len(doc.metadata.get("title", "")) if doc.metadata else 0
    features['isEncrypted'] = int(doc.is_encrypted)

    # Extract text
    full_text = ""
    for page in doc:
        full_text += page.get_text()
    features['text'] = int(len(full_text.strip()) > 0)

    # Embedded files & images
    features['embedded files'] = len(doc.embfile_names())
    features['images'] = sum([len(page.get_images(full=True)) for page in doc])

    # PDF header version
    with open(pdf_path, 'rb') as f:
        header = f.read(20)
        match = re.match(rb'%PDF-(\d\.\d)', header)
        features['header'] = match.group(1).decode() if match else "Unknown"

    # Keywords
    keywords = ['obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref',
                'encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction',
                'Acroform', 'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 'XFA', 'Colors']
    counts = {key: 0 for key in keywords}

    with open(pdf_path, 'rb') as f:
        raw_data = f.read()
        for key in keywords:
            counts[key] = len(re.findall(rb'\b' + key.encode() + rb'\b', raw_data))

    features.update(counts)

    # Xref length
    try:
        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            features['xref Length'] = len(reader.xref._xref_table) if hasattr(reader, 'xref') else 0
    except Exception:
        features['xref Length'] = 0

    # Page number
    features['pageno'] = len(doc)
    doc.close()

    # Convert to DataFrame
    return pd.DataFrame([features])

import numpy as np



def preprocess(df):
    df = df.drop(df[df['Class'].isnull()].index.tolist(), axis=0)
    df = df.drop(df[df['endobj'] == 'pdfid.py'].index.tolist(), axis=0)
    df = df.fillna(0)
    df["text"] = np.where(df["text"].str.contains("Yes"), 1, 0)
    def header_obj(col):
        match = re.search('%PDF-\d*.?\d*', col)
        if match:
            return 1
        return 0

    df['header'] = df['header'].apply(lambda col: header_obj(col))

    X = df.drop(columns=['Class', 'File name'])
    y = df['Class']
    return X, y


if __name__ == "__main__":
    # Example usage
    # pdf_path = "we dont have months. its in 2 days.pdf"
    # features = extract_pdf_features(pdf_path)
    # print(features)

    # Predict malware
    # Load the model and scaler
    
    # Predict on a sample PDF file
    result = predict_pdf_malware("malw.pdf")
    print("Prediction:", "Malicious" if result == 0 else "Benign")