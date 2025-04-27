from flask import Blueprint, request, jsonify, current_app

from flask import Flask, request, redirect, flash, jsonify
from werkzeug.utils import secure_filename
import os
import logging
from utils.process_file import process_file
import os
proces_routes = Blueprint('process', __name__)




@proces_routes.route('/', methods=['POST','GET'])
def upload_file():

  if request.method == 'GET':
    return '''
    <!doctype html>
    <title>Upload File</title>
    <h1>Upload File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''


  if 'file' not in request.files:
    return jsonify({'error': 'No file part in the request.'}), 400
  file = request.files['file']
  if file.filename == '':
    return jsonify({'error': 'No file selected for uploading.'}), 400

  # Secure the filename and save the uploaded file.
  filename = secure_filename(file.filename)
  save_path = os.path.join("uploads", filename)
  file.save(save_path)

  # Process the file and generate an analysis report.
  report = process_file(save_path, filename)
  return jsonify({'report': report})