import pysftp
import sqlite3
import os
import csv
import pandas as pd
import datetime
from requests import request
import webbrowser
import base64
import json
import urllib
import requests
import pyodbc

# SFTP Server Connection Settings

host = 'yourhost.com'
username = 'your user name'
private_key = 'path to openssh.pem'


# Create an instance of CnOpts and set hostkeys to None
cnopts = pysftp.CnOpts()
cnopts.hostkeys = None


# Create an SFTP connection to the specified host using the provided credentials
srv = pysftp.Connection(host=host, username=username, private_key=private_key, cnopts=cnopts)

remote_path= 'sftp path'

# download csv files to change the headers
local_path= 'path to save metadata file'
mapping_file = (local_path + 'your mapping.csv')
mapped_files_path = local_path + 'mapped_files\\'
import datetime


def download_csvs(srv, remote_path, local_path, mapping_file, mapped_files_path):
    # Get a list of all folders in the remote directory
    folder_list = srv.listdir(remote_path)
   
    # Loop through the list of folders
    for folder in folder_list:
        # Get a list of all files in the folder
        file_list = srv.listdir(remote_path + '/' + folder)
       
        # Loop through the list of files in the folder and download each one
        for file in file_list:
            # Check if the file has a .csv extension
            if file.endswith('.csv'):
                # Define the local file path
                local_file_path = local_path + file
               
                # Check if the file already exists in the local directory
                if not os.path.exists(local_file_path):
                    srv.get(remote_path + '/' + folder + '/' + file, local_file_path)
                else:
                    # Skip processing this file if it already exists in the local directory
                    continue
               
                # Read the mapping CSV into a pandas dataframe
                mapping = pd.read_csv(mapping_file)
                header_map = dict(zip(mapping['Original Header'], mapping['New Header']))


                # Read the input CSV into a pandas DataFrame
                df = pd.read_csv(local_file_path)


                # Remove the "line item" column
                df.drop("Line Item", axis=1, inplace=True)
           

                date_cols = ["Scan Date", "Storage Receipt Date"]
                df[date_cols] = df[date_cols].apply(lambda x: pd.to_datetime(x, errors='coerce', utc=True).dt.tz_convert('UTC').apply(lambda y: f"/Date({int((y.timestamp() * 1000))})/" if not pd.isnull(y) else ""))


                # Loop through each header in the DataFrame and apply the mapping
                for header in df.columns:
                    if header in header_map:
                        df.rename(columns={header: header_map[header]}, inplace=True)


                # Define the output file path
                output_file_path = mapped_files_path + file


                # Write the updated DataFrame to a new CSV file
                df.to_csv(output_file_path, index=False)

#Run
download_csvs(srv, remote_path, local_path, mapping_file, mapped_files_path)
 
# Create system to track files that have been uploaded
def create_db():
    """
    Create a SQL Server database and table to store the names of processed files.
    """
    conn = pyodbc.connect('Driver={ODBC Driver 17 for SQL Server};'
                          'Server=DESKTOP-E370A8F\MSSQLSERVERDEV;'
                          'Database=master;'
                          'Trusted_Connection=yes;')
    c = conn.cursor()


    # Create the database if it doesn't exist
    c.execute("IF NOT EXISTS(SELECT * FROM sys.databases WHERE name = 'name') BEGIN CREATE DATABASE DBNAME END;")
    conn.commit()


    # Switch to the database
    c.execute("USE DBNAME;")
    conn.commit()


    # Create the table if it doesn't exist
    c.execute('''IF NOT EXISTS(SELECT * FROM sys.tables WHERE name='processed_files') BEGIN CREATE TABLE processed_files (pdf_file_name VARCHAR(255), id VARCHAR(255), envId VARCHAR(255), name VARCHAR(255), date_uploaded DATE) END;''')
    conn.commit()


    return conn
   
conn = create_db()


def file_is_processed(conn, pdf_file_name):
    """
    Check if pdf_file_name is present in processed_files table
    """
    c = conn.cursor()
    c.execute("SELECT * FROM processed_files WHERE pdf_file_name = ?", (pdf_file_name,))
    row = c.fetchone()
    return row is not None


def check_files(remote_path):
    #conn = create_db()
    not_processed_files = []

    # List the files in the remote directory
    folders = srv.listdir(remote_path)
    for folders in folders:
        for pdf_file_name in srv.listdir(folders):
            if pdf_file_name.endswith(".pdf"):
                if file_is_processed(conn, pdf_file_name):
                    print(f"{pdf_file_name} already processed, skipping")
                    continue
                else:
                    #insert_to_db(conn, pdf_file_name)
                    not_processed_files.append(pdf_file_name)
    return not_processed_files


# Run the check_files function and get the files that have not been processed
not_processed_files = check_files(remote_path)

# Your OAuth2 client ID and secret
CLIENT_ID = "your client id"
CLIENT_SECRET = "your client secret"

# The authorization server's endpoints
AUTH_ENDPOINT = "https://REPLACE.AUTH.ENDPINT.OAuth.aspx"
TOKEN_ENDPOINT = "https://REPLACE.TOKEN.ENDPINT./OAuth"


# The OAuth2 redirect URI
REDIRECT_URI = "https://localhost/"


# The OAuth2 scope
SCOPE = "full"


# Encode the client ID and secret for use in the basic auth header
base64_auth_string = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode('utf-8')).decode('utf-8')
auth_string = f'Basic {base64_auth_string}'
auth_header = {
        'Authorization': auth_string,
        'Accept': 'application/json',
        'Content-Type' : 'application/x-www-form-urlencoded'
    }


def login_get_refresh_token():


    # Construct the authorization URL
    auth_url = f'{AUTH_ENDPOINT}?client_id={CLIENT_ID}&scope={SCOPE}&response_type=code&redirect_uri={REDIRECT_URI}'


    # Open the authorization URL in a new browser tab
    webbrowser.open_new_tab(auth_url)


    # Wait for the user to authorize and get the authorization code
    auth_code = input('Enter the authorization code: ')


    # URL-decode the token
    auth_code = urllib.parse.unquote(auth_code)


    # Data for the token exchange request
    data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        #"client_id" : CLIENT_ID,
        #"client_secret": CLIENT_SECRET
    }


    # Send a POST request to the token endpoint
    response = requests.post(TOKEN_ENDPOINT, data=data, headers=auth_header)


    # Raise HTTP errors if any
    if response.status_code != 200:
        error_response = response.json()
        print(f"Error response: {error_response}")
    else:
    # process the successful response
        #pass
        response_json = response.json()
        refresh_token = response_json["refresh_token"]
        access_token = response_json["access_token"]

        # Store the tokens in the file
        with open('tokens.txt', 'w') as file:
            file.write(refresh_token + '\n' + access_token)
    return refresh_token, access_token


with open("tokens.txt", "r") as f:
    refresh_token = f.readline().strip()
    access_token = f.readline().strip()


# Obtain an access token
def get_access_token(refresh_token, auth_header, REDIRECT_URI, TOKEN_ENDPOINT):
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "redirect_uri": REDIRECT_URI,
    }

    # Send a POST request to the token endpoint
    response = requests.post(TOKEN_ENDPOINT, data=data, headers=auth_header)
    #print('Request data:', headers)
    response_json = response.json()


    # Raise HTTP errors if any
    if response.status_code != 200:
        error_response = response.json()
        print(f"Error response: {error_response}")
    else:
    # process the successful response
        #pass
        refresh_token = response_json["refresh_token"]
        access_token = response_json["access_token"]


        # Store the tokens in the file
        with open('tokens.txt', 'w') as file:
            file.write(refresh_token + '\n' + access_token)


        return refresh_token, access_token


refresh_token, access_token = get_access_token(refresh_token, auth_header, REDIRECT_URI, TOKEN_ENDPOINT)


# The API's base URL
api_base_url = 'https://REPLACE.API.BASE/v1'


# Set the API endpoint URL
api_endpoint = f'{api_base_url}/Document/'


# Main Cabinet
main_cabinet = 'cabinet name'



def insert_to_db(conn, pdf_file_name, id, envId, name, date):
    """
    Inserts the file name and the specified attributes into the SQLite table
    """
    c = conn.cursor()
    c.execute("INSERT INTO processed_files (pdf_file_name, id, envid, name, date_uploaded) VALUES (?,?,?,?,?)", (pdf_file_name, id, envId, name, date))
    conn.commit()




class CustomAttributes:
    """
    Class to store the custom attributes for a PDF file to be uploaded.
    """
    def __init__(self, title, attributes):
        self.attributes = attributes
        self.title = title



def extract_custom_attributes(metadata_file_path):
    """
    Extracts the custom attributes for a PDF file from the metadata file.

    title: The assigned name of the PDF file that was gotten from the metadata file (header name 1060).

    returns a list of instances of the CustomAttributes class with the extracted custom attributes.This process repeats
    for each row in the CSV file.
    """
    with open(metadata_file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            title = row['60']
            if not title:
                return None
            attributes = {k: v for k, v in row.items() if k != '60'}
            return CustomAttributes(title=title, attributes=attributes)


def upload_pdf(api_endpoint, pdf_file_path, custom_attributes):
    """
    Uploads a PDF file along with its custom attributes to the specified API endpoint.
   
    api_headers: The headers to be sent with the API request.
    api_endpoint: The endpoint URL to upload the file to.
    pdf_file_path: The path of the PDF file to be uploaded.
    custom_attributes: An instance of the CustomAttributes class with the custom attributes for the PDF file.
    """
    with open("tokens.txt", "r") as f:
        refresh_token = f.readline().strip()
        access_token = f.readline().strip()


    array = [ {'id' : i, 'value' : custom_attributes.attributes[i]} for i in custom_attributes.attributes]
    serialized_profile_data = json.dumps(array)


    with srv.open(pdf_file_path, 'rb') as f:
        files = {
            'file': (custom_attributes.title, f)
        }
        data = {
            'action':'upload',
            'cabinet': main_cabinet,
            'profile': serialized_profile_data,
            'return': 'full',
        }


        api_headers = {
            'Authorization': "Bearer " + access_token,
            'Accept': 'application/json'
        }
       
        # try uploading the file twice, if fails at first will run get_access_token() to get a new access token then try again
        for attempt in range(2):
            try:

                response = requests.post(api_endpoint, headers=api_headers, data=data, files=files)
               
                print("Response headers:", response.headers)
                print("Response text:", response.text)
                response.raise_for_status()
                print(f"{custom_attributes.title} processed successfully")
                date_str = response.headers["Date"]
                date = datetime.datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %Z')
                standard_attributes = response.json()["standardAttributes"]
                id = standard_attributes["id"]
                envId = standard_attributes["envId"]
                name = standard_attributes["name"]
                insert_to_db(conn, custom_attributes.title, id, envId, name, date)


                # Remove the file name from the list of not processed files
                if custom_attributes.title in not_processed_files:
                    not_processed_files.remove(custom_attributes.title)


                break
           
            except requests.exceptions.HTTPError as error:
                if attempt == 1:
                    print(f"Error processing {custom_attributes.title} & Exceeded maximum number of attempts.")
                    print(f"\t API error: {error}")
                    print(f"\t Response text: {error.response.text}")
                    print(f"\t Response headers: {error.response.headers} \n\n")
                    break
                else:
                    access_token, refresh_token = get_access_token(refresh_token, auth_header, REDIRECT_URI, TOKEN_ENDPOINT)
               


def import_files(not_processed_files, mapped_files_path, remote_path, api_endpoint):
    """
    Imports files by processing a list of file names, extracting custom attributes, checking if the PDF exists, and uploading the PDF to the API.
    """
    if not not_processed_files:
        print("\n No files left in not_processed_files, uploading complete.")
        return


    for metadata_file_name in os.listdir(mapped_files_path):
        if not not_processed_files:
            print("\n No files left in not_processed_files, uploading complete.")
            return
        metadata_file_path = os.path.join(mapped_files_path, metadata_file_name)
        # Extract custom attributes from the metadata file
        custom_attributes = extract_custom_attributes(metadata_file_path)
        if not custom_attributes:
            print(f"Error processing {metadata_file_name}: No matching PDF found.")
            continue


        # Check if there is a matching PDF for the current metadata file
        pdf_file_found = False
        pdf_file_path = None
        folder_name = metadata_file_name.split('.')[0]
        for folder_item in srv.listdir(remote_path):
            if folder_item == folder_name:
                folder_path = os.path.join(remote_path, folder_item).replace("\\", "/")
                for pdf_file_name in srv.listdir(folder_path):
                    if pdf_file_name.endswith(".pdf") and custom_attributes.title == pdf_file_name:
                        if pdf_file_name in not_processed_files:
                            pdf_file_path = os.path.join(folder_path, pdf_file_name).replace("\\", "/")
                            pdf_file_found = True
                            print(f"Found {pdf_file_name} in folder {pdf_file_path}")
                            break
            if pdf_file_found:
                break
        if not pdf_file_found:
            print(f" Error processing {pdf_file_name} from metadata file {metadata_file_name}: No PDF file matching the custom attributes title ='{custom_attributes.title}' \n, was found at PDF file path: {pdf_file_path}/{metadata_file_name.split('.')[0]} \n Metadata file path: {metadata_file_path} \n Remote path: {remote_path}")
            continue
        if pdf_file_path:
            # Upload the PDF to the API
            upload_pdf(api_endpoint, pdf_file_path, custom_attributes)
            #print(f"{pdf_file_path} successfully uploaded to the API.")
        else:
            break


import_files(not_processed_files, mapped_files_path, remote_path, api_endpoint)

