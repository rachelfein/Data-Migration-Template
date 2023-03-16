# Data-Migration-Tempalte

This Python script is designed to efficiently handle the uploading of PDF documents and corresponding CSV metadata files from an sftp server to the document management software, NetDocs. By utilizing NetDocs' API, the script is able to seamlessly transfer all documents located in the sftp file path. Additionally, a logging system has been incorporated within the script to ensure that each document is only uploaded once, with all upload activity recorded in a SQL server database. This streamlined approach to document management allows for a more effective and organized workflow.

## Usage

To use this script, you need to have Python 3 and pandas library installed on your machine. Add your credentials, file paths, and API endpoints where specified.
