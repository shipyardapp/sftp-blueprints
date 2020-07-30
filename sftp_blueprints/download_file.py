import os
import io
import re
import json
import tempfile
import argparse

import paramiko


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-file-name-match-type', dest='source_file_name_match_type',
                        choices={'exact_match', 'regex_match'}, required=True)
    parser.add_argument('--source-folder-name',
                        dest='source_folder_name', default='', required=False)
    parser.add_argument('--source-file-name',
                        dest='source_file_name', required=True)
    parser.add_argument('--destination-file-name',
                        dest='destination_file_name', default=None, required=False)
    parser.add_argument('--destination-folder-name',
                        dest='destination_folder_name', default='', required=False)
    parser.add_argument('--host', dest='host', default=None, required=True)
    parser.add_argument('--port', dest='port', default=21, required=True)
    parser.add_argument('--username', dest='username', default=None, required=False)
    parser.add_argument('--password', dest='password', default=None, required=False)
    parser.add_argument('--key', dest='key', default=None, required=False)
    return parser.parse_args()


def extract_file_name_from_source_full_path(source_full_path):
    """
    Use the file name provided in the source_file_name variable. Should be run only
    if a destination_file_name is not provided.
    """
    destination_file_name = os.path.basename(source_full_path)
    return destination_file_name


def enumerate_destination_file_name(destination_file_name, file_number=1):
    """
    Append a number to the end of the provided destination file name.
    Only used when multiple files are matched to, preventing the destination file from being continuously overwritten.
    """
    if re.search(r'\.', destination_file_name):
        destination_file_name = re.sub(
            r'\.', f'_{file_number}.', destination_file_name, 1)
    else:
        destination_file_name = f'{destination_file_name}_{file_number}'
    return destination_file_name


def determine_destination_file_name(*, source_full_path, destination_file_name, file_number=None):
    """
    Determine if the destination_file_name was provided, or should be extracted from the source_file_name, 
    or should be enumerated for multiple file downloads.
    """
    if destination_file_name:
        if file_number:
            destination_file_name = enumerate_destination_file_name(
                destination_file_name, file_number)
        else:
            destination_file_name = destination_file_name
    else:
        destination_file_name = extract_file_name_from_source_full_path(
            source_full_path)

    return destination_file_name


def clean_folder_name(folder_name):
    """
    Cleans folders name by removing duplicate '/' as well as leading and trailing '/' characters.
    """
    folder_name = folder_name.strip('/')
    if folder_name != '':
        folder_name = os.path.normpath(folder_name)
    return folder_name


def combine_folder_and_file_name(folder_name, file_name):
    """
    Combine together the provided folder_name and file_name into one path variable.
    """
    combined_name = os.path.normpath(
        f'{folder_name}{"/" if folder_name else ""}{file_name}')
    combined_name = os.path.normpath(combined_name)

    return combined_name


def determine_destination_name(destination_folder_name, destination_file_name, source_full_path, file_number=None):
    """
    Determine the final destination name of the file being downloaded.
    """
    destination_file_name = determine_destination_file_name(
        destination_file_name=destination_file_name, source_full_path=source_full_path, file_number=file_number)
    destination_name = combine_folder_and_file_name(
        destination_folder_name, destination_file_name)
    return destination_name


def find_sftp_file_names(client, prefix=''):
    """
    Fetched all the files in the folder on the SFTP server
    """
    try:
        files = []
        folders = []
        if prefix != '':
            data = client.listdir(prefix)
        else:
            data = client.listdir()

        for fname in data:
            if fname.startswith('.'):
                continue
            if prefix:
                fdata = str(client.lstat(f'{prefix}/{fname}')).split()[0]
            else:
                fdata = str(client.lstat(fname)).split()[0]
            if fdata.startswith('d'):
                folders.append(fname)
            else:
                if prefix != '':
                    files.append(f'{prefix}/{fname}')
                else:
                    files.append(fname)

        for folder in folders:
            if prefix:
                folder = f'{prefix}/{folder}'
            files.extend(find_sftp_file_names(client, folder))
    except Exception as e:
        print(f'Failed to find files in folder {prefix}')
        raise(e)

    return files


def find_matching_files(file_names, file_name_re):
    """
    Return a list of all file_names that matched the regular expression.
    """
    matching_file_names = []
    for file_name in file_names:
        fname = file_name.rsplit('/', 1)[-1]
        if re.search(file_name_re, fname):
            matching_file_names.append(file_name)

    return matching_file_names


def download_sftp_file(client, file_name, destination_file_name=None):
    """
    Download a selected file from the SFTP server to local storage in
    the current working directory or specified path.
    """
    local_path = os.path.normpath(f'{os.getcwd()}/{destination_file_name}')
    path = local_path.rsplit('/', 1)[0]
    if not os.path.exists(path):
        os.mkdir(path)
    try:
        client.get(file_name, local_path)
    except Exception as e:
        os.remove(local_path)
        print(f'Failed to download {file_name}')
        raise(e)

    print(f'{file_name} successfully downloaded to {local_path}')
    return


def get_client(host, port, username, key=None, password=None):
    """
    Attempts to create an SFTP client at the specified hots with the
    specified credentials
    """
    try:
        if key:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            k = paramiko.RSAKey.from_private_key_file(key)
            ssh.connect(hostname=host, port=port, username=username, pkey=k)
            client = ssh.open_sftp()
        else:
            transport = paramiko.Transport((host, int(port)))
            transport.connect(None, username, password)
            client = paramiko.SFTPClient.from_transport(transport)
        return client
    except Exception as e:
        print(f'Error accessing the SFTP server with the specified credentials' \
                f' {host}:{port} {username}:{key}')
        raise(e)


def main():
    args = get_args()
    host = args.host
    port = args.port
    username = args.username
    password = args.password
    key = args.key
    if not password and not key:
        print(f'Must specify a password or a RSA key')
        return

    key_path = None
    if key:
        if not os.path.isfile(key):
            fd, key_path = tempfile.mkstemp()
            print(f'Storing RSA temporarily at {key_path}')
            with os.fdopen(fd, 'w') as tmp:
                tmp.write(key)
            key = key_path
        client = get_client(host=host, port=port, username=username,
                            key=key)
    elif password:
        client = get_client(host=host, port=port, username=username,
                            password=password)

    source_file_name = args.source_file_name
    source_folder_name = clean_folder_name(args.source_folder_name)
    source_full_path = combine_folder_and_file_name(
        folder_name=source_folder_name, file_name=source_file_name)
    source_file_name_match_type = args.source_file_name_match_type

    destination_folder_name = clean_folder_name(args.destination_folder_name)
    if not os.path.exists(destination_folder_name) and \
            (destination_folder_name != ''):
        os.makedirs(destination_folder_name)

    if source_file_name_match_type == 'regex_match':
        files = find_sftp_file_names(client=client, prefix=source_folder_name)
        matching_file_names = find_matching_files(files,
                                            re.compile(source_file_name))
        print(f'{len(matching_file_names)} files found. Preparing to download...')

        for index, file_name in enumerate(matching_file_names):
            destination_name = determine_destination_name(
                    destination_folder_name=destination_folder_name,
                    destination_file_name=args.destination_file_name,
                    source_full_path=file_name, file_number=index+1)

            print(f'Downloading file {index+1} of {len(matching_file_names)}')
            try:
                download_sftp_file(client=client, file_name=file_name,
                    destination_file_name=destination_name)
            except Exception as e:
                print(f'Failed to download {file_name}... Skipping')
    else:
        destination_name = determine_destination_name(
                destination_folder_name=destination_folder_name,
                destination_file_name=args.destination_file_name,
                source_full_path=source_full_path)

        download_sftp_file(client=client, file_name=source_full_path,
                destination_file_name=destination_name)

    if key_path:
        print(f'Removing temporary RSA Key file {key_path}')
        os.remove(key_path)


if __name__ == '__main__':
    main()
