import os
import re
import json
import tempfile
import argparse
import glob

import paramiko


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-file-name-match-type',
            dest='source_file_name_match_type',
            choices={
                'exact_match',
                'regex_match'},
            required=True)
    parser.add_argument('--source-file-name', dest='source_file_name',
            required=True)
    parser.add_argument('--source-folder-name', dest='source_folder_name',
            default='', required=False)
    parser.add_argument('--destination-folder-name',
            dest='destination_folder_name', default='', required=False)
    parser.add_argument('--destination-file-name', dest='destination_file_name',
            default=None, required=False)
    parser.add_argument('--host', dest='host', default=None, required=True)
    parser.add_argument('--port', dest='port', default=21, required=True)
    parser.add_argument('--username', dest='username', default=None, required=False)
    parser.add_argument('--password', dest='password', default=None, required=False)
    parser.add_argument('--key', dest='key', default=None, required=False)
    return parser.parse_args()


def extract_file_name_from_source_full_path(source_full_path):
    """
    Use the file name provided in the source_full_path variable. Should be run
    only if a destination_file_name is not provided.
    """
    destination_file_name = os.path.basename(source_full_path)
    return destination_file_name


def enumerate_destination_file_name(destination_file_name, file_number=1):
    """
    Append a number to the end of the provided destination file name.
    Only used when multiple files are matched to, preventing the destination
    file from being continuously overwritten.
    """
    if re.search(r'\.', destination_file_name):
        destination_file_name = re.sub(
            r'\.', f'_{file_number}.', destination_file_name, 1)
    else:
        destination_file_name = f'{destination_file_name}_{file_number}'
    return destination_file_name


def determine_destination_file_name(
    *,
    source_full_path,
    destination_file_name,
        file_number=None):
    """
    Determine if the destination_file_name was provided, or should be extracted
    from the source_file_name, or should be enumerated for multiple file
    uploads.
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
    Cleans folders name by removing duplicate '/' as well as leading and
    trailing '/' characters.
    """
    folder_name = folder_name.strip('/')
    if folder_name != '':
        folder_name = os.path.normpath(folder_name)
    return folder_name


def combine_folder_and_file_name(folder_name, file_name):
    """
    Combine together the provided folder_name and file_name into one path
    variable.
    """
    combined_name = os.path.normpath(
        f'{folder_name}{"/" if folder_name else ""}{file_name}')
    combined_name = os.path.normpath(combined_name)

    return combined_name


def determine_destination_full_path(
        destination_folder_name,
        destination_file_name,
        source_full_path,
        file_number=None):
    """
    Determine the final destination name of the file being uploaded.
    """
    destination_file_name = determine_destination_file_name(
        destination_file_name=destination_file_name,
        source_full_path=source_full_path,
        file_number=file_number)
    destination_full_path = combine_folder_and_file_name(
        destination_folder_name, destination_file_name)
    return destination_full_path


def find_all_local_file_names(source_folder_name):
    """
    Returns a list of all files that exist in the current working directory,
    filtered by source_folder_name if provided.
    """
    cwd = os.getcwd()
    cwd_extension = os.path.normpath(f'{cwd}/{source_folder_name}/**')
    file_names = glob.glob(cwd_extension, recursive=True)
    return [file_name for file_name in file_names if os.path.isfile(file_name)]


def find_all_file_matches(file_names, file_name_re):
    """
    Return a list of all file_names that matched the regular expression.
    """
    matching_file_names = []
    for file in file_names:
        if re.search(file_name_re, file):
            matching_file_names.append(file)

    return matching_file_names

def cd_into_cwd(client, destination_path):
    """
    Changes working directory to the specified destination path
    and creates it if it doesn't exist
    """
    for folder in destination_path.split('/'):
        try:
            client.chdir(folder)
        except Exception as e:
            client.mkdir(folder)
            client.chdir(folder)


def upload_sftp_file(
        client,
        source_full_path,
        destination_full_path):
    """
    Uploads a single file to the SFTP server.
    """
    if not os.path.isfile(source_full_path):
        print(f'{source_full_path} does not exist')
        return

    try:
        client.put(source_full_path, destination_full_path,confirm=False)
    except Exception as e:
        print(f'Failed to upload {source_full_path} to SFTP server')
        raise(e)

    print(f'{source_full_path} successfully uploaded to ' \
            f'{destination_full_path}')


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
    source_folder_name = args.source_folder_name
    source_full_path = combine_folder_and_file_name(
        folder_name=f'{os.getcwd()}/{source_folder_name}',
        file_name=source_file_name)
    destination_folder_name = clean_folder_name(args.destination_folder_name)
    source_file_name_match_type = args.source_file_name_match_type


    if source_file_name_match_type == 'regex_match':
        file_names = find_all_local_file_names(source_folder_name)
        matching_file_names = find_all_file_matches(
            file_names, re.compile(source_file_name))
        print(f'{len(matching_file_names)} files found. Preparing to upload...')

        cwd_set = False
        for index, key_name in enumerate(matching_file_names):
            destination_full_path = determine_destination_full_path(
                            destination_folder_name=destination_folder_name,
                            destination_file_name=args.destination_file_name,
                            source_full_path=key_name, file_number=index + 1)
            if not cwd_set and destination_folder_name != '':
                path, _ = destination_full_path.rsplit('/', 1)
                cd_into_cwd(client=client, destination_path=path)
                cwd_set = True

            file_name = destination_full_path.rsplit('/', 1)[-1]
            print(f'Uploading file {index+1} of {len(matching_file_names)}')
            upload_sftp_file(client=client, source_full_path=key_name,
                            destination_full_path=file_name)

    else:
        destination_full_path = determine_destination_full_path(
                            destination_folder_name=destination_folder_name,
                            destination_file_name=args.destination_file_name,
                            source_full_path=source_full_path)

        if len(destination_full_path.split('/')) > 1:
            path, destination_full_path = destination_full_path.rsplit('/', 1)
            cd_into_cwd(client=client, destination_path=path)

        upload_sftp_file(client=client, source_full_path=source_full_path,
                        destination_full_path=destination_full_path)

    if key_path:
        print(f'Removing temporary RSA Key file {key_path}')
        os.remove(key_path)


if __name__ == '__main__':
    main()
