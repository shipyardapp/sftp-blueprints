import os
import re
import json
import tempfile
import argparse
import glob
import sys
import shipyard_utils as shipyard
import paramiko

EXIT_CODE_INCORRECT_CREDENTIALS = 3
EXIT_CODE_NO_MATCHES_FOUND = 200
EXIT_CODE_INVALID_FILE_PATH = 201
EXIT_CODE_SFTP_MOVE_ERROR = 202

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


def cd_into_cwd(client, destination_path):
    """
    Changes working directory to the specified destination path
    and creates it if it doesn't exist
    """
    for folder in destination_path.split('/'):
        try:
            client.chdir(folder)
        except Exception:
            client.mkdir(folder)
            client.chdir(folder)


def move_sftp_file(
        client,
        source_full_path,
        destination_full_path):
    """
    Move file from SFTP server.
    """
    # check if file exists
    try:
        client.stat(source_full_path)
    except FileNotFoundError:
        sys.exit(EXIT_CODE_INVALID_FILE_PATH)
    # move file
    try:
        client.rename(source_full_path, destination_full_path)
    except Exception:
        print(f'Failed to move {source_full_path} to {destination_full_path}')
        sys.exit(EXIT_CODE_SFTP_MOVE_ERROR)
    
    print(f'{source_full_path} successfully moved to ' \
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
        sys.exit(EXIT_CODE_INCORRECT_CREDENTIALS)


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
    source_full_path = shipyard.files.combine_folder_and_file_name(
        source_folder_name, source_file_name)
    destination_folder_name = shipyard.files.clean_folder_name(args.destination_folder_name)
    source_file_name_match_type = args.source_file_name_match_type


    if source_file_name_match_type == 'regex_match':
        file_names = find_sftp_file_names(client, prefix=source_folder_name)
        matching_file_names = shipyard.files.find_all_file_matches(
            file_names, re.compile(source_file_name))
        print(f'{len(matching_file_names)} files found. Preparing to move...')

        cwd_set = False
        for index, key_name in enumerate(matching_file_names):
            destination_full_path = shipyard.files.determine_destination_full_path(
                            destination_folder_name=destination_folder_name,
                            destination_file_name=args.destination_file_name,
                            source_full_path=key_name, file_number=index + 1)
            if not cwd_set and destination_folder_name != '':
                path, _ = destination_full_path.rsplit('/', 1)
                cd_into_cwd(client=client, destination_path=path)
                cwd_set = True

            file_name = destination_full_path.rsplit('/', 1)[-1]
            print(f'Moving file {index+1} of {len(matching_file_names)}')
            move_sftp_file(client=client, source_full_path=key_name,
                            destination_full_path=file_name)

    else:
        destination_full_path = shipyard.files.determine_destination_full_path(
                            destination_folder_name=destination_folder_name,
                            destination_file_name=args.destination_file_name,
                            source_full_path=source_full_path)

        if len(destination_full_path.split('/')) > 1:
            path, destination_full_path = destination_full_path.rsplit('/', 1)
            cd_into_cwd(client=client, destination_path=path)

        move_sftp_file(client=client, source_full_path=source_full_path,
                        destination_full_path=destination_full_path)

    if key_path:
        print(f'Removing temporary RSA Key file {key_path}')
        os.remove(key_path)


if __name__ == '__main__':
    main()
