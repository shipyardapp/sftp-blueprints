import argparse
import os
import re
import tempfile
import asyncio
import asyncssh
import paramiko


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-file-name-match-type",
        dest="source_file_name_match_type",
        choices={"exact_match", "regex_match"},
        required=True,
    )
    parser.add_argument(
        "--source-folder-name", dest="source_folder_name", default="", required=False
    )
    parser.add_argument("--source-file-name", dest="source_file_name", required=True)
    parser.add_argument(
        "--destination-file-name",
        dest="destination_file_name",
        default=None,
        required=False,
    )
    parser.add_argument(
        "--destination-folder-name",
        dest="destination_folder_name",
        default="",
        required=False,
    )
    parser.add_argument("--host", dest="host", default=None, required=True)
    parser.add_argument("--port", dest="port", default=21, required=True)
    parser.add_argument("--username", dest="username", default=None, required=False)
    parser.add_argument("--password", dest="password", default=None, required=False)
    parser.add_argument("--key", dest="key", default=None, required=False)
    return parser.parse_args()


def extract_file_name_from_source_full_path(source_full_path):
    """
    Extract the file name from the source full path.
    """
    return os.path.basename(source_full_path)


def enumerate_destination_file_name(destination_file_name, file_number):
    """
    Append a number to the end of the provided destination file name.
    """
    base_name, extension = os.path.splitext(destination_file_name)
    return f"{base_name}_{file_number}{extension}"


def determine_destination_file_name(
    *, source_full_path, destination_file_name, file_number=None
):
    """
    Determine if the destination_file_name was provided, or should be extracted from the source_file_name,
    or should be enumerated for multiple file downloads.
    """
    if destination_file_name:
        if file_number:
            destination_file_name = enumerate_destination_file_name(
                destination_file_name, file_number
            )
        else:
            destination_file_name = destination_file_name
    else:
        destination_file_name = extract_file_name_from_source_full_path(
            source_full_path
        )

    return destination_file_name


def clean_folder_name(folder_name):
    """
    Clean the folder name by removing duplicate '/' characters and leading/trailing '/' characters.
    """
    folder_name = folder_name.strip("/")
    if folder_name:
        folder_name = os.path.normpath(folder_name)
    return folder_name


def combine_folder_and_file_name(folder_name, file_name):
    """
    Combine the folder name and file name into a single path.
    """
    return os.path.normpath(os.path.join(folder_name, file_name))


def determine_destination_name(
    destination_folder_name, destination_file_name, source_full_path, file_number=None
):
    """
    Determine the final destination name of the file being downloaded.
    """
    destination_file_name = determine_destination_file_name(
        destination_file_name=destination_file_name,
        source_full_path=source_full_path,
        file_number=file_number,
    )
    return combine_folder_and_file_name(destination_folder_name, destination_file_name)


def find_sftp_file_names(client, prefix=""):
    """
    Fetched all the files in the folder on the SFTP server
    """
    try:
        files = []
        folders = []
        data = client.listdir(prefix) if prefix != "" else client.listdir()
        for fname in data:
            if fname.startswith("."):
                continue
            if prefix:
                fdata = str(client.lstat(f"{prefix}/{fname}")).split()[0]
            else:
                fdata = str(client.lstat(fname)).split()[0]
            if fdata.startswith("d"):
                folders.append(fname)
            elif prefix == "":
                files.append(fname)

            else:
                files.append(f"{prefix}/{fname}")
        for folder in folders:
            if prefix:
                folder = f"{prefix}/{folder}"
            files.extend(find_sftp_file_names(client, folder))
    except Exception as e:
        print(f"Failed to find files in folder {prefix}")
        raise e

    return files


def find_matching_files(file_names, file_name_re):
    """
    Return a list of all file_names that matched the regular expression.
    """
    matching_file_names = []
    for file_name in file_names:
        fname = file_name.rsplit("/", 1)[-1]
        if re.search(file_name_re, fname):
            matching_file_names.append(file_name)

    return matching_file_names


def download_sftp_file(client, file_name, destination_file_name=None):
    """
    Download a selected file from the SFTP server to local storage in
    the current working directory or specified path.
    """
    local_path = os.path.normpath(
        combine_folder_and_file_name(os.getcwd(), destination_file_name)
    )
    path = local_path.rsplit("/", 1)[0]
    if not os.path.exists(path):
        os.mkdir(path)
    try:
        client.get(file_name, local_path)
    except Exception as e:
        os.remove(local_path)
        print(f"Failed to download {file_name}")
        raise e

    print(f"{file_name} successfully downloaded to {local_path}")


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
            return ssh.open_sftp()
        else:
            transport = paramiko.Transport((host, int(port)))
            transport.connect(None, username, password)
            return paramiko.SFTPClient.from_transport(transport)
    except Exception as e:
        print(
            f"Error accessing the SFTP server with the specified credentials"
            f" {host}:{port} {username}:{key}"
        )
        raise e


def download_with_paramiko():
    args = get_args()
    host = args.host
    port = args.port
    username = args.username
    password = args.password
    key = args.key
    if not password and not key:
        print("Must specify a password or a RSA key")
        return

    key_path = None
    if key:
        if not os.path.isfile(key):
            fd, key_path = tempfile.mkstemp()
            print(f"Storing RSA temporarily at {key_path}")
            with os.fdopen(fd, "w") as tmp:
                tmp.write(key)
            key = key_path
        client = get_client(host=host, port=port, username=username, key=key)
    elif password:
        client = get_client(host=host, port=port, username=username, password=password)

    source_file_name = args.source_file_name
    source_folder_name = clean_folder_name(args.source_folder_name)
    source_full_path = combine_folder_and_file_name(
        folder_name=source_folder_name, file_name=source_file_name
    )
    source_file_name_match_type = args.source_file_name_match_type

    destination_folder_name = clean_folder_name(args.destination_folder_name)
    if not os.path.exists(destination_folder_name) and (destination_folder_name != ""):
        os.makedirs(destination_folder_name)

    if source_file_name_match_type == "regex_match":
        files = find_sftp_file_names(client=client, prefix=source_folder_name)
        matching_file_names = find_matching_files(files, re.compile(source_file_name))
        print(f"{len(matching_file_names)} files found. Preparing to download...")

        for index, file_name in enumerate(matching_file_names):
            destination_name = determine_destination_name(
                destination_folder_name=destination_folder_name,
                destination_file_name=args.destination_file_name,
                source_full_path=file_name,
                file_number=index + 1,
            )

            print(f"Downloading file {index+1} of {len(matching_file_names)}")
            try:
                download_sftp_file(
                    client=client,
                    file_name=file_name,
                    destination_file_name=destination_name,
                )
            except Exception as e:
                print(f"Failed to download {file_name}... Skipping")
    else:
        destination_name = determine_destination_name(
            destination_folder_name=destination_folder_name,
            destination_file_name=args.destination_file_name,
            source_full_path=source_full_path,
        )

        download_sftp_file(
            client=client,
            file_name=source_full_path,
            destination_file_name=destination_name,
        )

    if key_path:
        print(f"Removing temporary RSA Key file {key_path}")
        os.remove(key_path)


def is_openssh_key(filename):
    with open(filename, "r") as f:
        first_line = f.readline().strip()
        return first_line.startswith("-----BEGIN OPENSSH")


async def download_files(
    hostname,
    username,
    client_keys,
    remote_dir,
    pattern,
    local_dir,
    port=22,
    match_type="exact_match",
):
    try:
        print("Attempting to connect to SFTP server...")
        async with asyncssh.connect(
            hostname,
            username=username,
            client_keys=client_keys,
            port=port,
            known_hosts=None,
        ) as conn:
            print("Connected to SFTP server.")
            async with conn.start_sftp_client() as sftp:
                print("Attempting to download files from SFTP server...")
                remote_files = await sftp.listdir(remote_dir)
                print(f"Found {len(remote_files)} files in {remote_dir}.")
                if match_type == "exact_match":
                    print("Attempting to match files by exact match.")
                    filtered_files = [f for f in remote_files if f == pattern]
                elif match_type == "regex_match":
                    print("Attempting to match files by regex.")
                    regex = re.compile(pattern)
                    filtered_files = [f for f in remote_files if regex.match(f)]
                else:
                    raise ValueError(
                        "Invalid match_type. Must be 'exact_match' or 'regex_match'."
                    )
                print(
                    f"Found {len(filtered_files)} files matching pattern '{pattern}'."
                )
                for index, file_name in enumerate(filtered_files):
                    remote_path = f"{remote_dir}/{file_name}"
                    destination_file_name = (
                        file_name
                        if len(filtered_files) == 1
                        else f"{extract_file_name_from_source_full_path(file_name)}_{index + 1}"
                    )
                    local_path = combine_folder_and_file_name(
                        os.getcwd(),
                        combine_folder_and_file_name(local_dir, destination_file_name),
                    )
                    path = local_path.rsplit("/", 1)[0]
                    if not os.path.exists(path):
                        os.makedirs(path)
                    await sftp.get(remote_path, local_path)
                    print(f"Downloaded file: {file_name} -> {local_path}")

    except asyncssh.Error as e:
        print(f"SSH connection failed: {str(e)}")


async def download_with_asycssh():
    sftp_host = os.environ["SFTP_HOST"]
    sftp_port = int(os.environ["SFTP_PORT"])
    sftp_username = os.environ["SFTP_USERNAME"]
    rsa_private_key_path = os.environ["SFTP_RSA_KEY_FILE"]

    source_file_name = os.environ["SFTP_SOURCE_FILE_NAME"]
    source_folder_name = os.environ["SFTP_SOURCE_FOLDER_NAME"]
    source_file_name_match_type = os.environ["SFTP_SOURCE_FILE_NAME_MATCH_TYPE"]
    destination_folder_name = clean_folder_name(
        os.environ["SFTP_DESTINATION_FOLDER_NAME"]
    )
    if not os.path.exists(destination_folder_name) and destination_folder_name != "":
        os.makedirs(destination_folder_name)

    await download_files(
        hostname=sftp_host,
        username=sftp_username,
        port=sftp_port,
        client_keys=rsa_private_key_path,
        remote_dir=source_folder_name,
        pattern=source_file_name,
        local_dir=destination_folder_name,
        match_type=source_file_name_match_type,
    )


def main():
    try:
        download_with_paramiko()
    except paramiko.AuthenticationException as error:
        if (
            is_openssh_key(os.environ["SFTP_RSA_KEY_FILE"])
            and os.environ["SFTP_RSA_KEY_FILE"] != ""
        ):
            print(
                "Warning: Trouble Authenticating with RSA Key.\n"
                "We have detected an RSA Key in the OpenSSH format. We will now attempt to connect to the SFTP server using a different method. To avoid this warning in the future, it is recommended to use an RSA PEM key instead."
            )
            asyncio.run(download_with_asycssh())

        else:
            raise error


if __name__ == "__main__":
    main()
