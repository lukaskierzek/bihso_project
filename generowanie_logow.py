import random

OUTPUT_FILE = "data/raw/auditd_sample.log"
LABELS_FILE = "data/labels.csv"
TARGET_LINES = 2000

base_timestamp = 1715670000.000
serial = 1
pid_counter = 2000

NORMAL_COMMANDS = [
    ("ls", "/usr/bin/ls"),
    ("cat", "/usr/bin/cat"),
    ("vim", "/usr/bin/vim"),
    ("nano", "/usr/bin/nano"),
    ("python3", "/usr/bin/python3"),
    ("git", "/usr/bin/git"),
    ("ssh", "/usr/bin/ssh"),
    ("curl", "/usr/bin/curl"),
]

ADMIN_COMMANDS = [
    ("systemctl", "/usr/bin/systemctl"),
    ("journalctl", "/usr/bin/journalctl"),
    ("apt", "/usr/bin/apt"),
]

ATTACK_COMMANDS = [
    (
        "hydra",
        "/usr/bin/hydra",
        ["hydra", "-l", "root", "192.168.1.10"]
    ),
    (
        "nmap",
        "/usr/bin/nmap",
        ["nmap", "-sS", "192.168.1.0/24"]
    ),
    (
        "nc",
        "/usr/bin/nc",
        ["nc", "-e", "/bin/bash"]
    ),
    (
        "sudo",
        "/usr/bin/sudo",
        ["sudo", "cat", "/etc/shadow"]
    ),
]

NORMAL_PATHS = [
    "/home/lukasz/file.txt",
    "/home/lukasz/projects/app.py",
    "/home/lukasz/.bashrc",
    "/etc/hosts",
]

SUSPICIOUS_PATHS = [
    "/tmp/backdoor.sh",
    "/dev/shm/payload",
    "/var/tmp/rev.sh",
    "/etc/shadow",
]

CWDS = [
    "/home/lukasz",
    "/home/lukasz/projects",
    "/home/lukasz/projects/bihso",
    "/tmp",
]


def generate_timestamp():

    global base_timestamp

    if random.random() < 0.03:
        base_timestamp += random.randint(
            3600,
            18000
        )
    else:
        base_timestamp += random.uniform(
            1,
            60
        )

    return f"{base_timestamp:.3f}"


def generate_ids():

    global serial
    global pid_counter

    serial += 1

    pid_counter += random.randint(
        1,
        4
    )

    ppid = max(
        pid_counter - random.randint(1, 4),
        1
    )

    return serial, pid_counter, ppid


def random_success():

    if random.random() < 0.08:
        return "no", -13

    return "yes", 0


def create_path_line(
        timestamp,
        serial,
        attack=False
):

    path = (
        random.choice(
            SUSPICIOUS_PATHS
        )
        if attack
        else random.choice(
            NORMAL_PATHS
        )
    )

    return (
        f'type=PATH '
        f'msg=audit({timestamp}:{serial}): '
        f'item=0 '
        f'name="{path}"'
    )


def create_syscall_line(
        timestamp,
        serial,
        pid,
        ppid,
        command,
        executable,
        uid,
        auid,
        gid,
        success,
        exit_code,
        key
):

    return (
        f'type=SYSCALL '
        f'msg=audit({timestamp}:{serial}): '
        f'arch=c000003e '
        f'syscall=59 '
        f'success={success} '
        f'exit={exit_code} '
        f'ppid={ppid} '
        f'pid={pid} '
        f'auid={auid} '
        f'uid={uid} '
        f'gid={gid} '
        f'tty=pts0 '
        f'ses=3 '
        f'comm="{command}" '
        f'exe="{executable}" '
        f'key="{key}"'
    )


def create_execve_line(
        timestamp,
        serial,
        args
):

    argc = len(args)

    arguments = " ".join(
        [
            f'a{i}="{arg}"'
            for i, arg in enumerate(args)
        ]
    )

    return (
        f'type=EXECVE '
        f'msg=audit({timestamp}:{serial}): '
        f'argc={argc} '
        f'{arguments}'
    )


def create_cwd_line(
        timestamp,
        serial
):

    return (
        f'type=CWD '
        f'msg=audit({timestamp}:{serial}): '
        f'cwd="{random.choice(CWDS)}"'
    )


def generate_normal_event():

    timestamp = generate_timestamp()

    serial, pid, ppid = generate_ids()

    command, executable = random.choice(
        NORMAL_COMMANDS
    )

    success, exit_code = random_success()

    return [
        create_syscall_line(
            timestamp,
            serial,
            pid,
            ppid,
            command,
            executable,
            1000,
            1000,
            1000,
            success,
            exit_code,
            "normal_activity"
        ),
        create_execve_line(
            timestamp,
            serial,
            [command]
        ),
        create_cwd_line(
            timestamp,
            serial
        ),
        create_path_line(
            timestamp,
            serial
        )
    ]


def generate_admin_event():

    timestamp = generate_timestamp()

    serial, pid, ppid = generate_ids()

    command, executable = random.choice(
        ADMIN_COMMANDS
    )

    return [
        create_syscall_line(
            timestamp,
            serial,
            pid,
            ppid,
            command,
            executable,
            0,
            1000,
            0,
            "yes",
            0,
            "admin_activity"
        ),
        create_execve_line(
            timestamp,
            serial,
            [command]
        ),
        create_cwd_line(
            timestamp,
            serial
        ),
        create_path_line(
            timestamp,
            serial
        )
    ]


def generate_attack_event():

    timestamp = generate_timestamp()

    serial, pid, ppid = generate_ids()

    command, executable, args = random.choice(
        ATTACK_COMMANDS
    )

    uid = (
        0
        if command == "sudo"
        else 1000
    )

    return [
        create_syscall_line(
            timestamp,
            serial,
            pid,
            ppid,
            command,
            executable,
            uid,
            1000,
            uid,
            "yes",
            0,
            "attack_activity"
        ),
        create_execve_line(
            timestamp,
            serial,
            args
        ),
        create_cwd_line(
            timestamp,
            serial
        ),
        create_path_line(
            timestamp,
            serial,
            attack=True
        )
    ]


def generate_auth_event():

    timestamp = generate_timestamp()

    serial, pid, _ = generate_ids()

    result = random.choice(
        [
            "success",
            "failed",
            "failed",
            "failed"
        ]
    )

    return [
        (
            f'type=USER_AUTH '
            f'msg=audit({timestamp}:{serial}): '
            f'pid={pid} '
            f'uid=0 '
            f'auid=1000 '
            f'msg=\'op=PAM:authentication '
            f'acct="lukasz" '
            f'exe="/usr/sbin/sshd" '
            f'res={result}\''
        )
    ]


def main():

    random.seed(42)

    line_count = 0
    record_index = 0

    with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
    ) as log_file, open(
            LABELS_FILE,
            "w",
            encoding="utf-8"
    ) as labels_file:

        labels_file.write(
            "record_index,audit_id,label,scenario\n"
        )

        while line_count < TARGET_LINES:

            rand = random.random()

            if rand < 0.05:
                lines = generate_attack_event()
                label = 1
                scenario = "attack_activity"

            elif rand < 0.10:
                lines = generate_auth_event()
                is_failed_auth = "res=failed" in lines[0]
                label = 1 if is_failed_auth else 0
                scenario = (
                    "failed_authentication"
                    if is_failed_auth
                    else "successful_authentication"
                )

            elif rand < 0.20:
                lines = generate_admin_event()
                label = 0
                scenario = "admin_activity"

            else:
                lines = generate_normal_event()
                label = 0
                scenario = "normal_activity"

            audit_id = serial
            labels_file.write(
                f"{record_index},{audit_id},{label},{scenario}\n"
            )
            record_index += 1

            for line in lines:

                log_file.write(
                    line + "\n"
                )

                line_count += 1

                if (
                        line_count
                        >= TARGET_LINES
                ):
                    break

    print(
        f"Generated "
        f"{line_count} lines "
        f"into "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
