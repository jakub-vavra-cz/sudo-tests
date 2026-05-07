"""
SUDO Responder Tests.

:requirement: sudo
"""

from __future__ import annotations

from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology

import pytest


@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.ticket(jira=["RHEL-59136", "RHEL-127359", "RHEL-127360"])
def test__env_shell_once_local(client: Client):
    """
    :title: Environment variable SHELL is not duplicated
    :setup:
        1. Create user "user-1" with shell /bin/zsh
    :steps:
        1. Run "sudo /usr/bin/env" as user-1
        2. Check if variable SHELL is present only once
    :expectedresults:
        1. Command is executed successfully
        2. Variable SHELL is present only once
    :customerscenario: True
    """
    if client.host.compare_package_version({"major": 1, "minor": 9, "patch": 17, "prerelease": "p2"}, "sudo") < 0:
        pytest.skip("Sudo version is less than 1.9.17p2")
    client.host.conn.run("dnf install zsh -y")
    u = client.user("user-1").add(uid=10001, shell="/bin/zsh", password="Secret123")
    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()
    result = client.host.conn.run(f"sudo -iu {u.name} /usr/bin/env")
    assert result.rc == 0, f"Running env as {u.name} using sudo failed!"
    assert result.stdout.count("SHELL") == 1, f"Variable SHELL is duplicated for {u.name}!"


# Regexe feature was backported to RHEL 9.x with sudo version 1.9.17p2


@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.ticket(jira=["RHEL-128212", "RHEL-1376"])
def test__regex_wildcard_in_command(client: Client):
    """
    :title: Regex wildcard in command is working
    :setup:
        1. Create user "user-1"
        2. Create a sudo rule for user-1 with whoami command
        3. Create a sudo rule for user-1 with a regex/bash wildcard * in the command
    :steps:
        1. Run a whoami command
        2. Run a command matching the regex
        3. Run a command not matching the regex
    :expectedresults:
        1. Command is executed successfully
        2. Command is executed successfully
        3. Command is not executed
    :customerscenario: True
    """

    if (
        client.host.compare_package_version({"major": 1, "minor": 9, "patch": 17, "prerelease": "p2"}, "sudo") < 0
        or client.host.distro_major < 9
    ):
        pytest.skip("Sudo version is less than 1.9.17p2")
    u = client.user("user-1").add(uid=10001, password="Secret123")
    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()
    client.sudorule("user-1-whoami").add(user=u, command="/usr/bin/whoami", host="ALL")
    client.sudorule("user-1-regex").add(user=u, command="/usr/bin/d*", host="ALL")
    client.host.conn.run("cat /etc/sudoers.d/*")
    assert client.auth.sudo.run(
        u.name, "Secret123", command="/usr/bin/whoami"
    ), f"Running whoami as {u.name} using sudo failed!"
    assert client.auth.sudo.run(
        u.name, "Secret123", command="/usr/bin/df"
    ), f"Running df as {u.name} using sudo failed!"
    assert not client.auth.sudo.run(
        u.name, "Secret123", command="/usr/bin/wc"
    ), f"Running wc as {u.name} using sudo passed!"


@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.ticket(jira=["RHEL-128212", "RHEL-1376"])
def test__regex_regex_in_command(client: Client):
    """
    :title: Regex command is working
    :setup:
        1. Create user "user-1"
        2. Create a sudo rule for user-1 with whoami command
        3. Create a sudo rule for user-1 with a regex like ^...$
    :steps:
        1. Run a whoami command
        2. Run a command matching the regex
        3. Run a command not matching the regex
    :expectedresults:
        1. Command is executed successfully
        2. Command is executed successfully
        3. Command is not executed
    :customerscenario: True
    """
    if (
        client.host.compare_package_version({"major": 1, "minor": 9, "patch": 17, "prerelease": "p2"}, "sudo") < 0
        or client.host.distro_major < 9
    ):
        pytest.skip("Sudo version is less than 1.9.17p2")
    u = client.user("user-1").add(uid=10001, password="Secret123")
    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()
    client.sudorule("user-1-whoami").add(user=u, command="/usr/bin/whoami", host="ALL")
    client.sudorule("user-1-regex").add(user=u, command="^/usr/bin/d.*$", host="ALL")
    client.host.conn.run("cat /etc/sudoers.d/*")
    assert client.auth.sudo.run(
        u.name, "Secret123", command="/usr/bin/whoami"
    ), f"Running whoami as {u.name} using sudo failed!"
    assert client.auth.sudo.run(
        u.name, "Secret123", command="/usr/bin/df"
    ), f"Running df as {u.name} using sudo failed!"
    assert not client.auth.sudo.run(
        u.name, "Secret123", command="/usr/bin/wc"
    ), f"Running wc as {u.name} using sudo passed!"


@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.ticket(jira=["RHEL-128212", "RHEL-1376"])
def test__regex_regex_in_command_parameter(client: Client):
    """
    :title: Regex in command parameter is working
    :setup:
        1. Create user "user-1"
        2. Create a sudo rule for user-1 with a regex /bin/ls ^/usr/.*$
    :steps:
        1. Run a /bin/ls command with parameter /usr/sbin
        2. Run a /bin/ls command with parameter /root
    :expectedresults:
        1. Command is executed successfully
        2. Command is not executed
    :customerscenario: True
    """
    if (
        client.host.compare_package_version({"major": 1, "minor": 9, "patch": 17, "prerelease": "p2"}, "sudo") < 0
        or client.host.distro_major < 9
    ):
        pytest.skip("Sudo version is less than 1.9.17p2")
    u = client.user("user-1").add(uid=10001, password="Secret123")
    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()
    client.sudorule("user-1-regex").add(user=u, command="/bin/ls ^/usr/.*$", host="ALL")
    assert client.auth.sudo.run(
        u.name, "Secret123", command="/bin/ls /usr/sbin"
    ), f"Running ls /usr/sbin as {u.name} using sudo failed!"
    assert not client.auth.sudo.run(
        u.name, "Secret123", command="/bin/ls /root"
    ), f"Running ls /root as {u.name} using sudo passed!"


@pytest.mark.topology(KnownTopology.BareClient)
@pytest.mark.ticket(jira=["RHEL-95850"])
@pytest.mark.parametrize("nopasswd", [True, False], ids=["nopasswd_true", "nopasswd_false"])
def test__ksh_piped_sudo_output_not_mangled(client: Client, nopasswd: bool):
    """
    :title: ksh piped sudo command does not mangle output
    :setup:
        1. Install ksh
        2. Create user "user-1"
        3. Create a sudo rule for user-1 with NOPASSWD enabled/disabled
        4. Enable SSSD sudo responder and start SSSD
    :steps:
        1. Run "ksh -c 'cat /etc/services | head -3'" as user-1
        2. Run "ksh -c 'sudo cat /etc/services | head -3'" as user-1 with and without password prompt
    :expectedresults:
        1. Command is executed successfully
        2. Output is not mangled and matches the non-sudo command output
    :customerscenario: True
    """
    client.host.conn.run("dnf install -y ksh")
    u = client.user("user-1").add(uid=10001, password="Secret123")
    client.sssd.common.local()
    client.sssd.common.sudo()
    client.sssd.start()
    client.sudorule("user-1-all").add(user=u, command="ALL", host="ALL", nopasswd=nopasswd)

    plain = client.host.conn.run(f"su - {u.name} -c \"ksh -c 'cat /etc/services | head -3'\"")
    sudo_command = (
        "sudo cat /etc/services | head -3"
        if nopasswd
        else "printf 'Secret123\\n' | sudo -S -p '' cat /etc/services | head -3"
    )
    sudoed = client.host.conn.run(f"su - {u.name} -c \"ksh -c '{sudo_command}'\"")

    assert plain.rc == 0, f"Running piped command in ksh as {u.name} failed!"
    assert sudoed.rc == 0, f"Running piped sudo command in ksh as {u.name} failed!"
    assert sudoed.stdout == plain.stdout, "Output from piped sudo command in ksh is mangled!"
