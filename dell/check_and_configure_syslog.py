#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dell PowerConnect SSH checker & syslog configurator (pexpect)

- Проверяет доступность по SSH (с legacy алгоритмами)
- При успешном входе добавляет строку syslog (logging 172.18.11.20)
- Сохраняет конфигурацию (copy running-config startup-config)
"""

import argparse
import pexpect
import re
from typing import Tuple, Optional

SSH_OPTIONS = (
    "-oKexAlgorithms=+diffie-hellman-group1-sha1 "
    "-oHostKeyAlgorithms=+ssh-dss,ssh-rsa "
    "-oPubkeyAcceptedKeyTypes=+ssh-dss "
    "-oCiphers=+3des-cbc "
    "-oStrictHostKeyChecking=no "
    "-oUserKnownHostsFile=/dev/null "
    "-oPubkeyAuthentication=no "
    "-oPreferredAuthentications=password"
)

USERNAME_PROMPTS = [r"[Uu]ser ?[Nn]ame:", r"login:", r"username:"]
PASSWORD_PROMPTS = [r"[Pp]assword:"]
GENERIC_PROMPT_RE = r"[A-Za-z0-9_\-.:/@()\[\]]+[>#]\s*$"


def expect_any(child: pexpect.spawn, patterns, timeout: int) -> int:
    return child.expect([pexpect.TIMEOUT, pexpect.EOF] + [re.compile(p) for p in patterns], timeout=timeout)


def configure_syslog(child: pexpect.spawn, syslog_ip: str, timeout: int = 5) -> bool:
    """Выполняет команды конфигурации syslog"""
    try:
        child.sendline("conf")
        child.expect(re.compile(r"\(config\)#"), timeout=timeout)
        child.sendline(f"logging {syslog_ip}")
        child.expect(re.compile(r"\(config\)#"), timeout=timeout)
        child.sendline("exit")
        child.expect(re.compile(GENERIC_PROMPT_RE), timeout=timeout)
        child.sendline("copy running-config startup-config")
        idx = child.expect([
            re.compile(r"Overwrite file .*Yes.*no.*", re.IGNORECASE),
            re.compile(GENERIC_PROMPT_RE),
            pexpect.TIMEOUT,
            pexpect.EOF
        ], timeout=timeout)

        if idx == 0:
            # Коммутатор спросил подтверждение
            child.sendline("Yes")
            child.expect(re.compile(GENERIC_PROMPT_RE), timeout=timeout)
        elif idx in (2, 3):
            return False  # таймаут или разрыв
        # idx == 1 → приглашение появилось без вопроса — значит успешно

        return True
    except Exception:
        return False


def check_and_configure(host: str, login: str, password: str, syslog_ip: str, timeout: int = 8) -> Tuple[bool, str]:
    ssh_cmd = f"ssh {SSH_OPTIONS} -l {login} {host}"
    try:
        child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=timeout)

        # --- Login sequence ---
        idx = expect_any(child, USERNAME_PROMPTS, timeout)
        if idx in (0, 1):
            return False, f"{host}: timeout при ожидании 'User Name:'"
        child.sendline(login)

        idx = expect_any(child, PASSWORD_PROMPTS, timeout)
        if idx in (0, 1):
            return False, f"{host}: timeout при ожидании 'Password:'"
        child.sendline(password)

        # --- CLI prompt ---
        idx = child.expect([pexpect.TIMEOUT, pexpect.EOF, re.compile(GENERIC_PROMPT_RE)], timeout=timeout)
        if idx == 2:
            prompt = child.match.group(0).strip()
            # --- Конфигурация syslog ---
            if configure_syslog(child, syslog_ip, timeout=timeout):
                child.sendline("exit")
                child.close(force=True)
                return True, f"{host}: OK (добавлен syslog {syslog_ip})"
            else:
                child.sendline("exit")
                child.close(force=True)
                return False, f"{host}: ошибка при выполнении команд конфигурации"
        else:
            return False, f"{host}: не дождались приглашения CLI"

    except Exception as e:
        return False, f"{host}: ошибка подключения: {e}"


def main():
    parser = argparse.ArgumentParser(description="Проверка SSH и настройка syslog на Dell PowerConnect.")
    parser.add_argument("hosts", nargs="+", help="IP/имена хостов")
    parser.add_argument("--login", default="netadmin", help="Имя пользователя (по умолчанию netadmin)")
    parser.add_argument("--password", default="12345", help="Пароль (по умолчанию 12345)")
    parser.add_argument("--syslog-ip", default="172.18.11.20", help="Адрес syslog-сервера (по умолчанию 172.18.11.20)")
    parser.add_argument("--timeout", type=int, default=8, help="Таймаут ожидания (сек)")

    args = parser.parse_args()

    any_fail = False
    for host in args.hosts:
        ok, msg = check_and_configure(
            host=host,
            login=args.login,
            password=args.password,
            syslog_ip=args.syslog_ip,
            timeout=args.timeout,
        )
        print(msg)
        if not ok:
            any_fail = True

    raise SystemExit(0 if not any_fail else 2)


if __name__ == "__main__":
    main()
