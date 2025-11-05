#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dell PowerConnect SSH checker (pexpect)
- Использует старые KEX/HostKey/Cipher (как в задаче)
- Ожидает промпт "User Name:", затем "Password:", затем приглашение CLI
- Умеет проверять конкретный промпт (например, "172.18.0.18_E8_LO#") или общий вид [>#]
"""

import argparse
import pexpect
import re
from typing import Tuple, Optional


SSH_OPTIONS = (
    "-oKexAlgorithms=+diffie-hellman-group-exchange-sha1 "
    "-oHostKeyAlgorithms=+ssh-rsa "
    "-oCiphers=+aes128-cbc "
    "-oStrictHostKeyChecking=no "
    "-oUserKnownHostsFile=/dev/null "
    "-oPubkeyAuthentication=no "
    "-oPreferredAuthentications=password"
)

USERNAME_PROMPTS = [r"[Uu]ser ?[Nn]ame:", r"login:", r"username:"]
PASSWORD_PROMPTS = [r"[Pp]assword:"]

# Достаточно гибкий общий шаблон приглашения коммутатора:
GENERIC_PROMPT_RE = r"[A-Za-z0-9_\-.:/@()\[\]]+[>#]\s*$"

def expect_any(child, patterns, timeout: int) -> int:
    """Ожидает любой из regex-паттернов из списка."""
    return child.expect([pexpect.TIMEOUT, pexpect.EOF] + [re.compile(p) for p in patterns], timeout=timeout)

def check_host(
    host: str,
    login: str,
    password: str,
    timeout: int = 8,
    exact_prompt: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Возвращает (ok, message).
    ok = True, если удалось залогиниться и увидеть приглашение CLI.
    """
    ssh_cmd = f"ssh {SSH_OPTIONS} -l {login} {host}"
    try:
        child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=timeout)

        # 1) User Name:
        idx = expect_any(child, USERNAME_PROMPTS, timeout)
        if idx == 0:
            return False, f"{host}: timeout (ожидали User Name:)"
        if idx == 1:
            return False, f"{host}: соединение закрыто при ожидании User Name:"
        child.sendline(login)

        # 2) Password:
        idx = expect_any(child, PASSWORD_PROMPTS, timeout)
        if idx == 0:
            return False, f"{host}: timeout (ожидали Password:)"
        if idx == 1:
            return False, f"{host}: соединение закрыто при ожидании Password:"
        child.sendline(password)

        # 3) Успешный вход -> ждём приглашение
        if exact_prompt:
            # Проверяем конкретную строку приглашения
            prompt_re = re.escape(exact_prompt) + r"\s*$"
        else:
            # Общий вид приглашения для PowerConnect
            prompt_re = GENERIC_PROMPT_RE

        # Также ловим неправильный логин/пароль
        bad_login_res = [r"[Ii]nvalid|[Ll]ogin incorrect|authentication failed"]

        idx = child.expect(
            [pexpect.TIMEOUT, pexpect.EOF, re.compile(prompt_re), re.compile(bad_login_res[0])],
            timeout=timeout,
        )

        if idx == 2:
            # Успех, аккуратно выходим
            try:
                child.sendline("exit")
                child.close(force=True)
            except Exception:
                pass
            shown = exact_prompt if exact_prompt else "<generic prompt>"
            return True, f"{host}: OK (получили приглашение {shown})"

        if idx == 3:
            return False, f"{host}: неверные логин/пароль"

        if idx == 0:
            return False, f"{host}: timeout (ожидали приглашение CLI)"
        if idx == 1:
            return False, f"{host}: соединение закрыто до появления приглашения"

    except Exception as e:
        return False, f"{host}: ошибка запуска SSH: {e}"

    return False, f"{host}: неизвестная ошибка"

def main():
    parser = argparse.ArgumentParser(description="Проверка SSH доступа к Dell PowerConnect (pexpect).")
    parser.add_argument("hosts", nargs="+", help="IP/имя хоста(ов) для проверки")
    parser.add_argument("--login", default="netadmin", help="Имя пользователя (по умолчанию: netadmin)")
    parser.add_argument("--password", default="12345", help="Пароль (по умолчанию: 12345)")
    parser.add_argument("--timeout", type=int, default=8, help="Таймаут ожиданий, сек (по умолчанию: 8)")
    parser.add_argument(
        "--prompt",
        help="Точный ожидаемый промпт (например: 172.18.0.18_E8_LO#). "
             "Если не указан — проверяется общий вид приглашения [>#]."
    )

    args = parser.parse_args()

    any_fail = False
    for h in args.hosts:
        ok, msg = check_host(
            host=h,
            login=args.login,
            password=args.password,
            timeout=args.timeout,
            exact_prompt=args.prompt,
        )
        print(msg)
        if not ok:
            any_fail = True

    # Код возврата полезен для CI/скриптов
    raise SystemExit(0 if not any_fail else 2)

if __name__ == "__main__":
    main()
