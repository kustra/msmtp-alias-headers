# msmtp-alias-headers

A `sendmail` for [msmtp](https://marlam.de/msmtp/) that also rewrites local addresses in the
`To`, `Cc` and `Bcc` headers through `/etc/aliases`.

## The problem

System tools mail local names: cron mails a job's output to `root`, `mail -s … root` writes
`To: root`, unattended-upgrades and smartd mail `root`. msmtp's `aliases` setting turns `root` into a
real address, but only in the SMTP envelope. The message keeps its `To: root` header, and some
servers reject a header address without a domain. Amazon SES answers:

```
554 Transaction failed: Missing final '@domain'
```

GMX and Strato are reported to reject such mail as well
([msmtp issue #98](https://github.com/marlam/msmtp/issues/98)). msmtp's own remedies replace the
recipient headers wholesale:

- `undisclosed_recipients on` replaces `To`, `Cc` and `Bcc` with `To: undisclosed-recipients:;`.
- `set_to_header on` (msmtp 1.8.29 and later; Debian 13 ships 1.8.28) replaces them with one new
  `To` header that lists every envelope recipient: `Cc` recipients move into `To`, display names
  are lost, and `Bcc` recipients become visible to everyone.

This script rewrites only the local addresses and leaves the rest of each header as it was.

## What it does

`msmtp-alias-headers` reads the message from standard input. In the `To`, `Cc` and `Bcc` headers it
expands every address without an `@` through `/etc/aliases`, then runs `/usr/bin/msmtp` with its own
arguments and exits with msmtp's status.

```
To: root                       →  To: owner@example.com
Cc: Ops <lk>, ann@example.com  →  Cc: Ops <owner@example.com>, ann@example.com
```

The aliases file is read as msmtp reads it (msmtp's `src/aliases.c`):

- `name: a@example.com, b@example.com` maps a local name to up to 32 addresses; `#` starts a
  comment;
- `default:` matches any local name that has no line of its own; a local name with neither stays as
  it is;
- a target that is itself a local name is expanded again, at most 16 levels deep;
- a line without exactly one `:`, a name containing `@`, a duplicate name or a line of 511 bytes or
  more (its newline included) is an error, as in msmtp, and so is an empty address.

Everything else passes unchanged: the body, the other headers, the line endings, display names, and
any header that holds no local address. The aliases file is read only when a header holds a local
address.

When the rewrite fails (a missing or invalid `/etc/aliases`, an alias loop, a header it cannot
rebuild), the script logs a warning to standard error and to syslog (facility `mail`) and hands the
message to msmtp unchanged, so that the mail fares as it would with msmtp alone. If msmtp cannot be
started it exits 69 (`EX_UNAVAILABLE`); if msmtp is
killed by a signal it exits 128 plus the signal's number. Options with which msmtp sends nothing
(`--version`, `--help`, `--pretend`, `--serverinfo`, `--configure`, `--rmqs`) go straight to msmtp
without reading standard input.

## Requirements

- Python 3.10 or later, standard library only, with the fix for
  [CVE-2023-27043](https://github.com/python/cpython/issues/102988) in `email.utils.getaddresses`
  (3.10.15, 3.11.10, 3.12.6, 3.13 and later, and current Debian and Ubuntu builds). Without it the
  parser can read one address as two recipients, so the script leaves the headers unchanged and logs
  a warning.
- msmtp with `aliases /etc/aliases` in its configuration, so that the envelope gets the same
  expansion.
- An `/etc/aliases` file; `msmtp-mta` does not create one. For example:

  ```
  default: you@example.com
  ```

## Installation

On Debian and Ubuntu with `msmtp-mta`, which provides `/usr/sbin/sendmail` and `/usr/lib/sendmail`
as links to msmtp:

```sh
sudo install -m 0755 msmtp-alias-headers /usr/local/sbin/msmtp-alias-headers
for p in /usr/sbin/sendmail /usr/lib/sendmail; do
  if [ "$(readlink -f "$p")" = /usr/bin/msmtp ]; then
    sudo dpkg-divert --local --rename --divert "$p.msmtp" --add "$p"
    sudo ln -s /usr/local/sbin/msmtp-alias-headers "$p"
  else
    echo "$p is not msmtp's; left alone"
  fi
done
```

The diversion keeps an upgrade of `msmtp-mta` from replacing the links. Check it with a mail to a
local name:

```sh
printf 'To: root\nSubject: test\n\ntest\n' | /usr/sbin/sendmail -t
```

To undo it (safe to run more than once):

```sh
for p in /usr/sbin/sendmail /usr/lib/sendmail; do
  if [ "$(readlink "$p")" = /usr/local/sbin/msmtp-alias-headers ]; then
    sudo rm "$p" && sudo dpkg-divert --local --rename --remove "$p"
  fi
done
sudo rm -f /usr/local/sbin/msmtp-alias-headers
```

On other systems, put the script wherever the tools that send mail look for `sendmail`. The paths
of the aliases file and of msmtp are the constants `ALIASES` and `MSMTP` at the top of the script.

## Limitations

- Only `To`, `Cc` and `Bcc` are rewritten. `From` is msmtp's business (`from` and
  `set_from_header`); the `Resent-` headers are not touched.
- A header with a group (`undisclosed-recipients:;`, `admins: root, lk;`) or one the parser rejects
  is left as it is, since rebuilding it would drop that part.
- A rewritten header is written on one line, and an address that several aliases lead to appears
  once per alias.
- Mail submitted to `msmtpd` goes to `msmtp`, not to `sendmail`, and is not rewritten.

## A note on msmtp's envelope expansion

In msmtp's alias expansion, a local recipient that directly follows an expanded one is passed on
unexpanded: `msmtp -i root lk ann@example.com` sends to the alias of `root`, to `lk` and to
`ann@example.com`. The headers this script writes are not affected, and with `-t` msmtp takes the
recipients from those headers, which avoids the problem.

## Tests

```sh
/usr/bin/python3 -I test_msmtp_alias_headers.py
```

Run them with the Python that will run the script. On a Python without the CVE-2023-27043 fix the
rewriting tests are skipped.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

The program is provided "as is", without warranty of any kind, and to the extent permitted by
applicable law its author accepts no liability for any damage arising from its use, lost mail
included (sections 15 and 16 of the license).
