# Third-party notices

This repository contains one file that is **not our work**: `restore-5.php`.

## What it is

`restore-5.php` is 1C-Bitrix's own site restore utility — the script normally
published as `restore.php` and distributed free of charge from:

    https://www.1c-bitrix.ru/download/files/scripts/restore.php

**Copyright in this file belongs to 1C-Bitrix.** It carries no copyright
header and no license grant of any kind. We make **no ownership claim over
any part of it**, and nothing in this repository should be read as one.

The copy retained here is an **older release** of that script. 1C-Bitrix
serves only the current release at the URL above; at the time of writing that
current release is 217,997 bytes, dated 2026-07-13, and is a substantially
different and much larger program than this one (~95 KB).

## Why an old version is retained

Bitrix backup archives and the restore script that consumes them are
contemporaneous: a backup produced by an old Bitrix product is restored by the
restore script of that era. Replacing the script with the current release does
not make an old archive restorable — it simply removes the tool that
understands it.

That matters in practice because the script **replaces itself**. On first load
the stock code performs a `HEAD` request against 1c-bitrix.ru, compares
`filesize(__FILE__)` against the published `Content-Length`, and on any
difference downloads the current release and `rename()`s it over `__FILE__`,
then redirects. Left enabled, simply opening the old script in a browser
destroys it and substitutes the current version, before any restore work
begins. Keeping a working copy therefore requires keeping a copy at all.

An operator restoring a legacy Bitrix installation who no longer has the
matching script has no way to obtain one from the vendor. This copy exists so
that such a restore remains possible.

## Our position on including it

We rely on fair use / fair dealing, in good faith, on the following basis:

- The file was, and its successor still is, distributed by the rights holder
  **free of charge to the general public** at a stable URL. This copy is an
  earlier release of that same freely-distributed utility, obtained through
  that channel. It is not leaked, paid, or access-restricted material.
- Its intended audience is **1C-Bitrix's own licensees**, restoring their own
  Bitrix installations. It remains useful to exactly that audience, for
  exactly that purpose — the only difference is that their product is old
  enough that the current script no longer serves them.
- Retention is for **interoperability and archival** of a superseded release,
  not substitution: this file cannot be used in place of any 1C-Bitrix
  product, competes with nothing 1C-Bitrix sells, and has no value to anyone
  who is not already running Bitrix software.
- The script's own design **anticipates wide copying** — it is meant to be
  uploaded to arbitrary servers, and it self-updates from the vendor precisely
  because copies are expected to be scattered and stale.
- There is **no market harm**: the file is given away, so no sale is displaced
  by this copy existing.

This is our good-faith position, not a legal determination, and fair-use
doctrine varies by jurisdiction. **If 1C-Bitrix objects, open an issue and we
will remove the file immediately, no argument.**

## Our modifications

We claim authorship only of the changes below — bug fixes and diagnostics to
an old release, nothing more. Each is marked in-file with a `wr-util` comment.
The surrounding program is unchanged.

1. **Self-update disabled.** The update block is commented out (not deleted,
   so it stays readable and reversible). As shipped it overwrites this old
   script with the current release on first load, which defeats the entire
   purpose of retaining an old release. Nothing downstream depends on it: it
   only ever set `$strErrMsg` or terminated the request.

2. **Filename encoding detection fixed.** `CTar::DecodeFileName()` decided an
   archive's filename encoding with a single probe, `/[\xe0\xe1\xe3-\xff]/`,
   which matches only cp1251 Russian **lowercase** — it does not even include
   `в` (0xE2). A name in uppercase Cyrillic satisfies neither that test nor
   the utf8→cp1251 fallback test, and the restore aborts outright with
   "Unable to continue due to error in encoding detection of file name".

   Observed on a real archive, on the entry `upload/iblock/944/140УД12.pdf`:
   the raw bytes `d0 a3 d0 94` are valid UTF-8 for `У`/`Д`, and transcode
   correctly to cp1251 `d3 c4` — but both are below `0xE0`, so both probes
   miss. The archive is well-formed; only the detection is wrong.

   Fixed by testing **UTF-8 validity first**, then the full cp1251 Cyrillic
   range `[\xa8\xb8\xc0-\xff]`. Order is essential: merely widening the
   original probe makes the raw UTF-8 lead byte `0xD0` match first, which
   would mislabel every UTF-8 Cyrillic name as cp1251 and silently corrupt
   them — failing quietly instead of loudly, which is worse.

3. **Encoding-name comparison normalised.** `EncCurrent` is spelled `utf-8`
   while `EncRemote` is spelled `utf8`, so the equality check never matched in
   the common Linux→Linux UTF-8 case and every filename took a redundant
   `mb_convert_encoding('utf-8' <- 'utf8')` round trip. That is an identity
   transform, so nothing was corrupted, but skipping it makes extracted names
   provably byte-identical to the source rather than merely expected to be.

4. **Expanded diagnostics** on the encoding-detection failure path: the raw
   filename, its bytes in hex, its non-ASCII bytes, whether it is valid UTF-8,
   its utf8→cp1251 transcoding, and the probe used. The stock message names
   neither the file nor the bytes, making the failure impossible to act on.

## Everything else in this repository

All other files — `restore-42.php`, `mini-backup.php`, `mini-download.php`,
`mini-restore.php` and supporting files — are our own work and are not covered
by this notice.

## No warranty

These scripts dump databases, overwrite document roots and delete files. They
are provided as-is, without warranty of any kind. Use at your own risk, and
take your own backups first.
