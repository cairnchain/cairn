# Writes the Windows release archive so that the same files give the same
# bytes: entries in sorted order, each dated SOURCE_DATE_EPOCH and given fixed
# permissions, with nothing taken from the machine that runs it.
#
#   python deploy/release-zip.py <directory> <folder in it> <archive>
#
# Called by deploy/release-build.sh. 7-Zip, which made this archive before,
# writes each file's times as the disk has them, and those differ on every
# machine that checks the repository out.

import os
import sys
import time
import zipfile


def main():
    directory, folder, archive = sys.argv[1:4]
    # A zip date cannot be earlier than 1980, and is read in no time zone.
    stamp = max(int(os.environ["SOURCE_DATE_EPOCH"]), 315532800)
    date = time.gmtime(stamp)[:6]
    names = [folder + "/"]
    for name in sorted(os.listdir(os.path.join(directory, folder))):
        names.append(folder + "/" + name)
    with zipfile.ZipFile(archive, "w") as out:
        for name in names:
            entry = zipfile.ZipInfo(name, date_time=date)
            entry.create_system = 3
            if name.endswith("/"):
                entry.external_attr = (0o40755 << 16) | 0x10
                out.writestr(entry, b"")
                continue
            program = name.endswith(".exe")
            entry.external_attr = (0o100755 if program else 0o100644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(directory, name), "rb") as source:
                out.writestr(entry, source.read(), compresslevel=9)


if __name__ == "__main__":
    main()
