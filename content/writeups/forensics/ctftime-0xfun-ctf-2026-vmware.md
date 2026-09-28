---
title: "VMware - 0xFUN CTF 2026"
category: "forensics"
subcategory: "vm"
type: "writeup"
tags: ["forensics", "custom-vm", "vmware", "vm", "0xfun-ctf", "0xfun-ctf-2026", "2026", "ctf-writeup"]
summary: "![ Sign in via Google  ](https://hackmd.io/auth/google)  ![ Sign in via Facebook  ](https://hackmd.io/auth/facebook)  ![ Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter)  ![ Sign in via GitHu"
source:
  name: "CTFtime writeup #40681"
  url: "https://ctftime.org/writeup/40681"
original_source: "https://hackmd.io/@EPIDaX-NTqKc4Xpu5lWmVQ/HJmv07Av-l"
ctf:
  name: "0xFUN CTF 2026"
  year: 2026
  challenge: "VMware"
---

## Metadata

- **CTF:** 0xFUN CTF 2026
- **Task:** VMware
- **Author team:** LappungCTF{}
- **CTFtime tags:** forensics
- **CTFtime:** <https://ctftime.org/writeup/40681>
- **Original writeup:** <https://hackmd.io/@EPIDaX-NTqKc4Xpu5lWmVQ/HJmv07Av-l>

---
# 0xfunctf - Forensic (vmware) ## ![image](https://hackmd.io/_uploads/Hkc1xNCwZg.png) ## Overview given a 5.2 GB Kali Linux virtual machine challenge ![image](https://hackmd.io/_uploads/rknoxNRDbx.png) After extracting, the size exploded to approximately 15 GB ![image](https://hackmd.io/_uploads/HJExMVRDWg.png) So the intersection is here, we need to access the virtual Kali Linux, but we don't know the password. ## Step by Step ### Simple Solution To complete this challenge we need to install qemu utils first. Because here I am using WSL, so we need a tool to be able to read `.vmdk` (vmware format), with `qemu-utils` we can read many types of disk formats. ```zsh sudo apt install qemu-utils -y ``` After the installation is complete, before we use `qemu-utils` we need to `modprobe` it first, because we need to activate the `NBD` kernel module which can interact with disk files. ```bash sudo modprobe nbd max_part=8 ``` we use max_part=8 to move 8 partitions in one NBD device. Next we will start mapping the virtual disk file to a block in my linux. ```bash sudo qemu-nbd --connect=/dev/nbd0 kali-linux-2025.4-vmware-amd64.vmdk ``` `--connect=/dev/nbd0` used so that the system plugs a virtual disk into it, and when it is run it will behave like a hard disk. After connecting, so that we can modify the contents, we need to open the contents using mounting, if we don't do this we can't see or edit the contents ```bash mkdir temp_kali && sudo mount /dev/nbd0p1 temp_kali ``` see the dir ```bash yunx1ao   mnt/c/../../../../0xfunctf26  🌸  🌸 ls -la temp_kali total 976660 drwxr-xr-x 18 root root 4096 Jan 1 05:20 . drwxrwxrwx 1 spl1t4t3rminal spl1t4t3rminal 4096 Feb 15 00:56 .. lrwxrwxrwx 1 root root 7 Nov 10 16:50 bin -> usr/bin drwxr-xr-x 3 root root 4096 Dec 3 10:12 boot drwxr-xr-x 4 root root 4096 Dec 3 09:29 dev drwxr-xr-x 181 root root 12288 Jan 1 05:24 etc -rw-r--r-- 1 root root 41 Jan 1 05:20 .flag.txt drwxr-xr-x 3 root root 4096 Dec 3 09:36 home lrwxrwxrwx 1 root root 33 Dec 3 10:11 initrd.img -> boot/initrd.img-6.16.8+kali-amd64 lrwxrwxrwx 1 root root 33 Dec 3 10:11 initrd.img.old -> boot/initrd.img-6.16.8+kali-amd64 lrwxrwxrwx 1 root root 7 Nov 10 16:50 lib -> usr/lib lrwxrwxrwx 1 root root 9 Dec 3 09:33 lib32 -> usr/lib32 lrwxrwxrwx 1 root root 9 Nov 10 16:50 lib64 -> usr/lib64 drwx------ 2 root root 16384 Dec 3 10:11 lost+found drwxr-xr-x 2 root root 4096 Dec 3 09:29 media drwxr-xr-x 2 root root 4096 Dec 3 09:29 mnt drwxr-xr-x 3 root root 4096 Dec 3 09:33 opt drwxr-xr-x 2 root root 4096 Nov 10 16:50 proc drwx------ 5 root root 4096 Jan 1 05:20 root drwxr-xr-x 8 root root 4096 Dec 3 09:30 run lrwxrwxrwx 1 root root 8 Nov 10 16:50 sbin -> usr/sbin drwxr-xr-x 3 root root 4096 Dec 3 09:34 srv -rw------- 1 root root 1000000000 Dec 3 10:11 swap drwxr-xr-x 2 root root 4096 Nov 10 16:50 sys drwxrwxrwt 2 root root 4096 Dec 3 09:29 tmp drwxr-xr-x 15 root root 4096 Dec 3 09:33 usr drwxr-xr-x 12 root root 4096 Jan 1 05:19 var lrwxrwxrwx 1 root root 30 Dec 3 10:11 vmlinuz -> boot/vmlinuz-6.16.8+kali-amd64 lrwxrwxrwx 1 root root 30 Dec 3 10:11 vmlinuz.old -> boot/vmlinuz-6.16.8+kali-amd64 ``` After this we can see that there is a flag there .flag.txt for a simple solution we can copy it to that file ``` yunx1ao   mnt/c/../../../../0xfunctf26  🌸  🌸 cp temp_kali/.flag.txt ../ ``` and read the file ``` yunx1ao   mnt/c/../../../../0xfunctf26  🌸  🌸 cat .flag.txt 0xfun{w1th0ut_p2ssw0rd_1s_cr4zy_a2_h3ll} ``` \--- ### Using Virtual Box (password bypass) but because the main purpose of this challenge is that we need to be able to exercise privileges in a way that without an unknown password we can enter the virtual machine. if we check `/etc/shadow` ``` 🌸 sudo cat temp_kali/etc/shadow | grep "kali" kali:$y$j9T$xhXuOR0xfzrO0p0wraI0v.$4b0Rf7Uu3IepA81B9lxZoU1bCRXaVKPiL/P/3qUpv10:20453:0:99999:7::: ``` The `$y$` symbol at the beginning indicates that the system uses the Yescrypt encryption algorithm. This is the latest security standard on Kali Linux which is very strong and difficult to crack manually. does that sound scary?, oh of course not because we can edit it and then delete the hash ``` sudo sed -i 's/^kali:[^:]*:/kali::/' temp_kali/etc/shadow. ``` after deleting the hash we try to verify ``` yunx1ao   mnt/c/../../../../0xfunctf26  🌸  🌸 sudo cat temp_kali/etc/shadow | grep "kali" kali::20453:0:99999:7::: ``` and yes success. Next, open Oracle Virtual Box, create a VM and insert the hard disk. #### Configuration \- virtual Machina name and operating system ![image](https://hackmd.io/_uploads/rJna9ECwbg.png) use linux！ \- Set up unattended guest OS installation ![image](https://hackmd.io/_uploads/r12zoVRP-g.png) use default settings \- Specify Virtal Hardware ![image](https://hackmd.io/_uploads/BykSsVRwWl.png) use default settings \- Specify Virtual Hard Disk ![image](https://hackmd.io/_uploads/SyeEh4Awbx.png) we use that `kali-linux-2025.4-vmware-amd64.vmdk` ![image](https://hackmd.io/_uploads/HkgCGnVCv-g.png) and finish then after it has been successfully created, we can just go straight to the gas to enter the VM ![image](https://hackmd.io/_uploads/S1d3nVAvZg.png) if it works it should appear like that, i hope there is no problem with you guys. Next, if you are asked for a username and password, just fill in the username and leave the **password** field blank. like this ![image](https://hackmd.io/_uploads/ryO7TNCD-g.png) then press login, andd boom ![image](https://hackmd.io/_uploads/rkIwTERPWg.png) we got it, next we can read the flag too ![image](https://hackmd.io/_uploads/ByHiaVAD-g.png) ## Flag ``` 0xfun{w1th0ut_p2ssw0rd_1s_cr4zy_a2_h3ll} ``` \--- ## Save your storage first 🗿 ![image](https://hackmd.io/_uploads/rJ3J0VRv-g.png) sh1t, because it's successful, next don't forget to clean it, it's really disgusting. delete the machine first ```bash rmdir temp_kali sudo modprobe -r nbd cd .. rm -rf 0xfunctf26 ``` \--- ![image](https://hackmd.io/_uploads/BJUyyBRPWe.png) it is better now 🗿

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
