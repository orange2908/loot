---
title: "Mutant - KubSTU CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "base64", "mutant", "kubstu-ctf", "ctf-writeup"]
summary: "Open the PDF raw and see that after all displayed object there is a hidden object #5."
source:
  name: "CTFtime writeup #40765"
  url: "https://ctftime.org/writeup/40765"
ctf:
  name: "KubSTU CTF"
  challenge: "Mutant"
---

## Metadata

- **CTF:** KubSTU CTF
- **Task:** Mutant
- **Author team:** μAGMA
- **CTFtime:** <https://ctftime.org/writeup/40765>

---
Open the PDF raw and see that after all displayed object there is a hidden object #5. The problem with it is the filter set. The only specified filter is `/FlateDecode` though you can see that it is clearly also encoded as ASCII85.

Write a simple Python script that decodes the data:

```  
import base64  
import zlib

data_a85 = r"""Gat%$gMS6)&:N^l>'U0`6.8h^RGj.,((^akM*\ob1<q0=in.j*fdK2b44Toqcbl`jcmgQJc;*!U;cT`qF1X3Y<:\'J07Que=Zr16^\u*PhOA_iO)?`nBSN,[*8M&'$/dkgn/[%KHA5K$[Pi4()<$h%rI](7lqRh1RGL*DIHL9Sn<j%MJab_lWt=-PeY=VcH]N-8q(]`Ho@kDCAUZeZ]dqs#6K\\#qn<j#3KK#=V);nbbq6>(]q_Mf4*Q#?>hN&JdnH%U,jrf=1]&R.o5,6_jYL:bdq=j+E'OF\5?-cQ2#pYJQbEJo\e%^RT_1q7OJj0=l7Ic,knF$qT)Tf`qCQBuYI(6sFY]\U:TQB9m9DSkj)p#`Kg^NsZcrurZgo*3ad5WR>XgFX`Y&B'`^IEG_-,"Wj10#YXI)-=!Qh,j9Wk@EGYR>dNP'-TZr80@,m@_c;`g?&HiV[&V5(\jkq&?bcb26#Y&NN(F&6TH\\)_^adFmP2L0A39b\\#\depM8a0V9ZF4A;O/uhl4UIS\l]LhkBKC'3Oul(>kr"e[aaDDW&5)]rN)LBXllZMD=U&]Z=2G^(7AIS'+Y\5:,>%Nm[-5Om+X5eEj'p*fChP%:8D=WO;&fmsJWqla*-X8$uhe$=4OGP->nYs.[#HRLC*]>MH]r^/3>RJQ1q[ad`lo[04#4e7'Hpf&Xg$VVXYj@:Kl7e)OYp5E+.A5^k$_<a3UOS4tk1DN]8UlMQ/n:WCCVg*esqS>HF(an9*MFt?pD3D"TjOQKbR&g&[(lS&WnhrlSGo6a]!<9#-?@]_"2[9dD")U_<"btu%onX$NH8,c&.MJ9($n__0n)U-jeHT5'%2E[ta5k2.ECC?U7Sno,F:UW<%*"\F5VK$5IUu\,edbDUncKc/_R3BJHD.A;t@FQ/agm\\_iQV*N_,[>X%:&#KM6H7F'dji4g:#!7<_j?=sEdkN=I_9_#69_adfnFlgU<jYRaHkj"?2:)8qU7dG(A?"<p^@&I7&>TdYV-ghXd,7(KVN+MX"loJAUSfs++@p8r"X*;=5s+_rZ')TkBM^<69hhQE`:8eX30V;Kmr53.+`P#9(<["PFZ,=1a:0u1,dgo-5_#h]TOTYV8cPb`o/[#YCm4;l^#bJ$&>W9O73HGWO"A--60a?6e2aD`^X0m?YB&Y6e+(t51k1H/*]J[l\DR(-kuIjQh;Sion1"InkCi'a]^#2>$kRdO.*-lI*#Doe0k2-V\GcF(ZR<,@f<Tj7=Ek@jnL"bVmJ(;$g5dhme,'O+1q2[qeC:edr/HsmWrr%0_at34nZGIiNjJ?2&RH_T:4O&H./4oc1]NP>#b(,RWl92]6<f$mJ9Jc[5iBM9m](=0o'7'r:Bo5dq^*Ur3)3"%(Y*#?+O*QqNmuA?Vg&Lh/K^1r9&+nF`1Tp]?Sp>m.Pet=50=jlg_MAkB>=^4_fZbKEb$Zh=54Sn,$DJmoskiSbojBA(HG4lXu^Z\Iu]
