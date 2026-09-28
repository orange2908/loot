---
title: "sess.io - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "prng"
type: "writeup"
tags: ["md5", "web", "prng", "mt19937", "sess", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "The Sess.io challenge is an interesting Capture The Flag (CTF) problem that tests knowledge in exploiting pseudo-random number generation (PRNG) weaknesses, seed reversibility, and cryptographic manip"
source:
  name: "CTFtime writeup #40421"
  url: "https://ctftime.org/writeup/40421"
original_source: "https://blog.hitc.at/posts/ctf/nullcon-hackim-ctf-goa-2025/sess_io/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "sess.io"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** sess.io
- **Author team:** fish3r
- **CTFtime tags:** md5, web, prng
- **CTFtime:** <https://ctftime.org/writeup/40421>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/nullcon-hackim-ctf-goa-2025/sess_io/>

---
## Introduction

### Context Explanation

The **[Sess.io](http://Sess.io)** challenge is an interesting Capture The Flag (CTF) problem that tests knowledge in exploiting pseudo-random number generation (PRNG) weaknesses, seed reversibility, and cryptographic manipulation. The challenge presents a minimalist web page where users can sign up by providing a username and a password. The "magic" happens in the backend, where the user-provided credentials are used to generate a session ID that is tightly coupled with the system's flag. Understanding and manipulating this relationship allows us to recover the flag.

### Directive

Our goal is to reverse-engineer how the session ID is generated so we can extract pieces of the flag chunk by chunk. The ultimate objective is to reconstruct the entire flag step by step by exploiting the function's reliance on the PHP `mt_rand()` PRNG seeded with parts of the flag.

\---

## Solution

### Analyzing the Source Code

The PHP code provided by the challenge is fully accessible via the `?source` endpoint.

```php

```

From this code, we can deduce the following critical points:  
1\. The `$FLAG` is divided into chunks of 4 characters via `$SEEDS = str_split($FLAG, 4);`.  
2\. The PRNG (`mt_rand`) is seeded by a value derived from `$SEEDS`. Specifically:  
\- The index in `$SEEDS` depends on the first character of the MD5 hash of the input.   
\- The selected seed value is calculated as `intval(bin2hex($SEEDS[index]), 16)`.  
3\. The function `session_id_secure` generates a random 1000-character string using a seeded PRNG, selecting characters randomly from the `ALPHA` array.

Thus, the goal becomes reversing this process:  
1\. Determine which `$SEEDS` chunk is selected based on MD5 values.  
2\. Reconstruct the seed.  
3\. Use the seed's value to deduce the flag chunk by chunk.

\---

## Exploitation

### Step 1: Identifying MD5-Based Index

The key to exploiting the challenge lies in the calculation done with the MD5 hash and its relationship with `$SEEDS`. Let's break it down step by step.

\---

#### How the Index is Determined

In the source code, the following line calculates the index of the `$SEEDS` array that will be used to seed the PRNG:

```php  
$SEEDS[md5($id)[0] % (count($SEEDS))]  
```

Here's what this means:

1\. **`md5($id)`**: The MD5 hash of the input `$id`, where `$id = $_POST['username'] . $_POST['password']`, is computed. This results in a 128-bit (32-character hexadecimal string) hash.

For example, if `$id = "ba"`, then `md5("ba")` could be something like `"07159c47ee1b19ae4fb9c40d480856c4"`.

2\. **`md5($id)[0]`**: The first character of the MD5 hash is extracted. This is crucial because the characters in MD5 hashes are hexadecimal (i.e., `0-9` and `a-f`).

3\. **`md5($id)[0] % (count($SEEDS))`**: The first character is interpreted as a hexadecimal value. It is then converted to its decimal equivalent and used in a modulo operation with the size of the `$SEEDS` array.

\- For example, suppose `md5($id)[0] = "0"` (hexadecimal). Its decimal equivalent is `0`.  
\- If there are 10 chunks in `$SEEDS` (`count($SEEDS) = 10`), we calculate `0 % 10 = 0`. This maps to `$SEEDS[0]`.

This operation ensures that the first chunk of `$SEEDS` (i.e., index `0`) is selected for seeding the PRNG.

\---

#### Why the First Character Matters

The goal is to control which part of the `$SEEDS` array is used to seed the PRNG. To do this, we need inputs (`username` and `password`) such that the **first character** of the MD5 hash is a specific value, allowing us to select a specific chunk of `$SEEDS`.

The challenge is that the MD5 function is deterministic but complex, so predicting the first character requires brute force. By trying many different combinations of `username` and `password`, we can find inputs such that the first character of their MD5 hash is consistent with our target.

\---

#### Mapping First Characters to Decimal Values

Since MD5 hashes are hexadecimal, the possible first characters are:  
\- `0-9`: These directly translate to decimal values `0-9`.  
\- `a-f`: These correspond to decimal values `10-15`.

For the purpose of extracting the flag, we are primarily interested in values `0-9` because they correspond to indices in `$SEEDS`. If the flag produces at least 10 chunks, each chunk will be mapped to one of these 10 indices.

For example:  
\- If the first character of the MD5 hash is `"0"`, the decimal value is `0`, so we map to `$SEEDS[0]`.  
\- If the first character is `"1"`, the decimal value is `1`, so we map to `$SEEDS[1]`.  
\- This continues up to `"9"`, which maps to `$SEEDS[9]`.

To exploit this, we want to generate combinations of `username` and `password` such that `md5($id)[0]` cycles through these specific values from `0` to `9`.

\---

#### Brute Forcing Valid Combinations

To achieve the above goal, I wrote a PHP script that iterates over two-character combinations of alphanumeric characters (`a-z`, `0-9`, etc.) for simplicity. For each combination, it computes the MD5 hash and checks whether the first character corresponds to a target value (`0, 1, 2, ..., 9`).

```php  
$combo,  
'hash' => $hash  
];  
break 2; // Move to next digit when a combination is found  
}  
}  
}  
}  
  
return $results;  
}

$combinations = generateCombinations();

// Display results  
foreach ($combinations as $digit => $result) {  
echo "Digit $digit : Combination '{$result['combo']}' -> Hash: {$result['hash']}\n";  
}

?>  
```

Here is the output from the script:

```  
Digit 0 : Combination 'ba' -> Hash: 07159c47ee1b19ae4fb9c40d480856c4  
Digit 1 : Combination 'ab' -> Hash: 187ef4436122d1cc2f40dc2b92f0eba0  
Digit 2 : Combination 'bb' -> Hash: 21ad0bd836b90d08f4cf640b4c298e7c  
Digit 3 : Combination 'ah' -> Hash: 3cf4046014cbdfaa7ea8e6904ab04608  
Digit 4 : Combination 'aa' -> Hash: 4124bc0a9335c27f086f24ba207a4912  
Digit 5 : Combination 'ad' -> Hash: 523af537946b79c4f8369ed39ba78605  
Digit 6 : Combination 'ap' -> Hash: 62c428533830d84fd8bc77bf402512fc  
Digit 7 : Combination 'at' -> Hash: 7d0db380a5b95a8ba1da0bca241abda1  
Digit 8 : Combination 'au' -> Hash: 8bcc25c96aa5a71f7a76309077753e67  
Digit 9 : Combination 'al' -> Hash: 97282b278e5d51866f8e57204e4820e5  
```

\---

### Step 2: Extracting Sessions and Reversing the Seed

The core of the challenge centers around reversing the pseudo-random number generation (PRNG) that's used to generate the session ID. Since PHP uses the Mersenne Twister PRNG for `mt_rand()`, it is possible to reverse-engineer the initial seed used in the random number generation if we have enough of the output. The tool **`php_mt_seed`** allows us to achieve this. Here's a deeper explanation of why and how it works.

\---

#### Why Use `php_mt_seed`?

In the PHP code, the session ID is generated using the `session_id_secure` function, which is based on the output of `mt_rand()`:

```php  
for($i=0; $i<1000; $i++) {  
$id .= ALPHA[mt_rand(0, count(ALPHA) - 1)];  
}  
```

\- `ALPHA` is a predefined array: `["a", "b", "c", ..., "z", "0", "1", ..., "9", "_", "-"]`. This gives `count(ALPHA) - 1 = 37`.  
\- For each iteration of the loop, `mt_rand(0, 37)` generates a random number between 0 and 37, indexing into the `ALPHA` array to append a random character to the session ID.

Because `mt_rand()` is deterministic when seeded via `mt_srand()`, the sequence of random numbers it generates depends entirely on the **initial seed**. If we know enough output values from `mt_rand()`, we can reverse-engineer the seed with a tool like **`php_mt_seed`**.

Reversing the seed is crucial because the seed is derived from the flag itself (`intval(bin2hex($SEEDS[i]), 16)`), meaning recovering the seed reveals part of the flag.

\---

#### How `php_mt_seed` Works

`php_mt_seed` is a utility specifically designed to reverse the Mersenne Twister PRNG seed used by PHP. To reverse the PRNG and recover the seed, we need:  
1\. A sequence of numbers generated by `mt_rand()`, and  
2\. The exact range of those numbers (`min` and `max` values used in `mt_rand()`).

In our case:  
\- The outputs are the **indices** of the `ALPHA` array.  
\- Since `mt_rand(0, 37)` is used, the range of possible numbers is from **0 to 37**.

The tool needs at least 10-15 consecutive PRNG outputs to reliably reverse the seed. Because the session ID is 1000 characters long, we have more than enough data to begin reversing the seed.

\---

#### Generating Sessions via the Login Form

After finding valid `username` and `password` combinations, we can utilize them to generate session IDs by leveraging the server's login form. The process involves using the credentials to compute the corresponding MD5 hash, which influences the selection of specific chunks of seeds (`SEED[0]`, `SEED[1]`, etc.). These seeds are then used internally by the server to generate a session ID with the help of `mt_rand()`.

To generate a session, we initiate a login request via the web application using the known credentials. Upon a successful login, the server creates a session and assigns it to an identifier, typically stored in the form of a `PHPSESSID` cookie in the response headers. For example:

```http  
Set-Cookie: PHPSESSID=8bwxvicb2ogv1_3akeawjgpxzh_x-1zxogrg-ze1xdorambake92o27sd9kn4fgbvlw7vm15uw_qbx5ifcr...; path=/  
```

The value of the `PHPSESSID` represents the session ID that is directly tied to the PRNG (`mt_rand()`) output. Each session ID corresponds to a specific sequence of random numbers generated by the server during session creation.

To collect these session IDs consistently, we can submit repeated login requests, capturing the `PHPSESSID` values from each response. These session IDs are then stored for analysis in the next phase, where we aim to reverse the PRNG seed that produced them.

For each login iteration:

1\. **Submit valid credentials**: Using previously identified `username` and `password` combinations.  
2\. **Collect the session ID**: Extract the `PHPSESSID` from the response cookies.  
3\. **Store the session ID**: Save it for later use when reversing the PRNG.

Here is the list of session IDs captured during this phase:

```plaintext  
Flag chunk 0: 8bwxvicb2ogv1_3akeawjgpxzh_x-1zxogrg-ze1xdorambake92o27sd9kn4fgbvlw7vm15uw_qbx5ifcrz5ugk8-lgoybttwaw_m_19o2611uom602f19-sy4gk-dslc7tiiorkh1kvjo3aurufnxon8ml58ceuj4d4leyzsxpicikz5pjon5hrfhmyo5v8ud-_0r5p6tcn94lgype692h205tlfo8upoysem52onxn6gj5x81lhbsect0x0kujehsgmbqglydjws8817c7tn9in_l8si2e97qen1k7lf9aepk9qcofm5n9rmuqfswar3rh_j6k0povdq21_9_60fii3wvmebsmmka24une_6r6tlfn_ywql-meyw47b4-wnhr3g0pjlfnlj6cxdka2bzp7j-xybc8dzlwgaepsv2sdm0153eh4uaeum5f4qft91t-nr71t8ys2e2bahnm3o819g83hpwmsyevsh_8cv_ckkqulh10hxf5npmz-rtnzw3kegyu-ngatj-lkqz4xjjfch-qpj870t856-74wom5k042_1fsn34yab7labrlch0bo5eigni1az-r4v695eofu6hy6-ti77l-650m-wwptpbe3xcyggoq6128j5g7zpyzw17as4h1txpozjj5uil1l9f7kp5qzavaitcrqwnruxo36y-0o-p-1dxqixem1-vsgxvz5fi18e6yldwxioyniy42xoq1hf41_ttiy1eatedfb69ebmwk9-nponqejdxvdj4q6xzy2e57fi62wieog5d7vv3cc6btfpwjh5778a7q_uz92tzff2bc46jryvg4upb69o1dc-s1i-5to7vnw0dg7vdmfvdh-9r6y6zazsr04efigi-yt3mu5eahregt-x4k5yie5ko272pvmoqi58rwcl-yb529jbxwndr3qprby-la87byucmmprkk5dj_-bzofyua2dj25x4el4x9u-l8op-3_7a5wqi2

Flag chunk 1: sc_0nsixk5_mrr8xa5f4hday65tfxxbhx_bc-h282v9cq0v-c7uqmrrvr3dxohraf78i0emwdtkg1dlrpe9p-u9nss_pp4hjw_1suj3q7ptdc53mkyrh2idnlaj0qys5i5l-753macfng3r18cv99spw6w-rfg6kaszppn55ixq08q4kive0jr1l31bipcdx53rf0m5wjtah4fsmm36bive6lw3vt66tioky7h1uyx4_2uvkgi8jzh8sfavfo84hco4t-1oj6a5b536zgyq1g1-i_3tuueqh5zhfba5f2krxwissgpj14s2vwf_d0g4egl8_v3yxd781_w764v_myk8len471xifr4e1r_h5tt52uz6evkt8e2y1sgai5lz-1eruvlz_v6qsstuo77io9vf077hohd43kw9v-9xri6xevebt7zfq620ft6swlskv8bu_3142uomqxjbzlz-6dil14n46l0p06ehf4e91npqv7_nva9sk5gk11yiv_k79224xwkfdt3fmej5udmu1dwgxhuoeu4uzisey_2iplyozm4s_xl5t6hcjgm4ajn348egmaho0-cwz_e3275pb_6iiq0j773qniwgho53b5fuazl1e10ki8kbo8q6r0h7rvo6-irj_o0v7ve5vp-3ku0zlojz1ychhp5bdzlgiqmjre3lap8qljf3i3dav0z_2dj9boh29qo_0uhqczp2myh-8_zkhhlx1vxwbmc65par9wzjmg5dom449cqdcxvxwgcu1vlqj1mombe-px1g6pbbap_e2153qk4yikd46ufwk1dklmsdd_eixmrvy1lq07nci86xa1nmgjgmrawf5-mf8mbpm4hi-fiznzguqm8ttozxxdk7h5lgbp7jonq0eew6m58oyws_h7_44ggc_sgbvy7_oxvtyyds-w9s664afuk_8xlekl_4-txneg6v5jure99mh9z1ee_o2113qdjl8ge6tsx_-d2_-jxl7

Flag chunk 2: g1c84ou8utwl84j_6i58590s73_sq16pyu4wz2l1c64t5569iw6t111ra--zt5rejece6zekx-jzt4a887e5b-i-nc2m_74jz9m-49zunlb86838s1sd99usztvfrtk7tyvzma_lp9m54mpl-l6o8t-7s841qfqtjms5h7asdx68d358qj092ad7pe273-3f55xl3gkitei6avduldbjwcimk3fd9fbdcl7rh9z5a20oxe3rsenugp5la9e38luvgqgj101rg-in193thfqc6vcb7tg_7bihl6qvi40_j0_1ar9oddvu45fgqe_5zs9aw7q2vpf2ia8vud2g2y5fsx3-ity62xz-2hca5j2s1uuof_4noikn9t9562ow704a62nln2-c3wncc2rn5lp9nj8vp1ju8otvakl61nj2tpqq2yzyho_vq3b1a8qcap7zvz0qowjj2io9r8xbya41dqwyczlfh_krd_lxp3h6euf2t9ghnbxe8_m0_xpy6j-wu2jakvnhdao0p7i37ilrv2n4t-j-of517_zoat8yjk7vtj8qe_3g6b9nm1przgyl0us6h87lp212tz4pqozhmt7bk-gjnybpmc7c9jq3mr7-auj82kv87xi3srfdask7vrldm1pen2olu8oal92871r8cccad917m_7hyisn_lik1-smgvj7ggitl12bra26ziusf1mtczmbd15gab9cg75zljb_36ci8af656r7jymgqrwbe4xxxuxyczct3d4daubln_3kh6u90_htmyrrj3ps4mqq-bfw3i4o57c2ivflas57wews4989w56w7bcilzr2_ascr--21fais7kvilcu1nkoxqa-h731cssy0lu85mkcg-ezkuq7nk456f1924by8e-ghx76h8nl4-nc1uy0wbwg5n2geymxlxn1h2jx7plzab3vyksgyva_xpckwdvqkh1ftp0w_6jgfgdtdsf0dxo0cx02-7bdrawl

Flag chunk 3: 0po4g-sbcvss9qnfkcm65kjz6zp9j32ujl5c9977k74a0s7o0rbn4p1ol9dahyv-9-grbplrw9j_mwjmq581gp2-ozmwv4ci2ufozasv26b3wzj6kqonzdra9hfwvev2a4ir48vw9-6vgj97h6_2ena_l460-7agxencbqs3og4gr8qxia6k7l6x39h8h94d8191hg-rkvd_58aae783ugm7pvtlwaswk14wyj_3yc7xji-ao5t_375y0b0yvem83-5i4hnyx0-9e1fvg5o81ykatzidbr3zef-yhi4td43k90kld0cd--66nlut1-b2rlow_td-grt9g7a53dh3p3x0fgzqfp4xw-q99y1mfl31ui9dx4xhy2bpc_azrwmt-dh7igg33yu32i0ad_-cu7wzt3k6d_1rptt_7e0sigld_6k03-xgv6yf2brp9x_s05yaifnbn-5y0n9a5nzi3yzb0qxpb67bt9-h2p_5z8n-u545mx19c3nshqqmj2h92iz67fdcnknd6w8rhvz5nk20mqmhy3pzrc0s0-d7hhotq50v1i6qaejswsmgt7ennmswlf9raqi3qmttqj98lvcm42j-hlkb7nztxhrq3uws96o-7i3kzf0340ngn9289nenkcgz6ubaaz82wqzz3jjdsh4fl7ufcy-vpggv_u7ojb2qhlhtfe2f187y14u226wx98111lji_8yd67-lwyioq5m9enis9kletlg196426cmlhsxa8hozijztx0t1v4qqyybr8e5c3-tthvp23ldx55xt6mutechs-laiptjcyrkble529-e8563jsrhvb_lbddqywpuvivgcxsd63yf8-94k6vf7ny74m36dvqzwzlhgn0w4d3io3pw6zh5qp964pz84dlzff84imftvqe0hyawv_b1abqyzlmfay3gnin5j7qaatq2rz96btlr867pcc30sm8eg9xqoddhd3nk63yiz1zupyusth_wj

Flag chunk 4: 9fvvmt2mgj7x-n1fu4_piinllkox609ha122fdeb-8urxd6__8f3mchcy1-mvv_lmv0jwv6xlhf3u6sp4vs1ctc-cwet4jjup01ooz34vdrlxnfz7r54bf5ue0up7mpm6sjcmq-1eqedn4offhoors-spl3qovbe6_re-pwhcqhlgadpzy5jwxdkiqr3jjmsz7rue3gsdrvfpbs0v30bb1fl7a2judd11quycb8s0zgsg-82nqu9nvy_5nml6t90p0zgs4k2b9jinf46js1e9frgkklqp7ydtv1emtjuub6kviz9h5b-3cbiyj34aga_xou2cwto882c5c7ec3k7gcxk4vc8-1p5bubhbv1eptsliz1n8qhwo7f5z1my0euilka_slfbwtdp685v5rrep3v3utln1n-our6g_mwvq0g9wn-l3uz3h3mqex2or_dlme6f7pyaw6ym11-rlm0zy6b1flf6pby3jus1f2v6n2pf6hyy0rmots384i94qv-wnk5wgoypfpk3u-muwhwvbw4foznxot6g9dqiow67c4yczj2fcjqnj8zuuuun-b4kbms96gumll1jljtqt3cd9glj6w7kgvsyc81vkhxxdplrfrh18j1t_sm-u8gbytmv5mse9enwudxb_x-5o982drkoyt347f15_g-_97zcu-nz6317jse4hwdtcfd4wbrx7mhrdaik553q9wf4m9mbt4e5zgc2bofpkv386ceop-uh00pzuj12cgnfixgtw7_ehyg_55srvdd7wf1cgz1zflsmaxw8_evyft93oa82lybq8x157sohj3tj8dr7ogrtg_bwijcv7ivjirhp1grxoy2ghm-ear-d6liswceuhtp6cqjs13l8nqdtqycm4ljgw4tlvfh7gndxsipstwxfj53kzx_1w080g8wut-w6nc-ngp92zcrhe4b5kl7g2lt_9-su8r4naz9nvw5-m1g7du16ugbgimnzob58a9ei

Flag chunk 5: thw9343nszorwv8ckn1dw_mthklympt0z1_j4o1eg-0yvrivd9nxtlr99yqc4c7-1xps0-3f2al24w1lqq8zh26agqnppf4ajy2l6k_hl3-ijal67uhz83xx7t4c_xbnl79ls_2puxsnpfk5wtd1dbbig5a5lplmhle5vsldq7fh41g01fl-wjll5xbf4spnlr-waoqztazn673otp5c6hlkhwvw4q6i9rf7zfn3p-y-h8mwuatcij7pa2jd5jln5pqp92pn0-x4lgbtnaezu5stixwk1at4oef464sg09neshabbze1f60wvyaexlwh2577gq2g7znlr0y91y_xflwq3zn-lsdb1f7whq8r2y89h1hcrvr3l9cdrdzmzja25ss3f6pm2ullp5k39d6z7uiol8vmjmwfxk-1ydirxq45jw07smqohmmrf-162olfaz5dhzd1753-57v7mkkwl60p1pho1l16hoxvhxe2zyumnbizscb5q-97tbjyw5dr1d-n_kg2wqs3ftiu9gm8k6nizrhbu8ip255akm5suld9rtigzgxhh4_pnk9z-rb3x6jxdoxggsyp5ulzaecphhe8dm3xcew44tto2vspzvlfjhmih2xeuuv5m6ae3ebmgulef0-seohpqgd1mqa83h7apcwwq28e0er-x4s6idlffyx32d5dy5y0ahgdcrmjc-25o-f72nihamy3s41jlaokhyjydi7ozjjhaiwr5we60q3l7gbtymrrgws54bhxo4h77p8efmwtbpanmt7eyyzdvyolwp12be54z0ekg5ndi23yfy2bdbkixowh2n_tvk4suuy8shrkfjyn9lz17dijpz-408ah7qgz3a7o5b_91own5z6rmh-q-rzh-crcxb4rw004w98xmt8ksc2e3avuew710eclj7-s3s86agh7qvorzw9sfcf9hcads005piqv9wovdo37csfwper2nyc0n30k6ul4swvpqf97

Flag chunk 6: 8esmqjz4i1gn01-dulpookzbsrayhkuej5ecl44itncptzf0m10iygm3tky8elibnvucuce_jro1bucp5e14x7p7txv1au5ojo60g-ucx19lmumas65082pqykolwam5t661rekjr0qp-cghcmoouzrhte1jn1s16fxbm_a3nkv-y5t7j-j-lcmj6mr4kt4u25e1a1jcmvdvghdn0s8gg2n1_rlmb3babaqh7xf1quustywt_o6eedl_irbp72yo0r3dav3si779ebb3ncuk6fobqqc-9thcy544_yfzgyyu9v2x0h7gnbp3se30wio13e8liix9epfyb27b-lpw4ibr85kly_lvmu3wvh2_htdupiuxas11_h0j0ini-zvmosrubbtwxzwch1sk3qxa1wbeglmhcmgjdrh25zg41odaxtn4j4p7jr1bx-reijji4tjo2_z2s0y6n6bdr7y5y05e5_zjzglkafy0d_wdi7lxw9zgy5ww2fsshdftccl4p8-v_inurh3-e3kj6li0lij5p5d1sv-1w61_jj_yxr0eeo-fbqdhb8aonlinzu0t7tb65lrg42ks5-_d3ahbs0qc6nejmlo6uks22fuq92wzb_-xjcrkdh4fb_aoz144oahz72eymbxrri7zgk4d2rgbkyawed39x6__lx8o0xnnjxl8vr__8s2wcdtz1fkofkyf_3rbmn11imaq36-4zxqy5mjecw8hjcxe3djijx3-a06vfhizgke8l28t3u8wir2jx8ybocnm4d-o-dsk9zy623jl-bgpwxaab52nlurqt_r18yz6_6tte8f73strfi-u12lh8-c8qapiazbm6or526wb7fqo-s3vk6x0inq--ie_8nubmh4azzj9x4-xsklwnnkxx69pi7usg4xxlpuceja3mg-n63a0pu82od7nttmxi_c9x_2l6d6iht1-9nnxsxxovfo9lg-vm46roidnd_vh9y_6-pbza3-r

Flag chunk 7: d5k28813ss1i_eitqvatanj3p3v5xxzbdvzbl6la00id6w6hxi9bcmvxoxc7lax6gkd2n33791fwrimzskzxx0uurjp3-950ks_77u-v618ab5s_jrvra98n1fz2nu5gst3ws_uv6ojj2v_g9408v97b8y0-8e6ha8ia8ywbbpy19pw--994_ei_venkr216g4j26prm6d00-b9ug67o-ulfbf44b9k50iyk7sndabixbos_zu1ri68uxdvkq7e05ci60if_ma22r29s-xrs9r2j0x_s862mhoxosonfcn7pmpc47ehege8l_knoqmafdhc06oixw41sjgmtj5-vorus1kaqjqqgj71wrfdmv0r6dvs-35ojw7bi_9uchqyxufbhsfbz0bkg63q-lwtgxzvqy979xc-g7acp546fdca6fsnkazqy-al6h14n36t4c80fpub1i35m3f9d65175-9vc318m13cib3lghr7jv8rooi463byy_-q_ercfmkak0406n2iz7dd97ol35fwzz1kj-15hqcfpme2g208n0w32k0vv4k8r3fboptk-_k0f-4ejq51um148yrekbxf9cvkeg1fujlgwaimtzw_n8y1dnw4_c6lh8_6irsdlzavkulc25eh0n5ox4z2amg_rag35z9n6dyc_fe__f0ettav8hxmh2w6dp7o-lp-2s_vt5bgp7eeq7nfm8_l8nxsz4xhcc_ilj90uz89okljya2qyr5v-85crhh3gi7bocud0sdy8zdlze8td0b-xsevzw4lk2-6q84g_t_e5ili5z00rrd7roc4-3q90ca8blttyyrp6knsick63btsh4bf9pao9bxqrb2m7idi1hlbsmp5l-n3pfdwkmw37l1_8iu53v3sszhp7dta7vuw48bgiujkiqwbb6ywraw_6_qohlp8wm42unch4d9c3i976pq2evpt0dcj3qzcgng16da4u8s0ejr6klra584ns-p9

Flag chunk 8: u78grj0cjwuogn8-utrqg5j_b2pvgd3fl6-6up9-bs0cft0bw-7_zwa7sr2xdbjh7utiing8b-cafzm9yxurm6eyn6gpba3nmuv457vafcdsfr9lipsdlo-qaty3gzmzuyu_4haeeewqa9zkxx5lj23d5iuf6xz-0walxmwwzfej4gq9zw3ta2ogpl3f7lh_qzd26db8b-_zwdyyspk20qklo-rne26cq96o3at8lq45n8rdyr-wsx8yr_x4d4g6nx5ll-729w7gm7m80ddzx6b9v-q58fg2t51m-to9uwwzv1c5yvzhhvo7w-x89f8uqzw_i7hjttd5__9ihmi91pn1j6_p6hon29rl1wm49nwwp_j6h9yq87cerq8tzd1jtt6254-_p02wi0b7nt3ozvof00myn4pz4y29mfka9bau5nc2fbwlnmvs4y3383b4_rey50jxd5sxli90qg945fa3iqgmz3jjq47_fj5zooypd1-d_h_s01eckz2t3mu3315etbhfy1rappjq_ko82yd39i7742_kfkzehkcpko49r3kdryr9x9n2oo-lpzlep5ur6t4j1o4prajjl82q7-o95wd2i4phoqyrc53dx3mwa4sn-v0lcn4npdhucnu4i5_e8iqkukfrwa616trxqn3jjfb3t7axda-tlkng5-yietkngvls1-vu09n75c15jnjmhskz9op-9hymiqt6ap4f0ut-knqoh648zfj2bwh6ap9lt0hvu_ix1z67cgnq4_x9q87v_wphuy86qidh_e8g3ue8k12cchv-j2efnni8ebnp1uheiv4-m7z38c9kbu20nreomd2gq4hln_-k2rr-yie9b8r_wuypy7f8kys46n5zontbrqhb9m3hv6cim_m7tlo2tcwpsrxpn_u90-1n_7rxe5sn4ttn4wo-986y5he0fs19tsxt7y3z5qqel1prr-s7z777s0o7bq97-us099ykj_vjg7_hy_b-

Flag chunk 9: a-jtqk69cbq5k2n1asouw_-c01e3q2o7kecbeg2_k1psqvqj9b2htoojg5s4o4sqbbz43onpib60am4jjbjzig6yw5nexm4c3dycn9ntoda1tsn_xl0swl_h3eww1retewksr9qyz1vhe8v-cyi2txn319-fancgqy0dnipm4069vpwwwdbyrayobopk3u0ivs8gb421xkt6nmktb7-d16_ospqq0wmsmpltenk_zsov80gs9dany5c4krv5fn3hk7of4fcgcn8xezbkf078bv3hn3046qstk0bsc36p39m-120s44pl9ggibpor1kau1k_jhuhaad7ckpjibkd9x_q0pckshxsm-9t8oox4p52-bbwid77ixyw9susgtjid-cv7kac5rtiuux73ckt88qf21eg3s3custo6_o25y8w709qfguzzddl7wfd0_vjucjm6qcwtzwg4i15_qshz4x74d-rxi05bc7dpn9x9_a2oppxpjs6j6jmik_niltmqlb586kw-xcbma62x1vd08_0-m055k1uzm82z_tat9mw7nogzhqmf0ib6_6uttaeuqkzfrd8mm5qpvsrwjagf87jkhlg2p52dlwp5fwxjhoya8ensjpe3q-g2a1rq-n8wmziqa9vklxmjinm27mo512hnzvxzytqb0hejnjt8122gxf0xlpwzkmt8z2lfcwkvjjy-5xfp516gmg1ybmk4c1wzh5p4oqkvf6v5tunb2p3id8c_mpsjfmpufmteaq7ty83xa6ggrtm7jgu55n6lu-ejthx-_ont4imfrrohshk7bse9m1h1fosssayzh7qj338kevwr8u24jwtf1qo0v_l7hj03c6i93v-9q7bb6gfx3ymtbjr-lwf9g2utha37spum9y04nz03uwq5s9_roil8zv68d6oczfkhe3dlhvq_0x8lhgearklcx2936x_lhtbph7_uprmte9gtqtcow64xdjphlx0t9n8vqgst  
```

\---

#### Extracting PRNG Output from Session ID

To reverse the seed, we first need to map each character in the session ID back to its corresponding index in the `ALPHA` array.

Here's the PHP script used to perform this mapping:

```php  
define("ALPHA", str_split("abcdefghijklmnopqrstuvwxyz0123456789_-"));

function get_indices($session_id) {  
$indices = [];  
for ($i = 0; $i < strlen($session_id); $i++) {  
$indices[] = array_search($session_id[$i], ALPHA);  
}  
return $indices;  
}

// Replace 'retrieved_session_id_here' with the session ID you captured.  
$session_id = "retrieved_session_id_here";  
print_r(get_indices($session_id));  
```

Example output for a session ID like `"ab9_c-..."`:  
```  
[0, 1, 35, 36, 2, 37, ...]  
```  
These indices are the raw output from the PRNG function (`mt_rand(0, 37)`).

\---

#### Feeding Data to `php_mt_seed`

Once we have the extracted indices, we need to use them with the `php_mt_seed` tool to reverse the PRNG seed. However, the correct way to use the tool requires a specific format and multiple observations. `php_mt_seed` processes observations using the following format:

```bash  
./php_mt_seed <min_value_generated> <max_value_generated> <min_possible_value> <max_possible_value>  
```

Each set of four values corresponds to one generated PRNG output, and we need to provide multiple sets to the tool. Here's a detailed explanation of the arguments:

\- **`<min_value_generated>`**: The exact value generated by the PRNG (e.g., the index of a character in `ALPHA` extracted from the session ID). For a specific observation, this will be the same as `<max_value_generated>` since we know the exact value generated.  
\- **`<max_value_generated>`**: Same as `<min_value_generated>` because the generated value is precise for this observation.  
\- **`<min_possible_value>`**: The smallest possible value the PRNG could have generated. In the context of `mt_rand(0, 37)`, this is `0`.  
\- **`<max_possible_value>`**: The largest possible value the PRNG could have generated; this is `37` for `mt_rand(0, 37)`.

\---

#### Using Multiple Observations

The `php_mt_seed` tool requires multiple observations to reverse the PRNG seed. A single observation is insufficient to reconstruct the state of the Mersenne Twister PRNG due to its complex internal state. To reliably reverse the seed, we need at least 10-15 consecutive outputs from `mt_rand()` during session ID generation.

For example, if we extracted the following indices from a session ID:  
```  
[22, 10, 15, 35, 0]  
```  
Each of these indices represents a value generated by the PRNG. For each index, we define its corresponding group of values as follows:

\- For the index `22`: `22 22 0 37`  
\- For the index `10`: `10 10 0 37`  
\- For the index `15`: `15 15 0 37`  
\- For the index `35`: `35 35 0 37`  
\- For the index `0`: `0 0 0 37`

We then combine these groups into a single `php_mt_seed` command, providing all the observations to the tool:

```bash  
./php_mt_seed 22 22 0 37 10 10 0 37 15 15 0 37 35 35 0 37 0 0 0 37  
```

This command includes multiple observations, ensuring the tool has enough data to reverse-engineer the seed.

\---

#### Automating the Process to Generate the Command

To simplify the task of preparing the `php_mt_seed` command, which can be tedious and error-prone when done manually, we can automate the process with a script. The script will extract indices from the session ID and format them directly into a valid `php_mt_seed` command.

Here is the script, which automates the job:

```php  
<max_value> <min_possible> <max_possible>" to the command  
$command .= " $min_value $max_value 0 37";  
}  
}

return $command;  
}

$session_id = $argv[1]; // First argument is the session ID  
$num_indices = $argc >= 3 ? intval($argv[2]) : 10; // Second optional argument is the number of indices

// Generate and print the php_mt_seed command  
$command = generate_php_mt_seed_command($session_id, $num_indices);  
echo "Generated php_mt_seed command:\n";  
echo $command . "\n";  
?>  
```

Output for each session ID:

```  
php extract_index.php 8bwxvicb2ogv1_3akeawjgpxzh...[TRUNCATED]...  
./php_mt_seed 34 34 0 37 1 1 0 37 22 22 0 37 23 23 0 37 21 21 0 37 8 8 0 37 2 2 0 37 1 1 0 37 28 28 0 37 14 14 0 37

php extract_index.php sc_0nsixk5_mrr8xa5f4hday65...[TRUNCATED]...

./php_mt_seed 18 18 0 37 2 2 0 37 36 36 0 37 26 26 0 37 13 13 0 37 18 18 0 37 8 8 0 37 23 23 0 37 10 10 0 37 31 31 0 37

php extract_index.php g1c84ou8utwl84j_6i58590s73...[TRUNCATED]...  
./php_mt_seed 6 6 0 37 27 27 0 37 2 2 0 37 34 34 0 37 30 30 0 37 14 14 0 37 20 20 0 37 34 34 0 37 20 20 0 37 19 19 0 37

php extract_index.php 0po4g-sbcvss9qnfkcm65kjz6z...[TRUNCATED]...  
./php_mt_seed 26 26 0 37 15 15 0 37 14 14 0 37 30 30 0 37 6 6 0 37 37 37 0 37 18 18 0 37 1 1 0 37 2 2 0 37 21 21 0 37

php extract_index.php 9fvvmt2mgj7x-n1fu4_piinllko...[TRUNCATED]...  
./php_mt_seed 35 35 0 37 5 5 0 37 21 21 0 37 21 21 0 37 12 12 0 37 19 19 0 37 28 28 0 37 12 12 0 37 6 6 0 37 9 9 0 37

php extract_index.php thw9343nszorwv8ckn1dw_mthkl...[TRUNCATED]...  
./php_mt_seed 19 19 0 37 7 7 0 37 22 22 0 37 35 35 0 37 29 29 0 37 30 30 0 37 29 29 0 37 13 13 0 37 18 18 0 37 25 25 0 37

php extract_index.php 8esmqjz4i1gn01-dulpookzbsra...[TRUNCATED]...  
./php_mt_seed 34 34 0 37 4 4 0 37 18 18 0 37 12 12 0 37 16 16 0 37 9 9 0 37 25 25 0 37 30 30 0 37 8 8 0 37 27 27 0 37

php extract_index.php d5k28813ss1i_eitqvatanj3p3v...[TRUNCATED]...  
./php_mt_seed 3 3 0 37 31 31 0 37 10 10 0 37 28 28 0 37 34 34 0 37 34 34 0 37 27 27 0 37 29 29 0 37 18 18 0 37 18 18 0 37

php extract_index.php u78grj0cjwuogn8-utrqg5j_b2p...[TRUNCATED]...  
./php_mt_seed 20 20 0 37 33 33 0 37 34 34 0 37 6 6 0 37 17 17 0 37 9 9 0 37 26 26 0 37 2 2 0 37 9 9 0 37 22 22 0 37

php extract_index.php a-jtqk69cbq5k2n1asouw_-c01e...[TRUNCATED]...  
./php_mt_seed 0 0 0 37 37 37 0 37 9 9 0 37 19 19 0 37 16 16 0 37 10 10 0 37 32 32 0 37 35 35 0 37 2 2 0 37 1 1 0 37  
```

Which gives us this list of commands to run:

```bash  
./php_mt_seed 34 34 0 37 1 1 0 37 22 22 0 37 23 23 0 37 21 21 0 37 8 8 0 37 2 2 0 37 1 1 0 37 28 28 0 37 14 14 0 37

./php_mt_seed 18 18 0 37 2 2 0 37 36 36 0 37 26 26 0 37 13 13 0 37 18 18 0 37 8 8 0 37 23 23 0 37 10 10 0 37 31 31 0 37

./php_mt_seed 6 6 0 37 27 27 0 37 2 2 0 37 34 34 0 37 30 30 0 37 14 14 0 37 20 20 0 37 34 34 0 37 20 20 0 37 19 19 0 37

./php_mt_seed 26 26 0 37 15 15 0 37 14 14 0 37 30 30 0 37 6 6 0 37 37 37 0 37 18 18 0 37 1 1 0 37 2 2 0 37 21 21 0 37

./php_mt_seed 35 35 0 37 5 5 0 37 21 21 0 37 21 21 0 37 12 12 0 37 19 19 0 37 28 28 0 37 12 12 0 37 6 6 0 37 9 9 0 37

./php_mt_seed 19 19 0 37 7 7 0 37 22 22 0 37 35 35 0 37 29 29 0 37 30 30 0 37 29 29 0 37 13 13 0 37 18 18 0 37 25 25 0 37

./php_mt_seed 34 34 0 37 4 4 0 37 18 18 0 37 12 12 0 37 16 16 0 37 9 9 0 37 25 25 0 37 30 30 0 37 8 8 0 37 27 27 0 37

./php_mt_seed 3 3 0 37 31 31 0 37 10 10 0 37 28 28 0 37 34 34 0 37 34 34 0 37 27 27 0 37 29 29 0 37 18 18 0 37 18 18 0 37

./php_mt_seed 20 20 0 37 33 33 0 37 34 34 0 37 6 6 0 37 17 17 0 37 9 9 0 37 26 26 0 37 2 2 0 37 9 9 0 37 22 22 0 37

./php_mt_seed 0 0 0 37 37 37 0 37 9 9 0 37 19 19 0 37 16 16 0 37 10 10 0 37 32 32 0 37 35 35 0 37 2 2 0 37 1 1 0 37  
```

\---

#### Why Multiple Observations Are Necessary

The Mersenne Twister PRNG has an internal state consisting of 624 integer values; this state dictates the sequence of random numbers it generates. A single generated value (index from the session ID) doesn't provide enough information to uniquely determine the state or the seed. However, by providing a sequence of consecutive outputs (here, the indices `[22, 10, 15, 35, 0]`), `php_mt_seed` can connect these outputs to the internal state and deduce the seed (`mt_srand(seed)`).

\---

#### Running the Command and Interpreting the Output

Once we have all the commands, we can run them in sequence to recover the seed values. For example, running the first command:

![First php_mt_seed command ran](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_0.png>)

Outputs the seed `1162760059` at line :

```bash  
seed = 0x454e4f7b = 1162760059 (PHP 7.1.0+)  
```

And we continue gathering the seed values for all the commands.

![php_mt_seed command number 1](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_1.png>)

![php_mt_seed command number 2](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_2.png>)

![php_mt_seed command number 3](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_3.png>)

![php_mt_seed command number 4](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_4.png>)

![php_mt_seed command number 5](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_5.png>)

![php_mt_seed command number 6](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_6.png>)

![php_mt_seed command number 7](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_7.png>)

![php_mt_seed command number 8](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_8.png>)

![php_mt_seed command number 9](<https://blog.hitc.at/images/nullcon/web/sessio_php_mt_seed_9.png>)

Which gives us the following seed values:

```bash  
0: 1162760059  
1: 1397706053  
2: 1599296848  
3: 1163026259  
4: 1162040658  
5: 1163871820  
6: 1095196465  
7: 858993459  
8: 859266888  
9: 1094929277  
```

\---

#### Interpreting the Reversed Seed

The seed value recovered by `php_mt_seed` corresponds to the output of `intval(bin2hex($SEEDS[index]), 16)`. We can now, via this script, convert the seed values to their respective dehashed values: 

```php

```

Output: 

```bash  
Dehashed: ENO{  
Dehashed: SOME  
Dehashed: _SUP  
Dehashed: ER_S  
Dehashed: ECUR  
Dehashed: E_FL  
Dehashed: AG_1  
Dehashed: 3333  
Dehashed: 37_H  
Dehashed: ACK}  
Concatenated Dehashed Values: ENO{SOME_SUPER_SECURE_FLAG_1333337_HACK}  
```

And voila! We have the flag: `ENO{SOME_SUPER_SECURE_FLAG_1333337_HACK}`.
