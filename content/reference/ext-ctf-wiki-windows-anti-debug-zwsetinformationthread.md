---
title: "ZwSetInformationThread (CTF Wiki)"
category: "rev"
subcategory: "anti-debug"
type: "reference"
tags: ["ctf-wiki", "rev", "zwsetinformationthread", "anti-debug", "anti", "debug", "chinese", "zh"]
summary: "ZwSetInformationThread 等同于 NtSetInformationThread，通过为线程设置 ThreadHideFromDebugger，可以禁止线程产生调试事件，代码如下  c"
source:
  name: "CTF Wiki"
  url: "https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/reverse/platform/windows/anti-debug/zwsetinformationthread.md"
license: "CC BY-NC-SA 4.0"
---

# ZwSetInformationThread

## 关于ZwSetInformationThread

ZwSetInformationThread 等同于 NtSetInformationThread，通过为线程设置 ThreadHideFromDebugger，可以禁止线程产生调试事件，代码如下  ```c
#include <Windows.h>
#include <stdio.h>

typedef DWORD(WINAPI* ZW_SET_INFORMATION_THREAD) (HANDLE, DWORD, PVOID, ULONG);
#define ThreadHideFromDebugger 0x11
VOID DisableDebugEvent(VOID)
{
    HINSTANCE hModule;
    ZW_SET_INFORMATION_THREAD ZwSetInformationThread;
    hModule = GetModuleHandleA("Ntdll");
    ZwSetInformationThread = (ZW_SET_INFORMATION_THREAD)GetProcAddress(hModule, "ZwSetInformationThread");
    ZwSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
}

int main()
{
    printf("Begin\n");
    DisableDebugEvent();
    printf("End\n");
    return 0;
}
```

关键代码为`ZwSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);`，如果处于调试状态，执行完该行代码，程序就会退出  

## 如何绕过

注意到该处 ZwSetInformationThread 函数的第 2 个参数为 ThreadHideFromDebugger，其值为 0x11。调试执行到该函数时，若发现第 2 个参数值为 0x11，跳过或者将 0x11 修改为其他值即可

---

## Source

CTF Wiki - <https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/reverse/platform/windows/anti-debug/zwsetinformationthread.md>

Mirrored into CTF-Brain at commit `e225ddfcd420`. Licence: CC BY-NC-SA 4.0. The text is the original authors' work.
