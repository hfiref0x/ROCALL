<p align="center">
  <img src="https://github.com/hfiref0x/hfiref0x.github.io/blob/master/blog/img/05072025/Logo.png?raw=true" alt="Logo" width="220"/>
</p><p align="center"><sub>ReactOS fanboys warning</sub></p>

# Making ReactOS Great Again: Interlude (2025)

[Actual ROCALL readme](https://github.com/hfiref0x/ROCALL/blob/master/ROCALL.md)

<p align="center">
  <img src="https://github.com/hfiref0x/hfiref0x.github.io/blob/master/blog/img/05072025/Pepe.jpg?raw=true" alt="Pepe" />
</p><p align="center">Pic 1. ENERGETIC.</p>

This article is a direct continuation of two articles I wrote many years ago. Although this piece is not very long (as there is really nothing new to add), it serves as an interlude for possible future articles about ReactOS, should I ever wish to return to the topic.

- 📝 **Making ReactOS Great Again (2018)** — [kernelmode.info](https://www.kernelmode.info/forum/viewtopic6f46.html?f=11&t=5302) ([webarchive](https://web.archive.org/web/20240909192734/https://www.kernelmode.info/forum/viewtopic6f46.html?f=11&t=5302))
- 📝 **Is ReactOS Great Again (2019)** — [swapcontext.blogspot.com](https://swapcontext.blogspot.com/2019/12/is-reactos-great-again-2019.html)

While I'm no longer blogging for various reasons, I still remember that I promised some things at the end of the second article in December 2019.

>  **Next stop on the ReactOS station will be at the end of 2020 or 2021 depending on the moon phase, if something extraordinary doesn't happen until then of course. Maybe we can touch the x64 version then (and BSOD it, of course) 😃**

As you probably know, some “things” happened in 2020 and beyond, so unfortunately I wasn't able to fulfill my promise. To be honest, ReactOS was the last thing on my mind during these years. If you look at the ReactOS development history, you'll see that in the past few years the development activity (mostly an imitation of work as usual) has significantly dropped. Perhaps people have found better things to do, or better ways to spend their time and money. Even that schizophrenic IT-evangelist who wasted tons of time advertising ReactOS on various forums is gone, <b>jeditobe</b> I miss you! He was a valuable source of various ReactOS pasta, my favorite "it is working but not today" 😃

---

So, almost six years after the previous article, I came back to see what happened with this toyish VM-bound operating system, especially in light of their 0.4.15 release.

I didn't expect much, and as usual, from their advertising blog post I learned they have some new ugly UI innovations, which look like 💩 trash from the early 2000s. Okay, they also promised improvements to the USB stack, memory management, and the file system driver—which, surprise-surprise, is now Microsoft's open-sourced fastfat, lol.

Yeah, they took Microsoft code (in this case, an open-source file system driver) and integrated it instead of their own chaotic trash they had before. Nothing bad here, but it's pretty funny when the most stable and professionally written part of your operating system is a component from the very vendor whose OS you've been trying to mimic for 27 years (at the time of writing this post). 😂 Kind of like, what was the point then? Uhh-ohh what happened then to this great statement I love so much 
>There is no Windows code in ReactOS. There never was. There was never such an accusation in the first place.

Life kicks hard, yes?

The fastfat driver, along with some configuration manager changes, has significantly improved the overall survivability of this failed Windows NT-clone. You no longer need to reinstall ReactOS in case of a critical system error. Well, at least in my tests, it survived hundreds of system crashes without taking everything with it. 🔄

---

Unfortunately, this is the only visible dramatic change since 2019. Everything else is still at a low quality level and some things are even worse than before. Aside from this, a typical boot of this 0.4.15 release on my test machines takes almost a minute. I have no idea what is wrong here and honestly, this is not my job to figure out why your **release build** (whatever alpha it is or not) works the way it does, so I can reinstall Windows 10 in VM to the desktop (with autounattend) almost in the same time as your OS finishes booting.

So-called improved USB support results in needing to do a hardware reset for the virtual machine when you plug in a USB stick. Yeah, you have to reset the machine so this "OS" will manage to recognize and use the plugged disk. Otherwise, explorer will hang without any way to interrupt or terminate it. Very funny and very ReactOS-ish. 💥

GUI still sucks and randomly crashes. Sometimes its even fun to watch just like this one below on Pic 2.

<p align="center">
  <img src="https://github.com/hfiref0x/hfiref0x.github.io/blob/master/blog/img/05072025/TheEnd.png?raw=true" alt="TheEnd" />
</p><p align="center">Pic 2. That ReactOS feel.</p>

However, I was able to install browsers like Firefox and Chrome from their application manager. Previously Firefox installation resulted in reboot and ReactOS reinstall, so it's a huge progress. Due to no multiprocessor support, everything lags and is partially unusable. Yeah, by the way, it's 2025 and still no MP support, no x64 support (although they have some preliminary work on it). 🐢

---

You must be wondering when I will destroy ReactOS again with multiple bugs and their descriptions? Well, what can I say—they have mostly stayed alive for these almost six years! 😉 You don't have to destroy what is barely alive or alive just because of incident and moon phase. 

Their `KiServiceTable` still has a lot of bugged services that nobody gives a single fuck about, and imagine what will happen when this crapware code faces a multiprocessor environment. 🤣🧨

Their `W32pServiceTable` is a collection of bugs and programming mistakes. However, I must admit they fixed an integer overflow bug in `NtUserGetAsyncKeyState` which was used by my BSODScreensaver as an easter egg. ROFL x2

---

Anyway, BSODScreensaver will be updated and will include a new easter egg that they won't be able to fix easily (since it is known for almost six years they are either unable or unwilling to). 🧙‍♂️✨

<p align="center">
<img src="https://github.com/hfiref0x/hfiref0x.github.io/blob/master/blog/img/05072025/WhenYouHaveNothingToDo.jpg" />
</p>
<p align="center">Pic 3. When you have nothing to do.</p>

As for ROCALL—our ReactOS syscall fuzzer—it will receive a major update unifying its codebase with NTCALL64, which also received a major update recently. The biggest change here is type-aware syscall fuzzing. Since ReactOS is open source, it was relatively easy to obtain information and build a somewhat comprehensive database of syscall parameter types. This allows us to generate more realistic parameters for system services, e.g., give them specially crafted structures filled with random or specifically selected invalid data. 

This greatly increases the ability of ROCALL to reveal syscall error-handling bugs. Along with improved output and ReactOS adopting Microsoft’s fastfat driver, this makes fuzzing much more enjoyable—there is no need to revert virtual machine snapshots every time. 😎

The new approach of fuzzing (enabled with `-h` switch in ROCALL command line) revealed additional bugs (some of them even weren't in my previous lists). With enough passes for each syscall it brings a lot of fun to watch how ReactOS burns in blue screens. 💥🟦

By the way, it is 2025 and their so-called OS doesn't have a built-in simple way to diagnose system crashes. Yeah - after 27 years in development this OS cannot create memory dumps. All they can offer is a kernel debugger attached to a COM port. I mean some kernel debugger running on another OS which is better than ReactOS.

This is kind of strange when you waste years on mediocre GUI experiments but cannot implement basic features that you should have from the early builds. Priorities or lack of competence?

A nice blue screens gallery is included. This is the result of new ROCALL fuzzing plus some easter egg. Warning: multiple images! This gallery features multiple unrecoverable system errors, some related to working with `UNICODE_STRING` (yeah they still cannot handle this even in ntoskrnl). Several are results of integer overflows, some corrupt system memory during their execution flow. 

Additionally, some are caused by exhausted system resources because ReactOS leaks handles, memory—everything as if there are complete noobs who wrote these syscalls... oh I forgot most of this crap was coded by incompetent students with basic reverse engineering skills in a 2000s.

<details>
<summary><b>Show blue screen gallery</b></summary>

<table>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserSetWinEventHook.png" alt="NtUserSetWinEventHook" width="320"/><br/>
      <sub>NtUserSetWinEventHook</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserSBGetParms.png" alt="NtUserSBGetParms" width="320"/><br/>
      <sub>NtUserSBGetParms</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserOpenWindowStation.png" alt="NtUserOpenWindowStation" width="320"/><br/>
      <sub>NtUserOpenWindowStation</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserGetDCEx.png" alt="NtUserGetDCEx" width="320"/><br/>
      <sub>NtUserGetDCEx</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserGetCursorInfo.png" alt="NtUserGetCursorInfo" width="320"/><br/>
      <sub>NtUserGetCursorInfo</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserGetClassInfo.png" alt="NtUserGetClassInfo" width="320"/><br/>
      <sub>NtUserGetClassInfo</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserDrawCaption.png" alt="NtUserDrawCaption" width="320"/><br/>
      <sub>NtUserDrawCaption</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserCreateWindowStation.png" alt="NtUserCreateWindowStation" width="320"/><br/>
      <sub>NtUserCreateWindowStation</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserCreateAcceleratorTable.png" alt="NtUserCreateAcceleratorTable" width="320"/><br/>
      <sub>NtUserCreateAcceleratorTable</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserConvertMemHandle.png" alt="NtUserConvertMemHandle" width="320"/><br/>
      <sub>NtUserConvertMemHandle</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserCallOneParam.png" alt="NtUserCallOneParam" width="320"/><br/>
      <sub>NtUserCallOneParam</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUserBuildHwndList.png" alt="NtUserBuildHwndList" width="320"/><br/>
      <sub>NtUserBuildHwndList</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUnloadKey2.png" alt="NtUnloadKey2" width="320"/><br/>
      <sub>NtUnloadKey2</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtUnloadKey.png" alt="NtUnloadKey" width="320"/><br/>
      <sub>NtUnloadKey</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtSetSystemEnvironmentVariable.png" alt="NtSetSystemEnvironmentVariable" width="320"/><br/>
      <sub>NtSetSystemEnvironmentVariable</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtLoadKeyAndCo.png" alt="NtLoadKey and its variations (all, lol)" width="320"/><br/>
      <sub>NtLoadKey and its variations (all, lol)</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiSetDIBitsToDeviceInternal.png" alt="NtGdiSetDIBitsToDeviceInternal" width="320"/><br/>
      <sub>NtGdiSetDIBitsToDeviceInternal</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiPolyPatBlt.png" alt="NtGdiPolyPatBlt" width="320"/><br/>
      <sub>NtGdiPolyPatBlt</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiInvertRgn.png" alt="NtGdiInvertRgn" width="320"/><br/>
      <sub>NtGdiInvertRgn</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiGetTextExtent.png" alt="NtGdiGetTextExtent" width="320"/><br/>
      <sub>NtGdiGetTextExtent</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiGetFontResourceInfoInternalW.png" alt="NtGdiGetFontResourceInfoInternalW" width="320"/><br/>
      <sub>NtGdiGetFontResourceInfoInternalW</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiGetCharWidthW.png" alt="NtGdiGetCharWidthW" width="320"/><br/>
      <sub>NtGdiGetCharWidthW</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiGetCharacterPlacementW.png" alt="NtGdiGetCharacterPlacementW" width="320"/><br/>
      <sub>NtGdiGetCharacterPlacementW</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiGetCharABCWidthsW.png" alt="NtGdiGetCharABCWidthsW" width="320"/><br/>
      <sub>NtGdiGetCharABCWidthsW</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiExtCreateRgn.png" alt="NtGdiExtCreateRgn" width="320"/><br/>
      <sub>NtGdiExtCreateRgn</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiExtCreatePen.png" alt="NtGdiExtCreatePen" width="320"/><br/>
      <sub>NtGdiExtCreatePen</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiEngUnlockSurface.png" alt="NtGdiEngUnlockSurface" width="320"/><br/>
      <sub>NtGdiEngUnlockSurface</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiEngStretchBlt.png" alt="NtGdiEngStretchBlt" width="320"/><br/>
      <sub>NtGdiEngStretchBlt</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiEngCreatePalette.png" alt="NtGdiEngCreatePalette" width="320"/><br/>
      <sub>NtGdiEngCreatePalette</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiEngBitBlt.png" alt="NtGdiEngBitBlt" width="320"/><br/>
      <sub>NtGdiEngBitBlt</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiEngAlphaBlend.png" alt="NtGdiEngAlphaBlend" width="320"/><br/>
      <sub>NtGdiEngAlphaBlend</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiDdUnlock.png" alt="NtGdiDdUnlock" width="320"/><br/>
      <sub>NtGdiDdUnlock</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiDdLock.png" alt="NtGdiDdLock" width="320"/><br/>
      <sub>NtGdiDdLock</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiDdDDIdestroyDCFromMemory.png" alt="NtGdiDdDDIdestroyDCFromMemory" width="320"/><br/>
      <sub>NtGdiDdDDIdestroyDCFromMemory</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiDdDDICreateDCFromMemory.png" alt="NtGdiDdDDICreateDCFromMemory" width="320"/><br/>
      <sub>NtGdiDdDDICreateDCFromMemory</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiDdCreateSurface.png" alt="NtGdiDdCreateSurface" width="320"/><br/>
      <sub>NtGdiDdCreateSurface</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiDdCreateDirectDrawObject.png" alt="NtGdiDdCreateDirectDrawObject" width="320"/><br/>
      <sub>NtGdiDdCreateDirectDrawObject</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiDdCreateD3DBuffer.png" alt="NtGdiDdCreateD3DBuffer" width="320"/><br/>
      <sub>NtGdiDdCreateD3DBuffer</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiCreateRoundRectRgn.png" alt="NtGdiCreateRoundRectRgn" width="320"/><br/>
      <sub>NtGdiCreateRoundRectRgn</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiCreatePen.png" alt="NtGdiCreatePen" width="320"/><br/>
      <sub>NtGdiCreatePen</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiCreateEllipticRgn.png" alt="NtGdiCreateEllipticRgn" width="320"/><br/>
      <sub>NtGdiCreateEllipticRgn</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiCreateDIBrush.png" alt="NtGdiCreateDIBrush" width="320"/><br/>
      <sub>NtGdiCreateDIBrush</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiCreateDIBitmapInternal.png" alt="NtGdiCreateDIBitmapInternal" width="320"/><br/>
      <sub>NtGdiCreateDIBitmapInternal</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtGdiCreateCompatibleBitmap.png" alt="NtGdiCreateCompatibleBitmap" width="320"/><br/>
      <sub>NtGdiCreateCompatibleBitmap</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/raw/678bd8f41ff058cba889ab2f3d1f479709677502/blog/img/05072025/NtCreateMutant.png" alt="NtCreateMutant" width="320"/><br/>
      <sub>NtCreateMutant</sub>
    </td>
    <td align="center">
      <img src="https://github.com/hfiref0x/hfiref0x.github.io/blob/master/blog/img/05072025/EasterEgg.png?raw=true" alt="EasterEgg" width="320"/><br/>
      <sub>EasterEgg</sub>
    </td>
  </tr>
</table>

</details>

## 🚩 Conclusion

It's 2025 and ReactOS still sucks. But you finally can use it in VM for educational purposes (with kernel debugger attached for better experience lol). The greatest achievement for 27 years enabled by... Microsoft code. 🏆

ReactOS devs should wait a little, perhaps another 27 years and maybe, just maybe, Microsoft will open-source also the graphical subsystem driver (ReactOS fanboys already trying win32k from Windows 2003 Server as replacement for ReactOS-ish nightmare pile of garbage). And maybe MS will open-source even entirely Windows XP (RTM lol). So what was the point, ReactOS? 🤷‍♂️ To grab some donations from not so smart people expecting you to create something worthy? Well, valid point of course!

## P.S.

When will I come back to this topic again? Oh well, I'm not going to lie but everything in ReactOS changes so slowly so it takes years to have something worthy to try. I'm pretty much interested in their x64 version and MP support. Currently, while you can select MP configuration in the installation process - it will get stuck in an infinite loop after that, so this feature is "working but not today" (c) as usual. Guess I will have to wait (years? lol) for something worthy to try again.

It seems they are not willing to fix anything and their codebase is a complete failure with shining fastfat from MS saving this entire circus from reinstall.

<p align="center">
<img src="https://github.com/hfiref0x/hfiref0x.github.io/blob/master/blog/img/05072025/this_is_fine_bsod.png" />
</p>
<p align="center">Pic 4. ReactOS 1998-2025.</p>
