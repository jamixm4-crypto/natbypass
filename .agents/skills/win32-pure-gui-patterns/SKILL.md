---
name: win32-pure-gui-patterns
description: >-
  Best practices, memory safety rules, and threading guidelines for developing high-performance native Win32 GDI/User32 applications in pure Go without CGO.
  Use when designing Windows GUI apps, handling custom owner-drawn controls, multi-resolution icons, Dark Mode, or avoiding cross-thread deadlocks.
---

# Pure Go Win32 GUI Development Guidelines

## 1. Golden Rules of Win32 Threading in Go

### ⚠️ Never Call Win32 Window APIs from Background Goroutines
- In Win32, calling APIs like `GetWindowTextW`, `SetWindowTextW`, `SendMessageW`, or `DestroyWindow` on a window or control created by another thread sends a synchronous message to that thread's message queue.
- If the calling background thread holds a mutex (e.g. `logMutex`) and the UI thread is processing an event or acquiring that same mutex, **a permanent deadlock occurs**.

### Solution: Decoupled State & UI Polling
1. Background goroutines only mutate in-memory Go data structures (slices, maps, structs) under lightweight mutexes.
2. The UI thread periodically refreshes the controls using `WM_TIMER` (e.g. 1–2s tick) or `PostMessageW` (which is asynchronous and non-blocking).

---

## 2. Safe Owner-Drawn Controls & Control Creation

### ⚠️ Pre-initialize Control Metadata Before `CreateWindowExW`
- Controls created with `BS_OWNERDRAW` or `WS_VISIBLE` trigger synchronous `WM_DRAWITEM` and `WM_CTLCOLOR*` messages **DURING** the `procCreateWindowExW.Call(...)` execution before it returns.
- Store button labels and control types in global lookup tables **BEFORE** calling `procCreateWindowExW`.

```go
// CORRECT:
buttonLabels[id] = text
buttonTypes[id] = bType
hwnd, _, _ := procCreateWindowExW.Call(...)
```

---

## 3. High-DPI, Dark Mode & Resource Embedding

### Dark Title Bar (Windows 10 / 11)
```go
// DWMWA_USE_IMMERSIVE_DARK_MODE (20 on Win11 / Win10 20H1+)
darkMode := int32(1)
procDwmSetWindowAttribute.Call(hwnd, 20, uintptr(unsafe.Pointer(&darkMode)), 4)
```

### Embedding Multi-Resolution Application Icons
1. Use `github.com/akavel/rsrc` to compile `app.ico` (with 16x16, 32x32, 48x48, 256x256) into `rsrc_windows_amd64.syso`.
2. Place `rsrc_windows_amd64.syso` in the `main` package directory.
3. The Go compiler automatically links the Windows PE resource section into the final `.exe`.
