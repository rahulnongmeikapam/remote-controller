# Remote Controller

![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Language](https://img.shields.io/badge/language-C%2B%2B17-orange)
![Crypto](https://img.shields.io/badge/crypto-OpenSSL%203.x-green)

A native Windows remote administration application for authorized use. It includes a remote agent, viewer, background service monitor, authenticated sessions, screen streaming, input control, encrypted chat, and a sandboxed remote file manager.

> Use this software only on computers you own or are explicitly authorized to administer.

## What Is Included

| Executable | Purpose |
|---|---|
| `rc_agent.exe` | Runs on the remote computer and shares its screen, receives input, and handles remote operations. |
| `rc_viewer.exe` | Runs on the operator computer and connects to the agent. |
| `rc_service.exe` | Optional background monitor for unattended startup and agent launching. |

## Requirements

- Windows 10 or Windows 11 recommended.
- C++17 compiler: Visual Studio 2019+ or MinGW-w64.
- CMake 3.20 or newer.
- OpenSSL 3.x development package with `libcrypto`.
- Git, if cloning from GitHub.

### Recommended Windows setup with vcpkg

```cmd
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg.exe install openssl:x64-windows
```

You may use another OpenSSL installation. Set `OPENSSL_ROOT_DIR` to the directory containing the OpenSSL `include` and `lib` folders.

## Quick Build

Open Command Prompt in this repository and run:

```cmd
build.bat
```

The script automatically detects a standard vcpkg installation at `C:\Users\<username>\vcpkg`. For another vcpkg location:

```cmd
set VCPKG_ROOT=C:\vcpkg
build.bat
```

For a manually installed OpenSSL directory:

```cmd
set OPENSSL_ROOT_DIR=C:\Program Files\OpenSSL-Win64
build.bat
```

The build creates:

```text
build\Release\rc_agent.exe
build\Release\rc_viewer.exe
build\Release\rc_service.exe
build\Release\remote_crypto_tests.exe
```

The script also runs the crypto test suite automatically.

## Manual CMake Build

### Visual Studio

```cmd
cmake -S . -B build -DBUILD_TESTING=ON ^
  -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake ^
  -DOPENSSL_ROOT_DIR=C:\vcpkg\installed\x64-windows
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

### MinGW

Use a MinGW terminal with OpenSSL development files available:

```cmd
cmake -G "MinGW Makefiles" -S . -B build-mingw -DBUILD_TESTING=ON ^
  -DOPENSSL_ROOT_DIR=C:\path\to\openssl
cmake --build build-mingw
ctest --test-dir build-mingw --output-on-failure
```

## Running the Application

### Agent

1. Run `build\Release\rc_agent.exe` on the remote computer.
2. Choose the capture scale and JPEG quality.
3. Set the listening port, default `5000`.
4. Start the agent server.
5. Allow the application through the Windows Firewall when prompted.

### Viewer

1. Run `build\Release\rc_viewer.exe` on the operator computer.
2. Enter the agent IP address and port.
3. Connect and approve the request on the agent when interactive approval is enabled.

Command-line connection:

```cmd
rc_viewer.exe <agent-ip> [port]
```

### Service monitor

```cmd
build\Release\rc_service.exe
build\Release\rc_service.exe --service
```

## Features

- GDI screen capture with JPEG encoding and frame-difference skipping.
- Mouse and keyboard control.
- Encrypted chat and clipboard exchange.
- Dual-pane remote file manager.
- Upload and download with size, order, and SHA-256 verification.
- Remote file access restricted to `C:\RemoteControllerShare`.
- Delete and directory creation results with Windows error codes.
- Atomic session state and coordinated thread shutdown.
- Packet size limits and sequence/replay validation.

## Security Design

The active crypto implementation is in `common/crypto/` and uses OpenSSL 3.x:

```text
ECDH P-256
    -> HKDF-SHA256
    -> separate client-to-agent and agent-to-client keys
    -> AES-256-GCM
```

The handshake exchanges a standard 65-byte uncompressed P-256 public point:

```text
04 || X (32 bytes) || Y (32 bytes)
```

Encrypted packets contain:

```text
12-byte nonce || ciphertext || 16-byte authentication tag
```

Packet headers are authenticated as AES-GCM AAD. Authentication failures reject packets before application processing.

## Repository Layout

```text
apps/                  Windows agent, viewer, and service applications
common/protocol/       Shared packet protocol and networking
common/crypto/         Platform-independent OpenSSL crypto module
tests/                 Crypto tests
third_party/stb/       Image codec dependencies
CMakeLists.txt         CMake build definition
build.bat              One-command Windows build and test script
```

## Troubleshooting

### `CMake was not found`

Install CMake 3.20 or newer and add it to `PATH`.

### `Could NOT find OpenSSL`

Install OpenSSL 3.x development files or vcpkg OpenSSL:

```cmd
C:\vcpkg\vcpkg.exe install openssl:x64-windows
set VCPKG_ROOT=C:\vcpkg
build.bat
```

### `bcrypt.dll` errors

The active GitHub package no longer uses Windows CNG or CryptoAPI for application cryptography. Check that the OpenSSL 3.x `libcrypto` runtime DLL is available beside the executable or on `PATH`.

### Firewall or connection failure

- Confirm the agent is listening on the configured port.
- Use the correct IP address.
- Allow the executable through Windows Firewall.
- Verify both computers can reach each other over TCP.

### Build logs

Use verbose CMake output:

```cmd
cmake --build build --config Release --verbose
```

## Limitations

- Windows GUI, screen capture, input, and service features are Windows-specific.
- Linux crypto preparation is provided through the OpenSSL module, but the full GUI application is not yet a Linux application.
- File resume, transfer progress, cancellation, and persistent checkpoints are not implemented.
- Multi-monitor capture and coordinate mapping are incomplete.
- The service monitor is not a native Windows Service implementation.

## License and Authorization

Preserve the project license and permission notice when redistributing this software. Always obtain authorization before accessing another computer.
