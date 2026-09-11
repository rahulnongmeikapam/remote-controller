/*
 * Remote Controller - Common Protocol & Encryption Header
 * Uses key exchange + AES-256 encryption
 * Windows CryptoAPI for cryptography
 */

#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#if defined(__has_include)
#if __has_include(<mstcpip.h>)
#include <mstcpip.h>
#endif
#endif
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <functional>
#include <atomic>
#include <cstdlib>
#include "../crypto/Crypto.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#ifndef SIO_KEEPALIVE_VALS
#define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR, 4)
#endif

#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256 12
#endif

#ifndef CALG_SHA_256
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

// ============================================================================
// CONSOLE UI HELPERS
// ============================================================================

namespace Console {
    enum Color {
        BLACK = 0, BLUE = 1, GREEN = 2, CYAN = 3, RED = 4, MAGENTA = 5,
        YELLOW = 6, WHITE = 7, GRAY = 8, BRIGHT_BLUE = 9, BRIGHT_GREEN = 10,
        BRIGHT_CYAN = 11, BRIGHT_RED = 12, BRIGHT_MAGENTA = 13, BRIGHT_YELLOW = 14, BRIGHT_WHITE = 15
    };

    inline void InitConsole() {
        // Enable UTF-8 output
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        // Enable ANSI/VT100 sequences
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hOut, &mode);
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    inline void SetColor(Color fg, Color bg = BLACK) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), (WORD)(fg | (bg << 4)));
    }

    inline void ResetColor() {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), WHITE);
    }

    inline void ClearScreen() {
        system("cls");
    }

    inline void SetTitle(const char* title) {
        SetConsoleTitleA(title);
    }

    inline void PrintLogo() {
        // Logo banner removed
    }

    inline void PrintBox(const std::string& title, const std::string& content) {
        SetColor(BRIGHT_WHITE);
        std::cout << "\n   +";
        for (size_t i = 0; i < title.length() + 4; i++) std::cout << "-";
        std::cout << "+\n";
        std::cout << "   |  " << title << "  |\n";
        std::cout << "   +";
        for (size_t i = 0; i < title.length() + 4; i++) std::cout << "-";
        std::cout << "+\n";
        ResetColor();
        SetColor(GRAY);
        std::cout << "   " << content << "\n";
        ResetColor();
    }

    inline void PrintStatus(const std::string& msg, Color color = GREEN) {
        SetColor(BRIGHT_WHITE);
        std::cout << "   [";
        SetColor(color);
        std::cout << "*";
        SetColor(BRIGHT_WHITE);
        std::cout << "] ";
        ResetColor();
        std::cout << msg << std::endl;
    }

    inline void PrintError(const std::string& msg) {
        PrintStatus(msg, RED);
    }

    inline void PrintSuccess(const std::string& msg) {
        PrintStatus(msg, GREEN);
    }

    inline void PrintInfo(const std::string& msg) {
        PrintStatus(msg, CYAN);
    }

    inline void PrintWarning(const std::string& msg) {
        PrintStatus(msg, YELLOW);
    }

    inline std::string GetInput(const std::string& prompt) {
        SetColor(BRIGHT_YELLOW);
        std::cout << "\n   > " << prompt << ": ";
        SetColor(BRIGHT_WHITE);
        std::string input;
        std::getline(std::cin, input);
        ResetColor();
        return input;
    }

    inline int GetMenuChoice(const std::vector<std::string>& options) {
        SetColor(BRIGHT_WHITE);
        std::cout << "\n   +======================================+\n";
        std::cout << "   |          SELECT OPTION               |\n";
        std::cout << "   +======================================+\n";
        for (size_t i = 0; i < options.size(); i++) {
            std::cout << "   |  ";
            SetColor(BRIGHT_CYAN);
            std::cout << "[" << (i + 1) << "]";
            SetColor(BRIGHT_WHITE);
            std::cout << " " << options[i];
            for (size_t j = options[i].length(); j < 30; j++) std::cout << " ";
            std::cout << "|\n";
        }
        std::cout << "   +======================================+\n";
        ResetColor();

        std::string input = GetInput("Enter choice");
        try {
            return std::stoi(input);
        } catch (...) {
            return -1;
        }
    }
}

inline LONG WINAPI RemoteControllerUnhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo) {
    const DWORD exceptionCode = exceptionInfo && exceptionInfo->ExceptionRecord
        ? exceptionInfo->ExceptionRecord->ExceptionCode : 0;
    const ULONG_PTR exceptionAddress = exceptionInfo && exceptionInfo->ExceptionRecord
        ? (ULONG_PTR)exceptionInfo->ExceptionRecord->ExceptionAddress : 0;

    char modulePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, modulePath, sizeof(modulePath));
    char faultModule[MAX_PATH] = "unknown";
    HMODULE faultModuleHandle = nullptr;
    MEMORY_BASIC_INFORMATION memoryInfo{};
    if (exceptionAddress && VirtualQuery((LPCVOID)exceptionAddress, &memoryInfo, sizeof(memoryInfo)) &&
        memoryInfo.AllocationBase) {
        faultModuleHandle = (HMODULE)memoryInfo.AllocationBase;
        GetModuleFileNameA(faultModuleHandle, faultModule, sizeof(faultModule));
    }

    void* stack[16] = {};
    typedef USHORT (WINAPI* CaptureStackBackTraceFn)(DWORD, DWORD, void**, PDWORD);
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    CaptureStackBackTraceFn captureStack = kernel32
        ? reinterpret_cast<CaptureStackBackTraceFn>(GetProcAddress(kernel32, "RtlCaptureStackBackTrace"))
        : nullptr;
    USHORT stackCount = captureStack ? captureStack(0, 16, stack, nullptr) : 0;
    std::ofstream log("remote_controller_crash.log", std::ios::app);
    if (log.is_open()) {
        log << "Unhandled exception in " << modulePath
            << ": code=0x" << std::uppercase << std::hex << exceptionCode
            << ", address=0x" << exceptionAddress
            << ", module=" << faultModule << std::dec << "\n";
        log << "Stack:";
        for (USHORT i = 0; i < stackCount; ++i) {
            log << " 0x" << std::uppercase << std::hex << (ULONG_PTR)stack[i];
        }
        log << std::dec << "\n";
        log.flush();
    }

    char message[512] = {};
    std::snprintf(message, sizeof(message),
                  "Remote Controller crashed.\n\nException: 0x%08lX\nAddress: 0x%p\nModule: %s\n\nDetails saved to remote_controller_crash.log.",
                  (unsigned long)exceptionCode,
                  (void*)exceptionAddress,
                  faultModule);
    MessageBoxA(nullptr, message, "Remote Controller Crash", MB_OK | MB_ICONERROR | MB_TOPMOST);
    return EXCEPTION_EXECUTE_HANDLER;
}

inline void InstallCrashDiagnostics() {
    SetUnhandledExceptionFilter(RemoteControllerUnhandledExceptionFilter);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
}

// ============================================================================
// PROTOCOL DEFINITIONS
// ============================================================================

#define RC_VERSION          "2.0.0"
#define RC_DEFAULT_PORT     5000
#define RC_CONTROL_PORT     5001
#define RC_MAGIC            0x52435043  // "RCPC"

constexpr uint32_t RC_MAX_PACKET_SIZE = 16u * 1024u * 1024u;
constexpr uint32_t RC_MAX_CONTROL_PACKET_SIZE = 4096u;
constexpr uint32_t RC_MAX_CHAT_PACKET_SIZE = 1024u * 1024u;
constexpr uint32_t RC_MAX_FILE_CHUNK_SIZE = 1024u * 1024u;
constexpr uint32_t RC_MAX_FILE_LIST_SIZE = 4u * 1024u * 1024u;

// Message types
enum MessageType : uint8_t {
    MSG_HANDSHAKE_INIT      = 0x01,  // Viewer -> Agent: Start handshake
    MSG_HANDSHAKE_PUBKEY    = 0x02,  // Exchange ECDH public keys
    MSG_HANDSHAKE_VERIFY    = 0x03,  // Verify shared secret
    MSG_HANDSHAKE_OK        = 0x04,  // Handshake complete
    MSG_CONNECT_REQUEST     = 0x10,  // Viewer requests connection
    MSG_CONNECT_ACCEPT      = 0x11,  // Agent accepts
    MSG_CONNECT_REJECT      = 0x12,  // Agent rejects
    MSG_FRAME_DATA          = 0x20,  // Encrypted frame data
    MSG_CONTROL_MOUSE       = 0x30,  // Mouse event
    MSG_CONTROL_KEYBOARD    = 0x31,  // Keyboard event
    MSG_SPECIAL_KEY         = 0x32,  // Ctrl+Alt+Del, Win+L, TaskMgr
    MSG_CLIPBOARD_TEXT      = 0x35,  // Encrypted clipboard text exchange
    MSG_CHAT_TEXT           = 0x36,  // Encrypted live text chat
    MSG_PING                = 0x40,
    MSG_PONG                = 0x41,
    MSG_FILE_TRANSFER_BEGIN = 0x50,  // File transfer start
    MSG_FILE_TRANSFER_CHUNK = 0x51,  // File transfer data chunk
    MSG_FILE_TRANSFER_END   = 0x52,  // File transfer complete
    MSG_FILE_TRANSFER_REQ   = 0x53,  // Pre-transfer handshake request
    MSG_FILE_TRANSFER_ACK   = 0x54,  // Pre-transfer handshake response
    MSG_FILE_TRANSFER_CHUNK_ACK = 0x55,// Chunk verification ACK
    MSG_FILE_LIST_REQ       = 0x56,  // Request directory listing
    MSG_FILE_LIST_RESP      = 0x57,  // Directory listing response
    MSG_FILE_DELETE_REQ     = 0x58,  // Remote file/folder deletion
    MSG_FILE_MKDIR_REQ      = 0x59,  // Remote directory creation
    MSG_FILE_OPERATION_RESULT = 0x5A, // File operation result
    MSG_FILE_DOWNLOAD_REQ   = 0x5B,  // Request remote file download
    MSG_DISCONNECT          = 0xFF
};

#pragma pack(push, 1)

// Base packet header
struct PacketHeader {
    uint32_t magic;       // RC_MAGIC
    uint8_t  type;        // MessageType
    uint32_t length;      // Payload length
    uint32_t sequence;    // Packet sequence number
};

// Handshake init message
struct HandshakeInit {
    char     version[16];      // Version string
    char     deviceId[32];     // Unique device ID
    uint8_t  unattendedMode;   // 0 = require approval, 1 = auto-accept
};

// Standard P-256 uncompressed public point: 04 || X(32) || Y(32).
struct ECDHKeyExchange {
    uint8_t  publicKey[65];
};

// Connection request (from viewer)
struct ConnectRequest {
    char     viewerName[64];   // Name/description of viewer
    uint32_t requestedFPS;     // Requested framerate
    uint8_t  quality;          // JPEG quality (1-100)
    char     password[64];     // Unattended access password
};

// Control packet (mouse/keyboard)
struct ControlPacket {
    uint8_t  kind;        // 1 = mouse, 2 = keyboard
    uint8_t  mouseType;   // 1=move, 2=Ldown, 3=Lup, 4=Rdown, 5=Rup, 6=scroll
    int32_t  x;           // Mouse X (in image coords)
    int32_t  y;           // Mouse Y
    int16_t  scrollDelta; // Mouse scroll delta
    uint16_t vk;          // Virtual key code
    uint8_t  keyDown;     // 1 = down, 0 = up
};

// Frame header
struct FrameHeader {
    uint32_t frameId;
    uint32_t dataSize;    // Size of JPEG data
    uint16_t width;       // Original width
    uint16_t height;      // Original height
    uint8_t  quality;     // JPEG quality used
    float    scale;       // Scale factor used
};

struct FileTransferBegin {
    uint32_t transferId;
    uint64_t fileSize;
    uint32_t chunkSize;
    uint8_t sha256[32];
    char     fileName[260];
};

struct FileTransferChunkHeader {
    uint32_t transferId;
    uint32_t chunkIndex;
    uint32_t chunkSize;
};

struct FileTransferEnd {
    uint32_t transferId;
    uint32_t status;
};

struct FileTransferRequest {
    uint32_t transferId;
    uint64_t fileSize;
    uint32_t chunkSize;
    uint32_t totalChunks;
    uint8_t sha256[32];
    char     fileName[260];
};

struct FileTransferResponse {
    uint32_t transferId;
    uint8_t  accepted;   // 1 = accept, 0 = reject
    uint64_t resumeOffset;
};

struct FileTransferChunkAck {
    uint32_t transferId;
    uint32_t chunkIndex;
    uint8_t  status;     // 1 = OK, 0 = Fail
};

struct SpecialKeyPacket {
    uint8_t keyCmd;      // 1 = Ctrl+Alt+Del, 2 = Win+L, 3 = TaskMgr
};

struct FileListRequest {
    char path[260];
};

struct FileItem {
    char name[260];
    uint64_t size;
    uint8_t isDir;
    uint64_t lastModified;
};

struct FileListResponseHeader {
    char path[260];
    uint32_t itemCount;
};

struct FileDeleteRequest {
    char path[260];
};

struct FileMkdirRequest {
    char path[260];
};

struct FileDownloadRequest {
    char path[260];
};

struct FileOperationResult {
    uint8_t operation;
    uint8_t success;
    uint32_t errorCode;
    char path[260];
};

#pragma pack(pop)

inline uint32_t GetPacketPayloadLimit(uint8_t type) {
    switch (type) {
    case MSG_CONTROL_MOUSE:
    case MSG_CONTROL_KEYBOARD:
    case MSG_SPECIAL_KEY:
    case MSG_PING:
    case MSG_PONG:
    case MSG_DISCONNECT:
        return RC_MAX_CONTROL_PACKET_SIZE;
    case MSG_CHAT_TEXT:
    case MSG_CLIPBOARD_TEXT:
        return RC_MAX_CHAT_PACKET_SIZE;
    case MSG_FILE_TRANSFER_CHUNK:
        return RC_MAX_FILE_CHUNK_SIZE + sizeof(FileTransferChunkHeader);
    case MSG_FILE_LIST_RESP:
        return RC_MAX_FILE_LIST_SIZE;
    default:
        return RC_MAX_PACKET_SIZE;
    }
}

// ============================================================================
// ENCRYPTION (Windows CNG, loaded at runtime for MinGW compatibility)
// ============================================================================

typedef LONG NTSTATUS;
typedef void* BCRYPT_ALG_HANDLE;
typedef void* BCRYPT_KEY_HANDLE;
typedef void* BCRYPT_SECRET_HANDLE;

struct BCRYPT_ECCKEY_BLOB_LOCAL {
    ULONG dwMagic;
    ULONG cbKey;
};

struct BCRYPT_KDF_PARAMETER_LOCAL {
    LPCWSTR pszParameter;
    PUCHAR pbBuffer;
    ULONG cbBuffer;
};

struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_LOCAL {
    ULONG cbSize;
    ULONG dwInfoVersion;
    PUCHAR pbNonce;
    ULONG cbNonce;
    PUCHAR pbAuthData;
    ULONG cbAuthData;
    PUCHAR pbTag;
    ULONG cbTag;
    PUCHAR pbMacContext;
    ULONG cbMacContext;
    ULONG cbAAD;
    ULONGLONG cbData;
    ULONG dwFlags;
};

constexpr NTSTATUS RC_STATUS_SUCCESS = 0;
constexpr ULONG RC_BCRYPT_ECCPUBLIC_MAGIC = 0x31534345;
constexpr ULONG RC_BCRYPT_KDF_HASH = 0x00000002;
constexpr ULONG RC_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1;

#if 0
class LegacySecureChannel {
private:
    HCRYPTPROV hProv = 0;
    HMODULE bcrypt = nullptr;
    BCRYPT_ALG_HANDLE ecdhAlgorithm = nullptr;
    BCRYPT_KEY_HANDLE privateKey = nullptr;
    BCRYPT_SECRET_HANDLE sharedSecret = nullptr;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> aesKey;
    bool initialized = false;
    bool legacyMode = false;

    typedef NTSTATUS (WINAPI* BCryptOpenAlgorithmProviderFn)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
    typedef NTSTATUS (WINAPI* BCryptCloseAlgorithmProviderFn)(BCRYPT_ALG_HANDLE, ULONG);
    typedef NTSTATUS (WINAPI* BCryptGenerateKeyPairFn)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptFinalizeKeyPairFn)(BCRYPT_KEY_HANDLE, ULONG);
    typedef NTSTATUS (WINAPI* BCryptExportKeyFn)(BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
    typedef NTSTATUS (WINAPI* BCryptImportKeyPairFn)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptSecretAgreementFn)(BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_SECRET_HANDLE*, ULONG);
    typedef NTSTATUS (WINAPI* BCryptDeriveKeyFn)(BCRYPT_SECRET_HANDLE, LPCWSTR, BCRYPT_KDF_PARAMETER_LOCAL*, PUCHAR, ULONG, ULONG*, ULONG);
    typedef NTSTATUS (WINAPI* BCryptDestroyKeyFn)(BCRYPT_KEY_HANDLE);
    typedef NTSTATUS (WINAPI* BCryptDestroySecretFn)(BCRYPT_SECRET_HANDLE);
    typedef NTSTATUS (WINAPI* BCryptGetPropertyFn)(void*, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
    typedef NTSTATUS (WINAPI* BCryptSetPropertyFn)(void*, LPCWSTR, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptGenerateSymmetricKeyFn)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptEncryptFn)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
    typedef NTSTATUS (WINAPI* BCryptDecryptFn)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);

    BCryptOpenAlgorithmProviderFn openAlgorithm = nullptr;
    BCryptCloseAlgorithmProviderFn closeAlgorithm = nullptr;
    BCryptGenerateKeyPairFn generateKeyPair = nullptr;
    BCryptFinalizeKeyPairFn finalizeKeyPair = nullptr;
    BCryptExportKeyFn exportKey = nullptr;
    BCryptImportKeyPairFn importKeyPair = nullptr;
    BCryptSecretAgreementFn secretAgreement = nullptr;
    BCryptDeriveKeyFn deriveKey = nullptr;
    BCryptDestroyKeyFn destroyKey = nullptr;
    BCryptDestroySecretFn destroySecret = nullptr;
    BCryptGetPropertyFn getProperty = nullptr;
    BCryptSetPropertyFn setProperty = nullptr;
    BCryptGenerateSymmetricKeyFn generateSymmetricKey = nullptr;
    BCryptEncryptFn encryptCng = nullptr;
    BCryptDecryptFn decryptCng = nullptr;

    template <typename T>
    bool LoadCngFunction(T& target, const char* name) {
        target = reinterpret_cast<T>(GetProcAddress(bcrypt, name));
        return target != nullptr;
    }

    static std::string FormatStatus(NTSTATUS status) {
        std::ostringstream stream;
        stream << std::uppercase << std::hex << std::setw(8) << std::setfill('0')
               << (static_cast<uint32_t>(status));
        return stream.str();
    }

    bool LoadCng() {
        bcrypt = LoadLibraryA("bcrypt.dll");
        if (!bcrypt) {
            Console::PrintError("LoadLibraryA(bcrypt.dll) failed: Win32 error " + std::to_string(GetLastError()));
            return false;
        }

#define RC_LOAD_CNG(fn, name) \
        if (!LoadCngFunction(fn, name)) { \
            Console::PrintError(std::string("Missing CNG function ") + name); \
            return false; \
        }
        RC_LOAD_CNG(openAlgorithm, "BCryptOpenAlgorithmProvider");
        RC_LOAD_CNG(closeAlgorithm, "BCryptCloseAlgorithmProvider");
        RC_LOAD_CNG(generateKeyPair, "BCryptGenerateKeyPair");
        RC_LOAD_CNG(finalizeKeyPair, "BCryptFinalizeKeyPair");
        RC_LOAD_CNG(exportKey, "BCryptExportKey");
        RC_LOAD_CNG(importKeyPair, "BCryptImportKeyPair");
        RC_LOAD_CNG(secretAgreement, "BCryptSecretAgreement");
        RC_LOAD_CNG(deriveKey, "BCryptDeriveKey");
        RC_LOAD_CNG(destroyKey, "BCryptDestroyKey");
        RC_LOAD_CNG(destroySecret, "BCryptDestroySecret");
        RC_LOAD_CNG(getProperty, "BCryptGetProperty");
        RC_LOAD_CNG(setProperty, "BCryptSetProperty");
        RC_LOAD_CNG(generateSymmetricKey, "BCryptGenerateSymmetricKey");
        RC_LOAD_CNG(encryptCng, "BCryptEncrypt");
        RC_LOAD_CNG(decryptCng, "BCryptDecrypt");
#undef RC_LOAD_CNG
        return true;
    }

    bool IsLegacyWindows() const {
        char useCng[8] = {};
        DWORD useCngLength = GetEnvironmentVariableA("RC_USE_CNG", useCng, sizeof(useCng));
        if (useCngLength > 0 && (useCng[0] == '1' || useCng[0] == 'y' || useCng[0] == 'Y')) {
            return false;
        }

        // Compatibility mode is the safe default because some VM images
        // expose a bcrypt.dll that crashes inside the provider.
        return true;

    }

    bool BuildSessionKey(const uint8_t* iv, HCRYPTKEY& hKey) {
        hKey = 0;
        if (hProv == 0 || aesKey.empty() || !iv) return false;

        HCRYPTHASH hHash = 0;
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            return false;
        }

        bool ok = CryptHashData(hHash, aesKey.data(), (DWORD)aesKey.size(), 0) == TRUE;
        DWORD flags = CRYPT_EXPORTABLE | (256 << 16);

        if (ok) {
            ok = CryptDeriveKey(hProv, CALG_AES_256, hHash, flags, &hKey) == TRUE;
        }

        if (ok) {
            DWORD mode = CRYPT_MODE_CBC;
            ok = CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0) == TRUE;
        }

        if (ok) {
            ok = CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0) == TRUE;
        }

        CryptDestroyHash(hHash);

        if (!ok && hKey) {
            CryptDestroyKey(hKey);
            hKey = 0;
        }
        return ok;
    }

public:
    LegacySecureChannel() {}

    ~LegacySecureChannel() {
        Cleanup();
    }

    void Cleanup() {
        if (sharedSecret && destroySecret) {
            destroySecret(sharedSecret);
            sharedSecret = nullptr;
        }
        if (privateKey && destroyKey) {
            destroyKey(privateKey);
            privateKey = nullptr;
        }
        if (ecdhAlgorithm && closeAlgorithm) {
            closeAlgorithm(ecdhAlgorithm, 0);
            ecdhAlgorithm = nullptr;
        }
        if (bcrypt) {
            FreeLibrary(bcrypt);
            bcrypt = nullptr;
        }
        if (hProv != 0) {
            CryptReleaseContext(hProv, 0);
            hProv = 0;
        }
        publicKey.clear();
        aesKey.clear();
        initialized = false;
        legacyMode = false;
    }

    bool Initialize() {
        Cleanup();

        if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            Console::PrintError("Failed to initialize CryptoAPI context");
            return false;
        }

        // Older VM images can expose a defective bcrypt.dll implementation.
        // Keep them usable with the legacy CryptoAPI path instead of crashing
        // inside the provider before a session can be established.
        if (IsLegacyWindows()) {
            legacyMode = true;
            publicKey.resize(32);
            if (!CryptGenRandom(hProv, (DWORD)publicKey.size(), publicKey.data())) {
                Console::PrintError("Failed to generate legacy session material");
                return false;
            }
            initialized = true;
            Console::PrintWarning("Legacy Windows crypto compatibility mode enabled");
            return true;
        }

        if (!LoadCng()) return false;

        NTSTATUS status = openAlgorithm(&ecdhAlgorithm, L"ECDH_P256", nullptr, 0);
        if (status != RC_STATUS_SUCCESS) {
            Console::PrintError("BCryptOpenAlgorithmProvider(ECDH_P256) failed: NTSTATUS 0x" +
                                FormatStatus(status));
            return false;
        }

        status = generateKeyPair(ecdhAlgorithm, &privateKey, 256, 0);
        if (status != RC_STATUS_SUCCESS) {
            Console::PrintError("BCryptGenerateKeyPair failed: NTSTATUS 0x" + FormatStatus(status));
            return false;
        }

        status = finalizeKeyPair(privateKey, 0);
        if (status != RC_STATUS_SUCCESS) {
            Console::PrintError("BCryptFinalizeKeyPair failed: NTSTATUS 0x" + FormatStatus(status));
            return false;
        }

        ULONG publicSize = 0;
        status = exportKey(privateKey, nullptr, L"ECCPUBLICBLOB", nullptr, 0, &publicSize, 0);
        if (status != RC_STATUS_SUCCESS || publicSize > 128) {
            Console::PrintError("BCryptExportKey size query failed: NTSTATUS 0x" + FormatStatus(status));
            return false;
        }
        publicKey.resize(publicSize);
        status = exportKey(privateKey, nullptr, L"ECCPUBLICBLOB", publicKey.data(), publicSize, &publicSize, 0);
        if (status != RC_STATUS_SUCCESS) {
            Console::PrintError("BCryptExportKey failed: NTSTATUS 0x" + FormatStatus(status));
            return false;
        }
        publicKey.resize(publicSize);

        initialized = true;
        return true;
    }

    const std::vector<uint8_t>& GetPublicKey() const {
        return publicKey;
    }

    bool DeriveSharedSecret(const uint8_t* peerPublicKey, uint32_t peerKeyLen) {
        if (!initialized || !peerPublicKey || peerKeyLen == 0 || peerKeyLen > 128) return false;

        if (legacyMode) {
            if (!peerPublicKey || peerKeyLen == 0 || peerKeyLen > 128) return false;
            std::vector<uint8_t> peer(peerPublicKey, peerPublicKey + peerKeyLen);
            std::vector<uint8_t> material;
            material.reserve(publicKey.size() + peer.size());
            if (std::lexicographical_compare(peer.begin(), peer.end(), publicKey.begin(), publicKey.end())) {
                material.insert(material.end(), peer.begin(), peer.end());
                material.insert(material.end(), publicKey.begin(), publicKey.end());
            } else {
                material.insert(material.end(), publicKey.begin(), publicKey.end());
                material.insert(material.end(), peer.begin(), peer.end());
            }
            HCRYPTHASH hash = 0;
            if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hash)) return false;
            aesKey.resize(32);
            DWORD length = (DWORD)aesKey.size();
            bool ok = CryptHashData(hash, material.data(), (DWORD)material.size(), 0) == TRUE &&
                      CryptGetHashParam(hash, HP_HASHVAL, aesKey.data(), &length, 0) == TRUE &&
                      length == aesKey.size();
            CryptDestroyHash(hash);
            if (ok) Console::PrintWarning("Legacy CryptoAPI AES-CBC compatibility mode enabled");
            return ok;
        }

        if (!privateKey) return false;

        BCRYPT_KEY_HANDLE peerKey = nullptr;
        if (importKeyPair(ecdhAlgorithm, nullptr, L"ECCPUBLICBLOB", &peerKey,
                          const_cast<PUCHAR>(peerPublicKey), peerKeyLen, 0) != RC_STATUS_SUCCESS) {
            return false;
        }
        bool ok = secretAgreement(privateKey, peerKey, &sharedSecret, 0) == RC_STATUS_SUCCESS;
        destroyKey(peerKey);
        if (!ok) {
            Console::PrintError("Failed to perform ECDH agreement");
            return false;
        }

        wchar_t hashName[] = L"SHA256";
        BCRYPT_KDF_PARAMETER_LOCAL parameter{L"HashAlgorithm", (PUCHAR)hashName, sizeof(hashName)};
        aesKey.resize(32);
        ULONG derivedSize = 0;
        ok = deriveKey(sharedSecret, L"HASH", &parameter, aesKey.data(), (ULONG)aesKey.size(), &derivedSize, 0) == RC_STATUS_SUCCESS &&
             derivedSize == aesKey.size();
        if (!ok) return false;

        Console::PrintSuccess("Secure channel established (CNG ECDH P-256 + SHA-256)");
        return true;
    }

    std::vector<uint8_t> Encrypt(const uint8_t* data, size_t len,
                                 const uint8_t* aad = nullptr, size_t aadLen = 0) {
        if (hProv == 0 || aesKey.empty() || (!data && len > 0) || len > UINT32_MAX) return {};

        if (legacyMode) {
            uint8_t iv[16] = {};
            if (!CryptGenRandom(hProv, sizeof(iv), iv)) return {};
            HCRYPTKEY key = 0;
            if (!BuildSessionKey(iv, key)) return {};
            DWORD plainLength = (DWORD)len;
            DWORD bufferLength = plainLength + 16;
            std::vector<uint8_t> cipher(bufferLength);
            if (len > 0) memcpy(cipher.data(), data, len);
            BOOL ok = CryptEncrypt(key, 0, TRUE, 0, cipher.data(), &plainLength, bufferLength);
            CryptDestroyKey(key);
            if (!ok) return {};
            cipher.resize(plainLength);
            std::vector<uint8_t> result(sizeof(iv) + cipher.size());
            memcpy(result.data(), iv, sizeof(iv));
            if (!cipher.empty()) memcpy(result.data() + sizeof(iv), cipher.data(), cipher.size());
            return result;
        }

        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;
        std::vector<uint8_t> keyObject;
        ULONG objectLength = 0;
        ULONG resultLength = 0;
        uint8_t nonce[12] = {};
        uint8_t tag[16] = {};
        bool ok = CryptGenRandom(hProv, sizeof(nonce), nonce) == TRUE &&
            openAlgorithm(&algorithm, L"AES", nullptr, 0) == RC_STATUS_SUCCESS;
        wchar_t gcmMode[] = L"GCM";
        if (ok) ok = setProperty(algorithm, L"ChainingMode", (PUCHAR)gcmMode, sizeof(gcmMode), 0) == RC_STATUS_SUCCESS;
        if (ok) ok = getProperty(algorithm, L"ObjectLength", (PUCHAR)&objectLength, sizeof(objectLength), &resultLength, 0) == RC_STATUS_SUCCESS;
        if (ok) {
            keyObject.resize(objectLength);
            ok = generateSymmetricKey(algorithm, &key, keyObject.data(), objectLength,
                                      aesKey.data(), (ULONG)aesKey.size(), 0) == RC_STATUS_SUCCESS;
        }

        std::vector<uint8_t> cipher(len);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_LOCAL auth{};
        auth.cbSize = sizeof(auth);
        auth.dwInfoVersion = RC_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
        auth.pbNonce = nonce;
        auth.cbNonce = sizeof(nonce);
        auth.pbAuthData = const_cast<PUCHAR>(aad);
        auth.cbAuthData = (ULONG)aadLen;
        auth.pbTag = tag;
        auth.cbTag = sizeof(tag);
        if (ok) ok = encryptCng(key, const_cast<PUCHAR>(data), (ULONG)len, &auth,
                                nullptr, 0, cipher.data(), (ULONG)cipher.size(), &resultLength, 0) == RC_STATUS_SUCCESS;

        if (key && destroyKey) destroyKey(key);
        if (algorithm && closeAlgorithm) closeAlgorithm(algorithm, 0);
        if (!ok || resultLength != len) return {};

        std::vector<uint8_t> result(sizeof(nonce) + sizeof(tag) + cipher.size());
        memcpy(result.data(), nonce, sizeof(nonce));
        memcpy(result.data() + sizeof(nonce), tag, sizeof(tag));
        if (!cipher.empty()) memcpy(result.data() + sizeof(nonce) + sizeof(tag), cipher.data(), cipher.size());
        return result;
    }

    std::vector<uint8_t> Decrypt(const uint8_t* data, size_t len,
                                 const uint8_t* aad = nullptr, size_t aadLen = 0) {
        constexpr size_t nonceSize = 12;
        constexpr size_t tagSize = 16;
        if (hProv == 0 || aesKey.empty() || !data || len < nonceSize + tagSize || len - nonceSize - tagSize > UINT32_MAX) return {};

        if (legacyMode) {
            if (len < 16) return {};
            HCRYPTKEY key = 0;
            if (!BuildSessionKey(data, key)) return {};
            size_t cipherLength = len - 16;
            std::vector<uint8_t> plain(cipherLength);
            if (cipherLength > 0) memcpy(plain.data(), data + 16, cipherLength);
            DWORD plainLength = (DWORD)cipherLength;
            BOOL ok = CryptDecrypt(key, 0, TRUE, 0, plain.data(), &plainLength);
            CryptDestroyKey(key);
            if (!ok) return {};
            plain.resize(plainLength);
            return plain;
        }

        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;
        std::vector<uint8_t> keyObject;
        ULONG objectLength = 0;
        ULONG resultLength = 0;
        bool ok = openAlgorithm(&algorithm, L"AES", nullptr, 0) == RC_STATUS_SUCCESS;
        wchar_t gcmMode[] = L"GCM";
        if (ok) ok = setProperty(algorithm, L"ChainingMode", (PUCHAR)gcmMode, sizeof(gcmMode), 0) == RC_STATUS_SUCCESS;
        if (ok) ok = getProperty(algorithm, L"ObjectLength", (PUCHAR)&objectLength, sizeof(objectLength), &resultLength, 0) == RC_STATUS_SUCCESS;
        if (ok) {
            keyObject.resize(objectLength);
            ok = generateSymmetricKey(algorithm, &key, keyObject.data(), objectLength,
                                      aesKey.data(), (ULONG)aesKey.size(), 0) == RC_STATUS_SUCCESS;
        }

        size_t cipherLen = len - nonceSize - tagSize;
        std::vector<uint8_t> result(cipherLen);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_LOCAL auth{};
        auth.cbSize = sizeof(auth);
        auth.dwInfoVersion = RC_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
        auth.pbNonce = const_cast<PUCHAR>(data);
        auth.cbNonce = nonceSize;
        auth.pbAuthData = const_cast<PUCHAR>(aad);
        auth.cbAuthData = (ULONG)aadLen;
        auth.pbTag = const_cast<PUCHAR>(data + nonceSize);
        auth.cbTag = tagSize;
        if (ok) ok = decryptCng(key, const_cast<PUCHAR>(data + nonceSize + tagSize), (ULONG)cipherLen,
                                &auth, nullptr, 0, result.data(), (ULONG)result.size(), &resultLength, 0) == RC_STATUS_SUCCESS;

        if (key && destroyKey) destroyKey(key);
        if (algorithm && closeAlgorithm) closeAlgorithm(algorithm, 0);
        if (!ok || resultLength != cipherLen) return {};
        return result;
    }

    bool IsReady() const { return initialized && !aesKey.empty(); }
    size_t GetWireOverhead() const { return legacyMode ? 16 : 28; }
};
#endif

using SecureChannel = remote_controller::crypto::SecureChannel;

// ============================================================================
// CONTACT STORAGE (IP Address Book)
// ============================================================================

struct Contact {
    std::string name;
    std::string ip;
    uint16_t port;
    std::string deviceId;
    time_t lastConnected;
    bool unattendedEnabled;
};

class ContactManager {
private:
    std::map<std::string, Contact> contacts;
    std::string filePath;

public:
    ContactManager(const std::string& path = "contacts.dat") : filePath(path) {
        Load();
    }

    void Load() {
        std::ifstream file(filePath);
        if (!file.is_open()) return;

        contacts.clear();
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            
            std::istringstream iss(line);
            Contact c;
            std::string lastConn, unattended;
            
            if (std::getline(iss, c.name, '|') &&
                std::getline(iss, c.ip, '|') &&
                iss >> c.port) {
                iss.ignore();
                std::getline(iss, c.deviceId, '|');
                iss >> c.lastConnected;
                iss.ignore();
                iss >> c.unattendedEnabled;
                contacts[c.name] = c;
            }
        }
    }

    void Save() {
        std::ofstream file(filePath);
        file << "# Remote Controller Contact List\n";
        file << "# Format: name|ip|port|deviceId|lastConnected|unattended\n";
        
        for (const auto& kv : contacts) {
            const Contact& c = kv.second;
            file << c.name << "|" << c.ip << "|" << c.port << "|"
                 << c.deviceId << "|" << c.lastConnected << "|"
                 << c.unattendedEnabled << "\n";
        }
    }

    void AddContact(const Contact& c) {
        contacts[c.name] = c;
        Save();
    }

    bool RemoveContact(const std::string& name) {
        if (contacts.erase(name) > 0) {
            Save();
            return true;
        }
        return false;
    }

    Contact* GetContact(const std::string& name) {
        auto it = contacts.find(name);
        return (it != contacts.end()) ? &it->second : nullptr;
    }

    std::vector<Contact> GetAllContacts() const {
        std::vector<Contact> result;
        for (const auto& kv : contacts) {
            result.push_back(kv.second);
        }
        return result;
    }

    void DisplayContacts() {
        if (contacts.empty()) {
            Console::PrintInfo("No saved contacts.");
            return;
        }

        Console::SetColor(Console::BRIGHT_WHITE);
        std::cout << "\n   +====+====================+==================+=======+\n";
        std::cout << "   | #  | Name               | IP Address       | Port  |\n";
        std::cout << "   +====+====================+==================+=======+\n";
        
        int idx = 1;
        for (const auto& kv : contacts) {
            const Contact& c = kv.second;
            std::cout << "   | " << std::setw(2) << idx++ << " | "
                      << std::setw(18) << std::left << c.name.substr(0, 18) << " | "
                      << std::setw(16) << std::left << c.ip << " | "
                      << std::setw(5) << c.port << " |\n";
        }
        std::cout << "   +====+====================+==================+=======+\n";
        Console::ResetColor();
    }

    Contact* GetContactByIndex(int index) {
        if (index < 1 || index > (int)contacts.size()) return nullptr;
        auto it = contacts.begin();
        std::advance(it, index - 1);
        return &it->second;
    }
};

// ============================================================================
// NETWORK HELPERS
// ============================================================================

class NetworkHelper {
public:
    static bool InitWinsock() {
        WSADATA wsaData;
        return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
    }

    static void CleanupWinsock() {
        WSACleanup();
    }

    static SOCKET CreateTCPSocket() {
        return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }

    static bool SetSocketTimeout(SOCKET sock, int sendMs, int recvMs) {
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&sendMs, sizeof(sendMs));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&recvMs, sizeof(recvMs));
        return true;
    }

    static bool SetSocketNoDelay(SOCKET sock) {
        int flag = 1;
        return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag)) == 0;
    }

    static bool SetSocketKeepalive(SOCKET sock) {
        // Enable TCP keepalive
        int keepalive = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepalive, sizeof(keepalive));

        // Set keepalive parameters (Windows-specific)
        struct tcp_keepalive {
            ULONG onoff;
            ULONG keepalivetime;
            ULONG keepaliveinterval;
        } alive;
        alive.onoff = 1;
        alive.keepalivetime = 5000;      // 5 seconds before first probe
        alive.keepaliveinterval = 1000;  // 1 second between probes
        
        DWORD bytesReturned;
        WSAIoctl(sock, SIO_KEEPALIVE_VALS, &alive, sizeof(alive), nullptr, 0, &bytesReturned, nullptr, nullptr);
        
        return true;
    }

    static bool SetSocketBuffers(SOCKET sock, int sendBuf = 256 * 1024, int recvBuf = 256 * 1024) {
        // Larger buffers for better throughput
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&sendBuf, sizeof(sendBuf));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&recvBuf, sizeof(recvBuf));
        return true;
    }

    static bool SendAll(SOCKET sock, const void* data, size_t len) {
        const char* ptr = (const char*)data;
        size_t sent = 0;
        while (sent < len) {
            int r = send(sock, ptr + sent, (int)(len - sent), 0);
            if (r <= 0) return false;
            sent += r;
        }
        return true;
    }

    static bool RecvAll(SOCKET sock, void* data, size_t len) {
        char* ptr = (char*)data;
        size_t received = 0;
        while (received < len) {
            int r = recv(sock, ptr + received, (int)(len - received), 0);
            if (r <= 0) return false;
            received += r;
        }
        return true;
    }

    static bool SendPacket(SOCKET sock, uint8_t type, const void* payload, size_t payloadLen,
                          SecureChannel* crypto = nullptr, uint32_t seq = 0) {
        if (payloadLen > GetPacketPayloadLimit(type) || payloadLen > UINT32_MAX ||
            (payloadLen > 0 && payload == nullptr)) {
            return false;
        }

        PacketHeader header;
        header.magic = RC_MAGIC;
        header.type = type;
        header.sequence = seq;

        if (crypto && crypto->IsReady()) {
            header.length = crypto->GetWireOverhead() == 16 ? 0 :
                (uint32_t)(payloadLen + crypto->GetWireOverhead());
            auto encrypted = crypto->Encrypt((const uint8_t*)payload, payloadLen,
                                              (const uint8_t*)&header, sizeof(header));
            if (encrypted.empty()) return false;
            if (crypto->GetWireOverhead() == 16) header.length = (uint32_t)encrypted.size();
            if (encrypted.size() != header.length) return false;
            if (!SendAll(sock, &header, sizeof(header))) return false;
            if (!SendAll(sock, encrypted.data(), encrypted.size())) return false;
        } else {
            header.length = (uint32_t)payloadLen;
            if (!SendAll(sock, &header, sizeof(header))) return false;
            if (payloadLen > 0 && !SendAll(sock, payload, payloadLen)) return false;
        }
        return true;
    }

    static bool RecvPacket(SOCKET sock, PacketHeader& header, std::vector<uint8_t>& payload,
                          SecureChannel* crypto = nullptr, uint32_t* expectedSequence = nullptr) {
        if (!RecvAll(sock, &header, sizeof(header))) return false;
        if (header.magic != RC_MAGIC) return false;
        if (expectedSequence && header.sequence != *expectedSequence) return false;
        uint64_t wireLimit = GetPacketPayloadLimit(header.type);
        if (crypto && crypto->IsReady()) wireLimit += crypto->GetWireOverhead();
        if (header.length > wireLimit) return false;

        if (header.length > 0) {
            std::vector<uint8_t> raw(header.length);
            if (!RecvAll(sock, raw.data(), header.length)) return false;

            if (crypto && crypto->IsReady()) {
                payload = crypto->Decrypt(raw.data(), raw.size(),
                                          (const uint8_t*)&header, sizeof(header));
                if (payload.empty() && header.length > crypto->GetWireOverhead() + 16) return false;
            } else {
                payload = std::move(raw);
            }
        } else {
            payload.clear();
        }
        if (expectedSequence) {
            *expectedSequence = header.sequence + 1;
        }
        return true;
    }

    static std::string GetLocalIP() {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        
        struct addrinfo hints = {}, *info;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(hostname, nullptr, &hints, &info) == 0) {
            const sockaddr_in* addr = (const sockaddr_in*)info->ai_addr;
            const char* ip = inet_ntoa(addr->sin_addr);
            freeaddrinfo(info);
            return ip ? ip : "127.0.0.1";
        }
        return "127.0.0.1";
    }
};

inline bool ComputeFileSHA256(const std::string& path, uint8_t digest[32]) {
    if (!digest) return false;

    std::ifstream file(path.c_str(), std::ios::binary);
    if (!file.is_open()) return false;

    std::vector<char> buffer(64 * 1024);
    std::vector<uint8_t> contents;
    bool ok = true;
    while (file) {
        file.read(buffer.data(), (std::streamsize)buffer.size());
        std::streamsize count = file.gcount();
        if (count > 0) contents.insert(contents.end(), buffer.data(), buffer.data() + count);
    }
    if (!ok) return false;
    std::array<uint8_t, 32> result{};
    if (!remote_controller::crypto::SecureChannel::Sha256(contents.data(), contents.size(), result)) return false;
    memcpy(digest, result.data(), result.size());
    return true;
}

// ============================================================================
// DEVICE ID GENERATOR (from unique_generator.cpp)
// ============================================================================

#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")

class DeviceID {
public:
    static std::string Generate() {
        std::string combined;
        
        // Get volume serial
        DWORD serial = 0;
        GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
        combined += std::to_string(serial) + "|";

        // Get computer name
        char compName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(compName);
        GetComputerNameA(compName, &size);
        combined += std::string(compName) + "|";

        // Get MAC address
        DWORD adapterSize = 0;
        GetAdaptersInfo(nullptr, &adapterSize);
        if (adapterSize > 0) {
            std::vector<BYTE> buf(adapterSize);
            PIP_ADAPTER_INFO info = (PIP_ADAPTER_INFO)buf.data();
            if (GetAdaptersInfo(info, &adapterSize) == ERROR_SUCCESS) {
                char mac[32];
                std::snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
                              info->Address[0], info->Address[1], info->Address[2],
                              info->Address[3], info->Address[4], info->Address[5]);
                combined += mac;
            }
        }

        std::array<uint8_t, 32> hash{};
        bool hashReady = remote_controller::crypto::SecureChannel::Sha256(
            reinterpret_cast<const uint8_t*>(combined.data()), combined.size(), hash);

        // Convert to readable format: XXX-XXX-XXX
        uint64_t val = 0;
        if (hashReady) {
            memcpy(&val, hash.data(), sizeof(uint64_t));
        } else {
            // Fallback keeps deterministic ID format even if crypto APIs fail.
            val = (uint64_t)std::hash<std::string>{}(combined);
        }
        val %= 1000000000ULL;

        std::ostringstream oss;
        oss << std::setw(3) << std::setfill('0') << ((val / 1000000) % 1000)
            << "-" << std::setw(3) << std::setfill('0') << ((val / 1000) % 1000)
            << "-" << std::setw(3) << std::setfill('0') << (val % 1000);

        return oss.str();
    }
};

// ============================================================================
// DPI AWARENESS
// ============================================================================

inline void EnableDPIAwareness() {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) return;

    // Try SetProcessDpiAwarenessContext (Windows 10 1703+)
    auto fnContext = (BOOL(WINAPI*)(void*))GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");
    if (fnContext) {
        fnContext((void*)-4);  // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        FreeLibrary(hUser32);
        return;
    }

    // Fallback to SetProcessDPIAware
    auto fn = (BOOL(WINAPI*)())GetProcAddress(hUser32, "SetProcessDPIAware");
    if (fn) fn();
    FreeLibrary(hUser32);
}

inline std::string GetBaseFileName(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

inline std::string SanitizeFileName(const std::string& name) {
    std::string result;
    result.reserve(name.size());

    for (size_t i = 0; i < name.size(); i++) {
        unsigned char ch = (unsigned char)name[i];
        if (ch < 32 || ch == '"' || ch == '<' || ch == '>' || ch == '|' || ch == ':' || ch == '*' || ch == '?' || ch == '\\' || ch == '/') {
            result.push_back('_');
        } else {
            result.push_back((char)ch);
        }
    }

    if (result.empty()) {
        result = "file.bin";
    }

    return result;
}

// ============================================================================
// LOW-SPEC OPTIMIZER: FAST FRAME DIFFERENCE DETECTOR
// ============================================================================

class FastFrameDiff {
public:
    static bool HasScreenChanged(const uint8_t* prevBuf, const uint8_t* currBuf, size_t size, uint32_t threshold = 100) {
        if (!prevBuf || !currBuf || size == 0) return true;
        
        size_t changedBytes = 0;
        size_t stride = 16;  // Sample every 16th byte (sub-millisecond low-CPU check)
        for (size_t i = 0; i < size; i += stride) {
            if (prevBuf[i] != currBuf[i]) {
                changedBytes++;
                if (changedBytes > threshold) return true;
            }
        }
        return false;
    }
};

// ============================================================================
// CLIPBOARD UTILITIES
// ============================================================================

class ClipboardHelper {
public:
    static std::string GetText() {
        if (!OpenClipboard(nullptr)) return "";
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (!hData) {
            hData = GetClipboardData(CF_UNICODETEXT);
            if (!hData) {
                CloseClipboard();
                return "";
            }
            wchar_t* wstr = (wchar_t*)GlobalLock(hData);
            if (!wstr) { CloseClipboard(); return ""; }
            int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
            std::string result(len, '\0');
            WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, nullptr, nullptr);
            GlobalUnlock(hData);
            CloseClipboard();
            if (!result.empty() && result.back() == '\0') result.pop_back();
            return result;
        }
        char* str = (char*)GlobalLock(hData);
        std::string result = str ? str : "";
        GlobalUnlock(hData);
        CloseClipboard();
        return result;
    }

    static bool SetText(const std::string& text) {
        if (text.empty()) return false;
        if (!OpenClipboard(nullptr)) return false;
        EmptyClipboard();
        HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
        if (!hGlob) { CloseClipboard(); return false; }
        char* ptr = (char*)GlobalLock(hGlob);
        if (ptr) {
            memcpy(ptr, text.c_str(), text.size() + 1);
            GlobalUnlock(hGlob);
            SetClipboardData(CF_TEXT, hGlob);
        }
        CloseClipboard();
        return true;
    }
};

