# MCMSA[Minecraft Microsoft Authentication]

[![GitHub release](https://img.shields.io/github/v/release/GongSunFangYun/MCMSA?style=flat-square)]()
[![Downloads](https://img.shields.io/github/downloads/GongSunFangYun/MCMSA/total?style=flat-square)]()
[![Stars](https://img.shields.io/github/stars/GongSunFangYun/MCMSA?style=flat-square)]()
[![Forks](https://img.shields.io/github/forks/GongSunFangYun/MCMSA?style=flat-square)]()
[![Issues](https://img.shields.io/github/issues/GongSunFangYun/MCMSA?style=flat-square)]()
[![License](https://img.shields.io/github/license/GongSunFangYun/MCMSA?style=flat-square)]()
![简体中文支持](https://img.shields.io/badge/Multi-Lang-ff8c00?style=flat-square&labelColor=ff8c00&color=ffd700)

A cross-platform Minecraft Microsoft authentication library implemented in multiple programming languages, supporting device code flow authentication.  
You can reference this project as a third-party library in your project—because all the processes are automated! You only need to handle variable assignments and method calls!  
Emm... As for example code on how to use these 'libraries,' please run the project written in the corresponding language and go through the full standard DCF process before checking.  
This project will absolutely not collect any user account data! The Azure application used by the project is just a empty program and does not contain any actual functionality!

## Supported Languages

| Language | Directory | Build Tool |
|----------|-----------|------------|
| **Java** | `Java/` | Maven |
| **Kotlin** | `Kotlin/` | Maven |
| **C** | `C/` | CMake + vcpkg |
| **C++** | `CPP/` | CMake + vcpkg |
| **C#** | `C#/` | .NET SDK |
| **Python** | `Python/` | pip |
| **JavaScript** | `JavaScript/` | npm |
| **TypeScript** | `TypeScript/` | npm |
| **Go** | `GoLang/` | go mod |
| **Rust** | `Rust/` | cargo |
| **PHP** | `PHP/` | composer |
| **VB.NET** | `VBNET/` | .NET SDK |

## Features

### **Core Features**
- **Device Code Flow Authentication** - Secure Microsoft OAuth 2.0 authentication without storing credentials
- **Full Authentication Chain** - Complete Microsoft → Xbox Live → Minecraft authentication pipeline
- **Cross-Platform** - Works on Windows, macOS, Linux, and any platform supporting the language
- **Unified Output Format** - Consistent JSON output across all language implementations

### **Security Features**
- **No Password Storage** - Uses OAuth device code flow for secure authentication
- **Token Management** - Handles access tokens, refresh tokens, and token expiration
- **Secure HTTP Communication** - All implementations use HTTPS with proper TLS
- **Error Handling** - Comprehensive error handling and retry mechanisms

### **Technical Features**
- **Multi-Language Support** - Same functionality implemented in 12+ programming languages
- **Language Idioms** - Each implementation follows its language's best practices and conventions
- **Dependency Management** - Proper package management for each ecosystem
- **Build Automation** - Complete build scripts and configuration files

### **Authentication Flow**
1. **Device Code Request** - Get device code from Microsoft
2. **User Verification** - User visits Microsoft site and enters code
3. **Token Polling** - Automatically polls for Microsoft access token
4. **Xbox Live Auth** - Convert Microsoft token to Xbox Live token
5. **XSTS Auth** - Get XSTS token for Minecraft services
6. **Minecraft Login** - Authenticate with Minecraft services
7. **Profile Fetch** - Retrieve Minecraft player profile and skins

### **Data Features**
- **Profile Information** - UUID, username, skins, capes
- **Token Storage** - Microsoft, Xbox Live, XSTS, and Minecraft tokens
- **Expiration Tracking** - Token expiration times and refresh capability
- **Skin Details** - Full skin metadata including texture URLs and variants

### **Developer Features**
- **Consistent API** - Same method signatures across all implementations
- **Comprehensive Error Handling** - Detailed error messages and recovery
- **Logging** - Step-by-step progress logging
- **Example Code** - Ready-to-use example code in each language
- **Configuration** - Easy to configure client ID and scopes

### **Platform Features**
- **HTTP Client Integration** - Uses each language's native or standard HTTP library
- **JSON Processing** - Native JSON handling in each language
- **Async/Concurrent** - Asynchronous implementations where supported
- **Timeout Management** - Configurable timeouts for network operations
- **Retry Logic** - Automatic retry for transient failures

### **Performance Features**
- **Connection Pooling** - Efficient HTTP connection reuse
- **Memory Efficient** - Stream-based JSON processing where available
- **Fast Polling** - Optimized polling intervals for quick authentication
- **Parallel Processing** - Concurrent operations where applicable

### **Use Case Features**
- **Minecraft Launchers** - Integration into custom Minecraft launchers
- **Server Management** - Automated authentication for server tools
- **Bot Development** - Authentication for Minecraft bots and automation
- **Educational Purpose** - Learn authentication flows in multiple languages
- **Library Development** - Foundation for building Minecraft-related libraries

### **Output Features**
```json
{
  "tokens": {
    "microsoft_access_token": "eyJ0eXAiOiJKV1Qi...",
    "microsoft_refresh_token": "0.AYcA1vzX5jy8kLp2...",
    "xbl_token": "eyJhbGciOiJSUzI1NiIs...",
    "xsts_token": "eyJhbGciOiJSUzI1NiIs...",
    "minecraft_access_token": "eyJraWQiOiJhYzg0YS...",
    "expires_in": 86400
  },
  "profile": {
    "id": "4566e69fc9...",
    "name": "PlayerName",
    "skins": [
      {
        "id": "b0a1c6f7-8d4e-4f3a-9c2b-...",
        "state": "ACTIVE",
        "url": "https://textures.minecraft.net/texture/...",
        "textureKey": "skin",
        "variant": "CLASSIC"
      }
    ],
    "capes": [],
    "profileActions": {}
  }
}
```