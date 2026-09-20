# 设备完整性检测（DeviceIntegrity）

一个原生 Android 风格的**设备篡改检测**应用：一次性把 Root、su、Magisk / Systemless、系统挂载、注入 Hook、谷歌证书、系统完整性、模拟器环境、Play Integrity 等 **60+ 项检测**跑一遍，给出评分与可导出的报告。

- 语言：Kotlin · 架构：单 Activity + Fragment（底部导航）
- UI：Material 3 / Material You（动态取色、深浅色跟随系统）
- 最低支持：Android 6.0（API 23） · 编译目标：API 34

## 快速开始

1. 用 **Android Studio Koala (2024.1.1) 或更新版本** → `File > Open` → 选择本目录。
2. 如果提示缺少 Gradle Wrapper，先在终端执行 `gradle wrapper`（或让 Studio 自动生成），再 Sync。
3. 连接手机（打开 USB 调试）→ Run。

> 仓库里没有提交 `gradle-wrapper.jar`（二进制文件），第一次打开时生成即可（`gradle wrapper`），或直接跑一次 GitHub Actions，从 `gradle-wrapper` 产物里取回。

## GitHub Actions 自动编译

已内置工作流 `.github/workflows/android.yml`：

- **触发**：推送到 `main` / `master`、PR、手动 `Run workflow`（可选 debug / release / 两者）、推送 `v*` 标签时自动发 Release。
- **产出**：`device-integrity-apks-<sha>` 产物里是编译好的 APK（保留 30 天）；`lint-report` 是 Lint 报告；`gradle-wrapper` 是生成好的 wrapper（可下载后提交回仓库，省掉每次生成）。
- **环境**：ubuntu-latest + JDK 17 + Gradle 8.7，Android SDK 与 Gradle 依赖均有缓存。

第一次跑之前什么都不用配，工作流会自己补出缺少的 Gradle Wrapper。

### 给 Release 包签名（可选）

不配密钥也能出包，只是 Release APK 会退回 debug 签名。要正式签名，在仓库 **Settings → Secrets and variables → Actions** 里加 4 个 Secret：

| Secret | 说明 |
| --- | --- |
| `KEYSTORE_BASE64` | 密钥库文件的 base64：`base64 -w0 your.jks` |
| `KEYSTORE_PASSWORD` | 密钥库密码 |
| `KEY_ALIAS` | 密钥别名 |
| `KEY_PASSWORD` | 密钥口令 |

工作流会解码成临时 jks 并传给 `app/build.gradle.kts` 里的 `signingConfigs["ci"]`。

### 打一个带 APK 的 Release

```bash
git tag v1.0.0 && git push origin v1.0.0
```

工作流会用 `softprops/action-gh-release` 自动建 Release 并把 APK 挂上去。

## 包含的检测项

| 分类 | 检测内容 |
| --- | --- |
| Root 与 su | 40+ 个常见 su 路径扫描、实际执行 `su` 判断是否返回 `uid=0`、busybox、当前进程 UID、系统目录可写测试、`ro.secure`/`ro.debuggable`/`service.adb.root`、root 常用目录、init.d 脚本 |
| Magisk / Systemless | 管理器 App（含 KernelSU / APatch / 常见 fork）、30+ 特征路径、`/data/adb/modules` 模块列表、`magiskd`/`magiskinit` 进程、挂载表特征、Zygisk/Riru 内存映射、`MAGISK_*` 环境变量、getprop 关键字、伪装包名扫描 |
| 系统挂载 | 只读分区是否被 `rw` 挂载、tmpfs/overlay 覆盖系统分区、可疑挂载点关键字、`/dev/block/loop*` 镜像挂载、verity 挂载选项、完整挂载表 |
| 风险应用 | SuperSU / KingRoot / root 隐藏类、Xposed / LSPosed / 太极 / Substrate、包名关键字扫描、shell 侧 `pm list packages` 补充扫描、未知来源安装开关 |
| 注入与 Hook | `/proc/self/maps` 注入特征、Frida 文件与 27042/27043/27047 端口扫描、Riru/Zygisk 注入库、`LD_PRELOAD`、`/proc/*/cmdline` 进程扫描 |
| 系统完整性 | Verified Boot（green/orange/yellow/red）、vbmeta locked/unlocked、bootloader 锁定、dm-verity、SELinux 模式、release-keys vs test-keys、user/userdebug/eng、OTA 公钥证书、系统框架签名、OEM 解锁、回滚索引、启动链路属性、系统目录文件扫描 |
| 谷歌证书与 GMS | Play 服务可用性、GMS 签名主体与指纹、应用商店签名校验、系统信任库（AndroidCAStore）中的 Google 根证书、`cacerts` 目录证书可解析性、APEX / otacerts.zip |
| 应用自身完整性 | 自身签名 SHA-256 与期望值比对（防二次打包）、安装来源、`FLAG_DEBUGGABLE`、APK 安装路径 |
| 调试与开发者选项 | 调试器附加、`TracerPid`（ptrace）、ADB / 无线调试、开发者选项与 root adbd、自动化测试环境 |
| 模拟器 / 虚拟环境 | Build 字段、QEMU 属性与设备文件、硬件特性缺失、传感器列表 |
| Play Integrity | 官方设备/应用完整性判定（需 GMS 与云端项目号） |

## 关于“谷歌证书检查”与 Play Integrity

- **本地校验**（默认开启，无需联网）：系统信任库里的 Google 根证书（GTS Root / Google Internet Authority / GlobalSign）清点、GMS 与 Play 商店的签名证书主体与 SHA-256、`otacerts.zip` 解析。
- **Play Integrity**（默认关闭，需配置）：
  1. 在 [Google Play 管理中心](https://play.google.com/console) 为你的应用启用 **Play Integrity**，并绑定一个 Google Cloud 项目；
  2. 在应用 **设置 → 谷歌证书与 Play Integrity** 里填入**云端项目号**（纯数字），或预置在 `app/build.gradle.kts` 的 `PLAY_CLOUD_PROJECT_NUMBER`；
  3. Integrity 令牌是**加密的**，要得到可信判定必须由**你自己的服务端**调用 Google 的解密接口。把服务端地址填进 **服务端解密地址**（或 `INTEGRITY_DECRYPT_ENDPOINT`），应用会把令牌 POST 过去并解析返回的 `deviceRecognitionVerdict`；
  4. 未配置服务端时，该项只返回 INFO（令牌已获取，待服务端解密）。
  - 参考：<https://developer.android.com/google/play/integrity>

## 目录结构

```
app/src/main/java/com/detect/integrity/
├── ui/            MainActivity（底部导航）、HomeFragment（检测+结果）、ChecksFragment（单项复检）、SettingsFragment
├── detection/     RootChecks / MagiskChecks / MountChecks / PackageChecks / HookChecks /
│                  SystemChecks / GoogleChecks / SelfChecks / DebugChecks / EmulatorChecks /
│                  PlayIntegrityCheck / CheckRegistry（检测项注册表）/ DetectionEngine（执行与评分）
├── model/         Category、Status、CheckResult、CheckSpec、KnownLists（特征库）、Score
├── util/          Shell、Fs、Props、Proc、Pkg、Hash
└── report/        ReportExporter（JSON / 文本报告、设备信息）
```

## 添加自己的检测项

1. 在 `detection/` 下写一个返回 `Outcome(status, summary, evidence)` 的函数；
2. 到 `detection/CheckRegistry.kt` 里 `add(CheckSpec(id, 标题, 分类, 说明, 权重) { 你的函数() })`；
3. 特征（路径、包名、关键字）统一放在 `model/KnownLists.kt`，改列表即可扩展。

UI 会自动出现新的分组与条目，不需要改界面代码。

## 设置项

- 跳过耗时检测项（系统目录全量扫描、端口扫描、伪装包名枚举）
- 严格模式（把“可疑”也判为不通过）
- 展示完整挂载表
- Play Integrity 开关 / 云端项目号 / 服务端解密地址
- 谷歌证书检查开关
- 期望签名指纹（填自己的 release 签名 SHA-256，小写无冒号）
- 主题模式（跟随系统 / 浅色 / 深色）、Material You 动态取色（需重启应用）

## 导出与分享

检测完成后可以：

- 顶部工具栏「导出」：生成 JSON 报告并通过系统分享面板发出；
- 首页「复制」：把完整文本报告复制到剪贴板。

报告包含设备信息（机型、指纹、补丁级别、vbmeta 状态等）、每项检测的状态与证据、总评分。

## 注意事项

- 所有检测都基于**本地可见特征**，属于“尽力而为”的启发式判断：隐藏手段（Shamiko、内核级 hook、自定义 ROM）可能导致漏报，某些正常设备也可能误报，请勿把单项结果当作唯一依据。
- `AndroidManifest.xml` 中声明了 `QUERY_ALL_PACKAGES`，目的是 Android 11+ 上枚举全部包名做关键字扫描；如果上架应用商店，请按商店政策提交使用说明，或直接删掉这个权限（检测仍可用，只是包名枚举不完整）。
- 需要网络权限的只有 Play Integrity 一项，其余检测全部离线完成。
