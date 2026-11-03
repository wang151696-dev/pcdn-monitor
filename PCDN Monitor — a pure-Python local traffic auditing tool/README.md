# pcdn_monitor — Windows 本机疑似 PCDN / 异常上传行为审计工具

一个只读的**防御性本机监控工具**，用于检测自己的电脑是否存在疑似 PCDN（P2P CDN 带宽共享）、
挖矿僵尸网络上传或其他异常后台上传行为。

> ⚠️ 本工具**不会**攻击或扫描任何外部设备、不上传任何数据、不记录数据包正文、
> 不自动结束进程 / 删除文件 / 修改防火墙。所有输出均为“**疑似风险**”提示，
> 不能作为确定性结论，请人工复核后再处理。

## 功能

- 每 2 秒（可配）采集网卡上传/下载速率，自动排除回环、虚拟网卡（Hyper-V/WSL/VMware/Tailscale 等，模式可配）
- 读取系统 TCP/UDP 连接表，按 PID 聚合：连接数、远端公网 IP 数、端口数、/24 网段数、监听端口
- 进程画像：路径、命令行、用户名、是否位于临时/缓存目录、是否开机自启（注册表 Run 键 + 启动文件夹）
- 0–100 分风险评分（10 条规则），**连续多个评估周期命中才计分**，避免瞬时流量误报
- 白名单机制：按进程名/路径/PID/远端IP/端口配置，`weight` 0~1 折算得分（0=忽略，仅降分不删数据）
- 输出：实时终端面板（rich 可选，缺失自动降级纯文本）、`app.log`、`samples.csv`、`alerts.jsonl`、`report.json`
- 公网 IP 默认脱敏（`123.45.67.xxx`）；高风险持续一段时间后可选弹窗+蜂鸣提醒
- 非管理员权限可运行（连接表/进程信息可能不完整，会明确提示降级）

## 安装

```bash
cd pcdn_monitor
python -m pip install -r requirements.txt
```

Python 3.10+，Windows 10/11。`rich` 为可选依赖，缺失时自动使用纯文本面板。

## 快速开始

**方式一：双击运行（推荐普通用户）**

- 双击 `启动监控.bat` —— 开始实时监控，窗口关闭或 Ctrl+C 后自动生成报告
- 双击 `快速体检.bat` —— 采集一轮数据（约 3 秒）立即出报告
- 首次报错缺依赖时，双击 `安装依赖.bat`

建议右键 `.bat` 选择“以管理员身份运行”，连接归属更完整。

**方式二：命令行**

```bash
python main.py                # 实时面板，Ctrl+C 退出并生成报告
python main.py --once         # 只采集一次并立即生成报告
python main.py --duration 600 # 运行 10 分钟后自动结束
python main.py --no-ui        # 后台无界面记录
python main.py --interval 1 --output D:\audit  # 1 秒采样，输出到指定目录
python main.py --config my.json --output out2
```

建议**以管理员身份**运行终端（连接表才能完整归属到系统进程的 PID）。

### 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--interval <秒>` | 采样间隔（默认 2，最小 0.5） |
| `--duration <秒>` | 运行时长；缺省一直运行 |
| `--config <路径>` | 配置文件；默认脚本目录 `config.json` |
| `--output <目录>` | 输出目录；默认 `output/` |
| `--once` | 采集一次立即出报告（跳过连续确认） |
| `--no-ui` | 关闭面板 |

## 评分规则（默认阈值，全部可在 config.json 调整）

| 规则 | 默认条件 | 分值 |
| --- | --- | --- |
| sustained_upload 持续高速上传 | ≥1Mbps 持续 10 分钟 | +20 |
| upload_ratio 上传/下载比例异常 | 窗口内比例 ≥2 且上传 ≥10MB | +15 |
| many_public_ips 连接大量公网IP | 窗口内 ≥100 个不同公网 IP | +15 |
| dispersed_networks 网段分散 | ≥50 个不同 /24 网段 | +10 |
| dispersed_ports 端口分散 | ≥200 个不同远端端口 | +10 |
| udp_anomaly UDP 异常 | UDP 端点峰值 ≥150 | +10 |
| process_many_conns 单进程大量外连 | 单进程 TCP ≥80 条 | +10 |
| public_listeners 公网监听端口 | 非回环监听端口 ≥3 | +5 |
| suspicious_path 异常目录 | 临时/缓存目录进程且有连接 | +10 |
| autostart_activity 自启外连 | 自启动进程且连接 ≥20 | +5 |

风险等级：0–29 低 / 30–59 可疑 / 60–79 高 / 80–100 严重。
每条规则需**连续 `consecutive_cycles`（默认 3）个评估周期**命中才计入分数。

## 白名单

`config.json` 的 `whitelist` 数组，字段：`name`（进程名）/`path`（目录前缀）/`pid`/
`remote_ip`/`port`，以及 `weight`（0~1）和 `reason`：

- 进程类规则：得分 × 命中进程的最小权重（`weight: 0` 表示该规则忽略，`0.3` 表示七折）
- 远端 IP/端口白名单：这些目标不计入 IP/端口/网段分散度统计
- 白名单**只影响评分**，不影响 samples.csv 等原始记录；命中的白名单会在报告中列出

默认已对云盘同步（OneDrive/百度网盘等）、BT 下载（qBittorrent 等）、直播推流（OBS）、
组网 VPN（Tailscale/ZeroTier）与代理客户端（Clash/V2Ray/sing-box 等）降权，避免常见误报。

注意：代理/VPN 进程的连接**仍会计入系统级"公网 IP 分散度"统计**（这是设计使然——
大量外连本身就值得展示）。如本机常驻代理导致该告警干扰判断，可把对应进程的
`weight` 设为 0、调高 `distinct_ips` 阈值，或把已知出口 IP 加入 `remote_ip` 白名单。

## 输出文件（默认 `output/`）

| 文件 | 内容 |
| --- | --- |
| `app.log` | 运行日志（滚动 1MB×3） |
| `samples.csv` | 每周期一行：速率、累计字节、连接数、公网 IP 数、评分 |
| `alerts.jsonl` | 每次风险抬升一条 JSON（等级/分数/命中规则/Top 进程） |
| `report.json` | 总报告：总流量、峰值、Top 可疑进程、远端 IP/端口统计、监听端口、命中规则与评分、白名单命中、局限性说明 |

公网 IP 默认脱敏为 `123.45.67.xxx`（`mask_public_ips: false` 可关闭）。

## 已知局限（重要）

1. **psutil 无法按进程统计字节数流量**。工具如实区分：上传/下载速率来自网卡计数器（系统级），
   进程级数据仅为连接行为统计，绝不伪造“每进程流量字节数”。
2. 仅凭连接与流量特征**无法 100% 确认 PCDN**（与 BT、网盘同步、直播推流、NAS 等行为重叠），
   因此全部结论均为“疑似风险”。
3. 自启动/异常目录判定为启发式（注册表 Run 键 + 启动文件夹；路径模式匹配），可能漏报/误报。
4. 如需五元组级字节统计，可进行第二阶段增强：`pktmon` / `tshark` / ETW 抓包（只记元数据，
   通过本地地址端口与连接快照关联 PID）。

## 开发与测试

```bash
python -m pip install pytest
python -m pytest
```

测试覆盖：公网/私网 IP 判定、速率计算与计数器清零、滑动窗口与持续时长、评分与连续确认、
白名单折算、IP 脱敏、进程退出容错、空连接列表等场景。

## 项目结构

```
pcdn_monitor/
  main.py               # 入口、CLI、主循环、UI（rich/纯文本）
  collector.py          # 网卡流量 + 连接表采集与聚合
  process_inspector.py  # 进程画像、自启动索引、异常目录判定
  detector.py           # 规则引擎、滑动窗口、白名单、评分
  reporter.py           # 日志/CSV/JSONL/报告/提醒
  models.py             # 数据模型
  utils.py              # IP 工具、格式化、默认配置
  config.json           # 默认配置（所有阈值）
  requirements.txt
  README.md
  tests/                # pytest 测试
```

## 隐私声明

本工具只在本机运行：不发起任何外连、不上传任何采集数据、不记录数据包内容；
所有输出文件保存在本地输出目录，删除目录即清空全部记录。
