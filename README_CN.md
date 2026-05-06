<div align="center">
  <img src="images/logo.png" alt="CyberStrikeAI Logo" width="200">
</div>

# CyberStrikeAI

[中文](README_CN.md) | [English](README.md)

**社区**：[加入 Discord](https://discord.gg/8PjVCMu8Zw)

<details>
<summary><strong>微信群</strong>（点击展开二维码）</summary>

<img src="./images/wechat-group-cyberstrikeai-qr.jpg" alt="CyberStrikeAI 微信群二维码" width="280">

</details>

<details>
<summary><strong>赞助</strong>（点击展开）</summary>

若 CyberStrikeAI 对您有帮助，可通过 **微信支付** 或 **支付宝** 赞助项目：

<div align="center">
  <img src="./images/sponsor-wechat-alipay-qr.jpg" alt="微信与支付宝赞助二维码" width="480">
</div>

</details>

CyberStrikeAI 是一款 **AI 原生安全测试平台**，基于 Go 构建，集成了 100+ 安全工具、智能编排引擎、角色化测试与预设安全测试角色、Skills 技能系统与专业测试技能、完整的测试生命周期管理能力，以及面向 **授权场景** 的 **内置轻量 C2（Command & Control，指挥与控制）** 能力（监听器、加密通信、会话与任务、实时事件、REST 与 MCP 协同）。通过原生 MCP 协议与 AI 智能体，支持从对话指令到漏洞发现、攻击链分析、知识检索与结果可视化的全流程自动化，为安全团队提供可审计、可追溯、可协作的专业测试环境。

> **个人学习笔记**：本仓库为个人学习用途的 fork，主要用于研究 MCP 协议集成与 AI 驱动的安全测试工作流。所有测试均在本地授权环境中进行。
>
> **学习重点**：目前重点关注 MCP stdio 模式的配置与调试，以及如何将外部工具通过 YAML 扩展接入平台。后续计划整理一份中文配置指南。

## 界面与集成预览

<div align="center">

### 系统仪表盘概览

<img src="./images/dashboard.png" alt="系统仪表盘" width="100%">

*仪表盘提供系统运行状态、安全漏洞、工具使用情况和知识库的全面概览，帮助用户快速了解平台核心功能和当前状态。*

### 核心功能概览

<table>
<tr>
<td width="33.33%" align="center">
<strong>Web 控制台</strong><br/>
<img src="./images/web-console.png" alt="Web 控制台" width="100%">
</td>
<td width="33.33%" align="center">
<strong>任务管理</strong><br/>
<img src="./images/task-management.png" alt="任务管理" width="100%">
</td>
<td width="33.33%" align="center">
<strong>漏洞管理</strong><br/>
<img src="./images/vulnerability-management.png" alt="漏洞管理" width="100%">
</td>
</tr>
<tr>
<td width="33.33%" align="center">
<strong>WebShell 管理</strong><br/>
<img src="./images/webshell-management.png" alt="WebShell 管理" width="100%">
</td>
<td width="33.33%" align="center">
<strong>MCP 管理</strong><br/>
<img src="./images/mcp-management.png" alt="MCP 管理" width="100%">
</td>
<td width="33.33%" align="center">
<strong>知识库</strong><br/>
<img src="./images/knowledge-base.png" alt="知识库" width="100%">
</td>
</tr>
<tr>
<td width="33.33%" align="center">
<strong>Skills 管理</strong><br/>
<img src="./images/skills.png" alt="Skills 管理" width="100%">
</td>
<td width="33.33%" align="center">
<strong>Agent 管理</strong><br/>
<img src="./images/agent-management.png" alt="Agent 管理" width="100%">
</td>
<td width="33.33%" align="center">
<strong>角色管理</strong><br/>
<img src="./images/role-management.png" alt="角色管理" width="100%">
</td>
</tr>
<tr>
<td width="33.33%" align="center">
<strong>系统设置</strong><br/>
<img src="./images/settings.png" alt="系统设置" width="100%">
</td>
<td width="33.33%" align="center">
<strong>MCP stdio 模式</strong><br/>
<img src="./images/mcp-stdio2.png" alt="MCP stdio 模式" width="100%">
</td>
<td width="33.33%" align="center">
<strong>Burp Suite 插件</strong><br/>
<img src="./images/plugins.png" alt="Burp Suite 插件" width="100%">
</td>
</tr>
</table>

</div>

## 特性速览

- 🤖 兼容 OpenAI/DeepSeek/Claude 等模型的智能决策引擎
- 🔌 原生 MCP 协议，支持 HTTP / stdio / SSE 传输模式以及外部 MCP 接入
- 🧰 100+ 现成工具模版 + YAML 扩展能力
-
