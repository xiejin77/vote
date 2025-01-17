# 电子投票系统

## 项目概述

这个项目实现了一个简单的电子投票系统，使用了 Paillier 同态加密算法来保护投票的隐私性。

**核心功能：**

*   管理员可以创建投票项目，并查看投票结果。
*   投票者可以登录系统并进行投票。
*   所有投票数据都使用 Paillier 算法加密，确保投票的机密性。
*   投票结果以同态加密的方式累加，无需解密即可计算最终结果。

## 技术栈

*   **后端：** Flask (Python)
*   **前端：** HTML, CSS, JavaScript
*   **加密：** Paillier (JavaScript 实现)
*   **存储：** 文本文件

## 系统架构

```plantuml
@startuml
!include <C4/C4_Container>

SHOW_LEGEND()

System_Boundary(c1, "电子投票系统") {

  Person(admin, "管理员", "创建投票项目，查看投票结果")

  Person(voter, "投票者", "登录系统，进行投票")

  Container(web_app, "Web 应用", "Flask", "提供用户界面和 API 接口")

  Container(encryption_module, "加密模块", "JavaScript", "使用 Paillier 算法加密投票数据")

  ContainerDb(file_storage, "文件存储", "文本文件", "存储加密后的投票数据")
}

Rel(admin, web_app, "使用", "HTTPS")

Rel(voter, web_app, "使用", "HTTPS")

Rel(web_app, encryption_module, "调用", "JavaScript")

Rel(web_app, file_storage, "读写", "")

SHOW_LEGEND()
@enduml
