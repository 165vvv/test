# test
运行安装程序
首先在官网下载Snort安装包，双击exe进行安装，
点击许可协议上的 “我同意”。
选择要安装的 Snort 组件，通常保持默认选择即可。
![图片](https://github.com/user-attachments/assets/ef6cdf7b-7b9e-4bc0-b241-44262e27835a)
选择安装位置，安装在系统盘（通常是 C 盘）中的单独文件夹，以方便管理和查找。
点击 “下一步” 开始安装，等待安装过程完成。
![图片](https://github.com/user-attachments/assets/1521de46-a5e4-4a94-a5db-ebdff8cd3ae1)

配置环境变量
安装完成后，为了在命令行下方便地启动 Snort，可以将 Snort 的安装目录添加到系统的环境变量中。
具体操作如下：右键点击 “我的电脑”，选择 “属性”。在弹出的系统属性窗口中，点击 “高级系统设置”。在高级选项卡下，点击 “环境变量” 按钮。在系统变量部分，找到 “Path” 变量，点击 “编辑”。在变量值的末尾添加 Snort 安装目录的路径（例如，如果 Snort 安装在 “C:\Program Files\Snort”，则添加 “C:\Program Files\Snort\bin”），注意用分号与其他路径分隔开。这里安装的位置是在C盘，故添加环境变量C:\Snort\bin
![图片](https://github.com/user-attachments/assets/a163de97-7c4c-448f-83aa-8c056c7c0600)
输入snort -ev查看，安装成功
![图片](https://github.com/user-attachments/assets/0dd3974c-4dff-48b8-ba8e-15008dbe9dff)

下载和配置规则集
下载安装的对应Snort的版本，此次安装的是Snort 2.9.20，那就下载对应的版本的规则即可
Snort 需要规则集来检测网络中的入侵行为。可以从Snort 规则集官网下载规则集文件。将下载的规则集文件解压，并将规则文件的路径配置到 Snort 的配置文件中。通常，Snort的配置文件是snort.conf，在配置文件中找到规则文件的配置项，将其路径修改为实际的规则文件路径。
从官网上下载rule
![图片](https://github.com/user-attachments/assets/e19357a2-00cc-48fe-94d3-babb62c7cd4f)
后导入到本地安装目录，如下
![图片](https://github.com/user-attachments/assets/5bce37df-01e3-487e-8b4f-c7590cce529a)
接下来，编辑“snort.conf”文件，以指定正确的路径，使snort能够找到规则文件和分类文件
使用记事本或编辑器打开安装目录下的/etc/snort.conf文件，更改以下位置的配置代码（其中的路径改为自己的安装目录）：
![图片](https://github.com/user-attachments/assets/6ab5a340-fbcb-452a-bb20-908b4366ba87)

配置动态加载的库
![图片](https://github.com/user-attachments/assets/6cd9e21e-3643-4b6f-81cf-b843340e94fb)

修改配置文件
Classification.conf(规则的警报级别相关的配置)和Reference.conf(提供更多警报相关信息的链接)的路径
# metadata reference data.  do not modify these lines
include C:/Snort/etc/classification.config
include C:/Snort/etc/reference.config
在local下面添加如下数据，是针对于nmap扫描的，
# 检测 Nmap TCP SYN 扫描（SYN 标志位，目标端口常为开放端口）
![图片](https://github.com/user-attachments/assets/b2c3c562-0472-4c00-a21d-e0c2cf807e68)

alert icmp any any -> any any (msg:"Detected Ping request (ICMP Echo Request)"; itype:8; sid:1000001;)
alert icmp any any -> any any (msg:"Detected Ping reply (ICMP Echo Reply)"; itype:0; sid:1000002;)
alert tcp any any -> any any (flags:S; msg:"SYN scan detected"; sid:1000003;)
alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000004;)
alert icmp any any -> any any (msg:"ICMP Traffic Detected"; sid:1000005;)
alert tcp any any -> any any (msg:"TCP Traffic Detected"; sid:1000006;)
分别对应的是：
Ping 请求检测、Ping 响应检测、SYN 扫描检测、HTTP 流量检测、ICMP 流量检测、TCP 流量检测，有流量传输过来即可对应接收。
  Ping 请求和响应检测：规则1和规则2用于检测 ICMP Ping 请求和响应。
  SYN 扫描检测：规则 3 用于检测潜在的端口扫描（SYN 扫描）。
  HTTP 流量检测：规则 4 用于检测向 HTTP 服务器的流量（TCP80端口）。
  ICMP 和 TCP 通用检测：规则 5 和 6 用于检测所有 ICMP 和 TCP 流量。
我们在添加几个SQL注入的规则，如下图：
![图片](https://github.com/user-attachments/assets/1d82630d-1452-473a-a994-a891e7849b28)
还可以添加对规则进行分类和优先级排序
分类规则
# 格式：config classification: <类别名称>, <描述>, <默认优先级>
config classification: sql-injection-attempt, SQL注入尝试, 1
config classification: port-scan, 端口扫描行为, 2
config classification: icmp-flood, ICMP泛洪攻击, 1
#默认优先级：数值越小优先级越高（范围通常为1-3）

统一分类标准：参考官方分类（如 classification.config 默认值），保持命名一致性。
优先级分级：
    1（高危）：数据泄露、远程代码执行。
   2（中危）：端口扫描、信息泄露。
   3（低危）：常规探测流量。
与响应联动：通过threshold或event_filter限制高频低危告警，减少噪音

嗅探与数据记录
输入 snort -W 查看当前网卡
![图片](https://github.com/user-attachments/assets/684a132c-07f2-4771-a57e-50621b56fc7e)

找到是11网络接口
路径配置好后设置启动命令：
snort -A console -i 11 -c C:\Snort\etc\snort.conf -l C:\Snort\log
该命令设置 Snort为：
 监听网络接口 11 上的流量（通常是当前使用的网络接口）。
 使用 snort.conf 配置文件，加载其中定义的规则来检测流量。
 将警报输出到控制台，这样你可以实时查看警报。
 将日志文件保存到 C:\Snort\log 目录，以便稍后可以进行进一步分析。
通过这条命令，Snort 会监听指定接口上的所有网络流量，并根据配置文件中的规则检测到异常行为时在控制台输出警报，同时将流量日志保存在 C:\Snort\log 目录下，便于之后查看和分析。

测试
接下来的是测试过程，启动后如下：
![图片](https://github.com/user-attachments/assets/a002214e-c524-4b1e-be72-19d1ab47dfb5)
启动成功后在在另一台机器进行ping，sql注入等命令的测试：
![图片](https://github.com/user-attachments/assets/5f131c94-260e-4315-b1ec-3e76bfad5739)
可以发现左边的数据成功拦截识别，log也有产生正常记录日志：
![图片](https://github.com/user-attachments/assets/24c646e8-132a-44ef-9e6a-fbd04b1b0d00)



