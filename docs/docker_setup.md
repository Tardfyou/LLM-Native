# Docker环境设置指南

## 🔍 网络诊断

在运行环境搭建脚本前，建议先运行网络诊断：

```bash
# 运行网络诊断脚本
./scripts/diagnose_network.sh
```

这个脚本会检查：
- ✅ Docker运行状态
- ✅ 网络连接情况
- ✅ DNS解析功能
- ✅ Ubuntu软件源可访问性
- ✅ Docker网络功能
- ✅ Docker构建功能

## 🔍 问题诊断

如果运行 `./scripts/dev.sh` 时遇到以下错误：

```
❌ docker-compose未安装或不可用
```

这是因为Docker Compose的版本兼容性问题。

## 🛠️ 解决方案

### 方案1：安装Docker Compose插件（推荐）

```bash
# Ubuntu/Debian系统
sudo apt-get update
sudo apt-get install docker-compose-plugin

# 验证安装
docker compose version
```

### 方案2：安装独立Docker Compose

```bash
# 下载并安装
sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 验证安装
docker-compose --version
```

### 方案3：使用手动启动脚本（无需Docker Compose）

如果无法安装Docker Compose，可以使用我们提供的备用脚本：

```bash
# 使用手动启动脚本
./scripts/dev-manual.sh
```

## 🐳 Docker版本兼容性

### Docker版本要求
- **最低版本**: Docker 20.10+
- **推荐版本**: Docker 24.0+

### 检查Docker版本
```bash
docker --version
docker info
```

### Docker Compose版本兼容性

| Docker版本 | Docker Compose命令 | 状态 |
|------------|-------------------|------|
| < 20.10 | `docker-compose` | ❌ 不支持 |
| 20.10+ | `docker compose` (内置) | ✅ 推荐 |
| 任何版本 | 独立安装的`docker-compose` | ✅ 兼容 |

## 🚀 启动开发环境

### 方法1：使用Docker Compose（推荐）
```bash
# 确保Docker Compose已安装
./scripts/dev.sh
```

### 方法2：使用手动脚本
```bash
# 无需Docker Compose
./scripts/dev-manual.sh
```

## 🔧 故障排除

### 权限问题
```bash
# 如果遇到权限错误
sudo usermod -aG docker $USER
# 重新登录或运行：newgrp docker
```

### 网络连接问题
```bash
# 运行网络诊断脚本
./scripts/diagnose_network.sh

# 检查DNS配置
cat /etc/resolv.conf

# 测试网络连接
ping 8.8.8.8
curl -I http://archive.ubuntu.com

# 如果网络有问题，临时修改DNS
echo 'nameserver 8.8.8.8' > /etc/resolv.conf
echo 'nameserver 8.8.4.4' >> /etc/resolv.conf

# 检查防火墙
sudo ufw status
```

### Docker构建失败
```bash
# 检查Docker磁盘空间
docker system df

# 清理Docker缓存
docker system prune -f

# 检查Dockerfile语法（不实际构建）
docker build --no-cache --progress=plain -t test-build . 2>&1 | head -50

# 如果仍然失败，使用备用Dockerfile
docker build -f Dockerfile.alternative -t llm-native:dev .

# 或者使用最小化Dockerfile
docker build -f Dockerfile.minimal -t llm-native:dev .
```

### 端口冲突
```bash
# 检查端口占用
netstat -tulpn | grep :8000
netstat -tulpn | grep :8001

# 修改端口映射（在docker-compose.yml中）
ports:
  - "8002:8000"  # 改为其他端口
```

### 容器无法启动
```bash
# 查看详细错误信息
docker logs <container_name>

# 清理并重试
docker system prune -f
./scripts/dev-manual.sh
```

### 磁盘空间不足
```bash
# 检查磁盘使用情况
df -h

# 清理Docker资源
docker system prune -a --volumes
```

## 📊 环境验证

### 验证开发环境
```bash
# 进入容器后运行测试
python3 scripts/test_environment.py

# 应该看到类似输出：
# ✅ Config模块导入成功
# ✅ DeepSeek客户端导入成功
# ✅ CodeQL框架导入成功
# ✅ 配置文件加载成功
```

### 验证API连接
```bash
# 测试DeepSeek API（需要有效API密钥）
python3 -c "
from src.model.deepseek_client import DeepSeekClient
from src.model.llm_client import LLMConfig
config = LLMConfig(api_key='your-api-key')
client = DeepSeekClient(config)
print('DeepSeek客户端创建成功')
"
```

## 🎯 开发工作流

### 1. 启动环境
```bash
./scripts/dev-manual.sh  # 或 ./scripts/dev.sh
```

### 2. 开发调试
```bash
# 在容器内
python3 src/main.py generate_detector --help
python3 scripts/test_environment.py
```

### 3. 代码修改
```bash
# 在宿主机修改代码
vim src/generator/engine.py

# 在容器内立即生效
python3 src/main.py generate_detector --vulnerability_desc "测试"
```

### 4. 停止环境
```bash
# 停止所有相关容器
docker stop llm_native_dev llm_native_vector_db
docker rm llm_native_dev llm_native_vector_db
```

## 📚 相关文档

- [开发工作流](development_workflow.md) - 详细的开发调试指南
- [架构文档](architecture.md) - 系统架构说明
- [API文档](api.md) - REST API使用指南

## 💡 提示

1. **优先使用Docker Compose**：安装成功后性能更好，功能更完整
2. **备用脚本可靠**：手动脚本在任何Docker环境下都可以工作
3. **环境隔离**：每个项目使用独立的容器和数据卷
4. **资源监控**：定期检查Docker资源使用情况

如果仍然遇到问题，请查看[故障排除](troubleshooting.md)文档或提交Issue。
