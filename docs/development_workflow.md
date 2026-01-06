# LLM-Native开发工作流指南

## 🎯 Docker开发环境说明

### **开发 vs 生产环境**

| 环境类型 | Dockerfile | 代码挂载 | 重启需求 | 适用场景 |
|----------|------------|----------|----------|----------|
| **开发环境** | `Dockerfile` | ✅ Volume挂载 | ❌ 不需要重启 | 日常开发、调试、测试 |
| **生产环境** | `Dockerfile.prod` | ❌ 直接复制 | ✅ 需要重启 | 部署上线、演示 |

## 🚀 开发环境启动流程

### **方式1：使用便捷脚本（推荐）**
```bash
cd LLM-Native

# 启动开发环境
./scripts/dev.sh
```

### **方式2：手动启动**
```bash
cd LLM-Native

# 1. 启动向量数据库
docker-compose --profile dev up -d vector-db

# 2. 启动开发容器
docker-compose --profile dev up dev

# 3. 在另一个终端进入容器
docker-compose --profile dev exec dev bash
```

### **方式3：直接运行（快速测试）**
```bash
cd LLM-Native

# 构建镜像（只需一次）
docker-compose build dev

# 运行特定命令
docker-compose --profile dev run --rm dev python3 src/main.py --help
```

## 🔧 开发调试工作流

### **1. 代码修改流程**

```bash
# 在主机上修改代码
vim src/generator/engine.py  # 修改代码

# 代码立即生效，无需重启容器
# 在容器中直接测试
docker-compose --profile dev exec dev python3 src/main.py generate_detector --vulnerability_desc "测试" --target_framework codeql
```

### **2. 容器内开发**

```bash
# 进入开发容器
docker-compose --profile dev exec dev bash

# 在容器内进行开发
cd /app
python3 src/main.py --help
python3 scripts/init_environment.py

# 测试代码修改
python3 -c "from src.model.deepseek_client import DeepSeekClient; print('Import成功')"

# 查看日志
tail -f logs/llm_native.log
```

### **3. 数据持久化**

```bash
# 知识库数据持久化（重启容器后仍存在）
docker volume ls | grep knowledge_data

# 查看生成的结果
ls -la results/
cat results/detector.ql

# 查看日志
ls -la logs/
cat logs/llm_native.log
```

## 🐛 调试技巧

### **1. 实时日志监控**
```bash
# 在新终端中监控日志
docker-compose --profile dev logs -f dev

# 或在容器内查看
docker-compose --profile dev exec dev tail -f logs/llm_native.log
```

### **2. 交互式调试**
```bash
# 进入容器进行调试
docker-compose --profile dev exec dev bash

# 运行Python交互式环境
python3 -c "
from src.core.config import Config
config = Config.load_from_file('config/config.yaml')
print('配置加载成功')
"

# 测试LLM连接
python3 -c "
from src.model.deepseek_client import DeepSeekClient
from src.model.llm_client import LLMConfig
config = LLMConfig(api_key='sk-6b1ae1bdb0e24c0189f0f0e9db43a94a', model_name='deepseek-chat')
client = DeepSeekClient(config)
print('DeepSeek客户端创建成功')
"
```

### **3. 单元测试**
```bash
# 运行测试
docker-compose --profile test up test

# 或手动运行
docker-compose --profile dev exec dev python3 -m pytest tests/ -v
```

### **4. API调试**
```bash
# 启动API服务器进行调试
docker-compose --profile dev exec dev python3 -m uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload

# 在另一个终端测试API
curl -X POST "http://localhost:8000/api/v1/generate" \
  -H "Content-Type: application/json" \
  -d '{"vulnerability_desc": "测试缓冲区溢出", "target_framework": "codeql"}'
```

## 📊 实验运行环境

### **大规模实验**
```bash
# 在开发容器中运行实验
docker-compose --profile dev exec dev bash

# 运行完整实验流程
cd /app
python3 scripts/run_experiments.py

# 监控实验进度
tail -f logs/llm_native.log
```

### **基准测试**
```bash
# 运行基准评估
docker-compose --profile dev exec dev python3 src/main.py evaluate_framework \
  --benchmark_name juliet_suite \
  --output_dir results/benchmark_eval

# 查看结果
ls -la results/benchmark_eval/
cat results/benchmark_eval/evaluation_summary.txt
```

## 🔄 代码更新流程

### **开发中的代码修改**
1. **修改主机代码** → 立即在容器中生效
2. **测试修改** → 在容器中运行测试
3. **提交代码** → git commit & push
4. **继续开发** → 无需重启容器

### **依赖更新**
```bash
# 修改requirements.txt
vim requirements.txt

# 重建容器以安装新依赖
docker-compose --profile dev build dev

# 重启服务
docker-compose --profile dev up -d vector-db
docker-compose --profile dev up dev
```

### **系统依赖更新**
```bash
# 修改Dockerfile添加新系统依赖
vim Dockerfile

# 重建镜像
docker-compose --profile dev build dev

# 重启容器
docker-compose --profile dev up dev
```

## 🛑 故障排除

### **常见问题**

#### **1. 端口冲突**
```bash
# 检查端口占用
lsof -i :8000

# 修改端口映射
vim docker-compose.yml  # 更改ports配置
docker-compose --profile dev up dev
```

#### **2. 权限问题**
```bash
# 修复文件权限
docker-compose --profile dev exec dev chown -R $(id -u):$(id -g) /app/results
```

#### **3. 容器无法启动**
```bash
# 查看容器日志
docker-compose --profile dev logs dev

# 清理并重启
docker-compose --profile dev down
docker system prune -f
docker-compose --profile dev up dev
```

#### **4. 向量数据库连接失败**
```bash
# 检查向量数据库状态
docker-compose --profile dev ps vector-db

# 重启向量数据库
docker-compose --profile dev restart vector-db
```

### **性能优化**

#### **1. Volume挂载性能**
```yaml
# 在docker-compose.yml中使用cached挂载以提高性能
volumes:
  - .:/app:cached  # 适用于macOS
  # 或
  - .:/app         # 适用于Linux
```

#### **2. 内存优化**
```bash
# 限制容器内存使用
docker-compose --profile dev exec dev docker update --memory=4g --memory-swap=8g <container_id>
```

## 📋 开发检查清单

### **每日开发**
- [ ] 启动开发环境：`./scripts/dev.sh`
- [ ] 检查日志：`tail -f logs/llm_native.log`
- [ ] 运行基础测试：`python3 src/main.py --help`
- [ ] 提交代码变更：`git commit -am "feat: xxx"`

### **功能开发**
- [ ] 编写代码
- [ ] 单元测试
- [ ] 集成测试
- [ ] 代码审查
- [ ] 文档更新

### **实验运行**
- [ ] 环境检查
- [ ] 数据准备
- [ ] 实验执行
- [ ] 结果分析
- [ ] 报告生成

## 🎯 最佳实践

1. **始终使用开发环境**进行开发和调试
2. **定期提交代码**，保持版本控制清晰
3. **编写测试用例**验证功能正确性
4. **监控日志输出**及时发现问题
5. **使用便捷脚本**简化操作流程
6. **定期清理容器**避免资源浪费

按照这个工作流，您可以在Docker环境中高效地进行开发、调试和实验，而无需频繁重构镜像！ 🐳✨
