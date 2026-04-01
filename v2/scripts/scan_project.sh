#!/bin/bash
#
# scan_project.sh - 使用自定义Checker扫描项目
#
# 用法:
#   ./scan_project.sh <checker.so> <checker_name> <project_dir> [include_dirs...]
#
# 示例:
#   ./scan_project.sh ./BufferOverflowChecker.so custom.BufferOverflowChecker ./tests/network_server
#   ./scan_project.sh ./NullDereferenceChecker.so custom.NullDereferenceChecker ./project -I./include
#

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 默认配置
LLVM_DIR="${LLVM_DIR:-/usr/lib/llvm-18}"
CLANG_C_PATH="${CLANG_C_PATH:-$LLVM_DIR/bin/clang}"
CLANG_CXX_PATH="${CLANG_CXX_PATH:-$LLVM_DIR/bin/clang++}"
TIMEOUT="${TIMEOUT:-120}"
MAX_WORKERS="${MAX_WORKERS:-4}"

# 打印使用帮助
usage() {
    echo "用法: $0 <checker.so> <checker_name> <project_dir> [options]"
    echo ""
    echo "参数:"
    echo "  checker.so      编译好的检测器共享库"
    echo "  checker_name    检测器名称 (如 custom.BufferOverflowChecker)"
    echo "  project_dir     要扫描的项目目录"
    echo ""
    echo "选项:"
    echo "  -I <dir>        添加include目录"
    echo "  -D <macro>      定义预处理宏"
    echo "  --timeout <s>   设置超时时间 (默认: 120)"
    echo "  --workers <n>   设置并行工作数 (默认: 4)"
    echo "  --output <dir>  设置输出目录 (默认: ./scan_results)"
    echo "  --format <fmt>  输出格式: text|json|html (默认: text)"
    echo "  -h, --help      显示帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 ./Checker.so custom.Checker ./src"
    echo "  $0 ./Checker.so custom.Checker ./project -I./include -I./lib"
    echo "  $0 ./Checker.so custom.Checker ./project --format json --output ./results"
    exit 0
}

# 解析参数
if [ $# -lt 3 ]; then
    usage
fi

CHECKER_SO="$1"
CHECKER_NAME="$2"
PROJECT_DIR="$3"
shift 3

INCLUDE_DIRS=""
OUTPUT_DIR="./scan_results"
FORMAT="text"

while [ $# -gt 0 ]; do
    case "$1" in
        -I)
            INCLUDE_DIRS="$INCLUDE_DIRS -I$2"
            shift 2
            ;;
        -D)
            DEFINE_MACROS="$DEFINE_MACROS -D$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --workers)
            MAX_WORKERS="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --format)
            FORMAT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "未知选项: $1"
            usage
            ;;
    esac
done

# 验证输入
if [ ! -f "$CHECKER_SO" ]; then
    echo -e "${RED}错误: 检测器文件不存在: $CHECKER_SO${NC}"
    exit 1
fi

# 支持文件或目录作为输入
if [ -f "$PROJECT_DIR" ]; then
    # 输入是单个文件
    PROJECT_MODE="file"
    PROJECT_PATH="$PROJECT_DIR"
elif [ -d "$PROJECT_DIR" ]; then
    # 输入是目录
    PROJECT_MODE="dir"
    PROJECT_PATH="$PROJECT_DIR"
else
    echo -e "${RED}错误: 项目路径不存在: $PROJECT_DIR${NC}"
    exit 1
fi

# 创建输出目录
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="$OUTPUT_DIR/scan_result_${TIMESTAMP}.${FORMAT}"

# 打印配置
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    Clang Static Analyzer 项目扫描${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}检测器:${NC} $CHECKER_NAME"
echo -e "${GREEN}检测器文件:${NC} $CHECKER_SO"
echo -e "${GREEN}扫描目标:${NC} $PROJECT_PATH"
echo -e "${GREEN}输出目录:${NC} $OUTPUT_DIR"
echo -e "${GREEN}输出格式:${NC} $FORMAT"
echo -e "${GREEN}并行数:${NC} $MAX_WORKERS"
echo ""

# 查找源文件
echo -e "${YELLOW}正在查找源文件...${NC}"

if [ "$PROJECT_MODE" = "file" ]; then
    # 单文件模式：直接使用指定的文件
    SOURCE_FILES="$PROJECT_PATH"
    FILE_COUNT=1
    echo -e "${GREEN}单文件模式: $PROJECT_PATH${NC}"
else
    # 目录模式：查找目录下的所有源文件
    SOURCE_FILES=$(find "$PROJECT_PATH" -type f \( -name "*.c" -o -name "*.cpp" -o -name "*.cc" -o -name "*.cxx" \) \
        ! -path "*/build/*" \
        ! -path "*/.git/*" \
        ! -path "*/node_modules/*" \
        ! -path "*/__pycache__/*" \
        2>/dev/null)

    FILE_COUNT=$(echo "$SOURCE_FILES" | grep -c . || true)
fi

echo -e "${GREEN}找到 $FILE_COUNT 个源文件${NC}"

if [ "$FILE_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}警告: 未找到源文件${NC}"
    exit 0
fi

# 扫描函数
scan_file() {
    local file="$1"
    local file_name=$(basename "$file")
    local compiler="$CLANG_CXX_PATH"

    case "$file" in
        *.c)
            compiler="$CLANG_C_PATH"
            ;;
    esac

    echo -e "${YELLOW}分析: $file_name${NC}"

    timeout "$TIMEOUT" "$compiler" --analyze \
        -Xclang -load -Xclang "$CHECKER_SO" \
        -Xclang -analyzer-checker -Xclang "$CHECKER_NAME" \
        -Xclang -analyzer-display-progress \
        -Xclang -analyzer-output=text \
        $INCLUDE_DIRS \
        $DEFINE_MACROS \
        "$file" 2>&1 || true
}

# 导出函数和变量供并行使用
export -f scan_file
export CHECKER_SO CHECKER_NAME CLANG_C_PATH CLANG_CXX_PATH TIMEOUT INCLUDE_DIRS DEFINE_MACROS
export RED GREEN YELLOW BLUE NC

# 开始扫描
echo ""
echo -e "${BLUE}开始扫描...${NC}"
echo ""

# 统计
TOTAL_BUGS=0
FILES_WITH_BUGS=0
PROCESSED=0

# 创建临时文件存储结果
TEMP_RESULTS=$(mktemp)

# 扫描每个文件
while IFS= read -r file; do
    PROCESSED=$((PROCESSED + 1))

    # 显示进度
    printf "\r${BLUE}进度: %d/%d${NC}" "$PROCESSED" "$FILE_COUNT"

    # 运行扫描
    OUTPUT=$(scan_file "$file")

    # 检查是否有发现
    if echo "$OUTPUT" | grep -q "warning:\|error:"; then
        FILES_WITH_BUGS=$((FILES_WITH_BUGS + 1))

        # 统计bug数量
        BUG_COUNT=$(echo "$OUTPUT" | grep -c "warning:\|error:" || true)
        TOTAL_BUGS=$((TOTAL_BUGS + BUG_COUNT))

        # 保存结果
        echo "FILE: $file" >> "$TEMP_RESULTS"
        echo "$OUTPUT" >> "$TEMP_RESULTS"
        echo "---" >> "$TEMP_RESULTS"
    fi

done <<< "$SOURCE_FILES"

echo ""
echo ""

# 生成报告
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}           扫描结果汇总${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}扫描文件数:${NC} $FILE_COUNT"
echo -e "${GREEN}处理文件数:${NC} $PROCESSED"
echo -e "${RED}问题文件数:${NC} $FILES_WITH_BUGS"
echo -e "${RED}问题总数:${NC} $TOTAL_BUGS"
echo ""

# 保存详细结果
if [ -s "$TEMP_RESULTS" ]; then
    echo -e "${YELLOW}详细报告:${NC}"
    echo ""

    if [ "$FORMAT" = "json" ]; then
        # JSON格式
        echo "{" > "$RESULT_FILE"
        echo "  \"scan_time\": \"$(date -Iseconds)\"," >> "$RESULT_FILE"
        echo "  \"checker\": \"$CHECKER_NAME\"," >> "$RESULT_FILE"
        echo "  \"project\": \"$PROJECT_PATH\"," >> "$RESULT_FILE"
        echo "  \"summary\": {" >> "$RESULT_FILE"
        echo "    \"total_files\": $FILE_COUNT," >> "$RESULT_FILE"
        echo "    \"files_with_bugs\": $FILES_WITH_BUGS," >> "$RESULT_FILE"
        echo "    \"total_bugs\": $TOTAL_BUGS" >> "$RESULT_FILE"
        echo "  }," >> "$RESULT_FILE"
        echo "  \"findings\": [" >> "$RESULT_FILE"

        # 解析并添加发现
        FIRST=true
        while IFS= read -r line; do
            if [[ "$line" == FILE:* ]]; then
                if [ "$FIRST" = true ]; then
                    FIRST=false
                else
                    echo "    }," >> "$RESULT_FILE"
                fi
                echo "    {" >> "$RESULT_FILE"
                echo "      \"file\": \"${line#FILE: }\"," >> "$RESULT_FILE"
                echo "      \"reports\": [" >> "$RESULT_FILE"
            elif [[ "$line" == *":"warning:* ]] || [[ "$line" == *":"error:* ]]; then
                echo "      \"$line\"," >> "$RESULT_FILE"
            fi
        done < "$TEMP_RESULTS"

        echo "      ]" >> "$RESULT_FILE"
        echo "    }" >> "$RESULT_FILE"
        echo "  ]" >> "$RESULT_FILE"
        echo "}" >> "$RESULT_FILE"
    else
        # 文本格式
        cat "$TEMP_RESULTS" > "$RESULT_FILE"
    fi

    # 显示简要结果
    if [ "$FORMAT" = "text" ]; then
        cat "$TEMP_RESULTS" | head -50
        if [ $(wc -l < "$TEMP_RESULTS") -gt 50 ]; then
            echo ""
            echo -e "${YELLOW}... 结果已截断，查看完整报告: $RESULT_FILE${NC}"
        fi
    fi

    echo ""
    echo -e "${GREEN}完整报告已保存: $RESULT_FILE${NC}"
else
    echo -e "${GREEN}✅ 未发现问题${NC}"
fi

# 清理
rm -f "$TEMP_RESULTS"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}扫描完成!${NC}"
echo -e "${BLUE}========================================${NC}"
