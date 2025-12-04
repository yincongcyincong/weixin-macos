
#!/bin/zsh

# ==============================================================================
#                      Diaphora & IDA Pro 自动化批处理脚本
# ==============================================================================

# --- 配置区 (Configuration) ---

# 1. 存放所有 .a 文件的**源目录** (The directory containing all .a files)
# !!! 请将此路径替换为您的实际目录 !!!
A_FILES_SOURCE_DIR="/Users/yincong/go/src/github.com/yincongcyincong/mars/mars/cmake_build/OSX/Darwin.out/"

# 2. 存放 .o 文件提取、以及最终 .i64/.sqlite 结果的**工作目录**
# 建议使用 /tmp，脚本运行完毕后可以手动删除此目录。
WORK_DIR="/tmp/diaphora_batch_$(date +%s)"

# 3. IDA Pro 可执行文件路径 (基于您提供的路径)
IDA_EXECUTABLE="/Applications/IDA Professional 9.1.app/Contents/MacOS/ida"

# 4. Diaphora 脚本路径 (基于您提供的路径)
DIAPHORA_SCRIPT="/Users/yincong/go/src/github.com/yincongcyincong/diaphora/diaphora.py"

# --- 脚本执行 (Script Execution) ---

echo "--- Diaphora 自动化分析开始 ---"
echo "源目录: ${A_FILES_SOURCE_DIR}"
echo "工作目录: ${WORK_DIR}"

# 路径检查
if [ ! -x "${IDA_EXECUTABLE}" ]; then
    echo "错误: 找不到 IDA 可执行文件或无执行权限: ${IDA_EXECUTABLE}" >&2
    exit 1
fi
if [ ! -f "${DIAPHORA_SCRIPT}" ]; then
    echo "错误: 找不到 Diaphora 脚本: ${DIAPHORA_SCRIPT}" >&2
    exit 1
fi

# 创建工作目录
mkdir -p "${WORK_DIR}" || { echo "错误: 无法创建工作目录 ${WORK_DIR}" >&2; exit 1; }


# 1. 循环查找所有 .a 文件
find "${A_FILES_SOURCE_DIR}" -name "*.a" -print0 | while IFS= read -r -d $'\0' archive_file; do

    # 提取 .a 文件名作为前缀 (例如: libmars)
    archive_base=$(basename "${archive_file}" .a)

    # 为当前 .a 文件创建一个专门的提取子目录
    EXTRACTION_DIR="${WORK_DIR}/${archive_base}_o_files"
    mkdir -p "${EXTRACTION_DIR}"

    echo ""
    echo ">>> 处理归档文件: ${archive_file}"

    # 切换到提取目录并使用 'ar -x' 提取所有 .o 文件
    (
        cd "${EXTRACTION_DIR}" || exit 1
        echo "   -> 正在提取 .o 文件到: ${EXTRACTION_DIR}"
        # 使用 ar -x 提取所有目标文件
        ar -x "${archive_file}"
    )

    if [ $? -ne 0 ]; then
        echo "   -> 警告: 提取 ${archive_file} 失败，跳过。"
        continue
    fi

    # 2. 循环处理所有提取出来的 .o 文件
    # 使用 find 确保只处理当前目录下的 .o 文件 (maxdepth 1)
    find "${EXTRACTION_DIR}" -maxdepth 1 -name "*.o" -print0 | while IFS= read -r -d $'\0' object_file; do

        # 提取 .o 文件名 (例如: tcpclient_fsm.cc)
        object_base=$(basename "${object_file}" .o)

        # 构造唯一的输出文件名，以防止不同 .o 文件覆盖彼此的结果
        OUTPUT_BASE="${archive_base}__${object_base}"
        IDA_IDB_PATH="${WORK_DIR}/${OUTPUT_BASE}.i64"
        DIAPHORA_SQLITE_PATH="${WORK_DIR}/${OUTPUT_BASE}.sqlite"
        IDA_LOG_PATH="${WORK_DIR}/${OUTPUT_BASE}.log"

        echo "   -> 正在分析 .o 文件: ${object_file}"
        echo "      输出 IDB: ${IDA_IDB_PATH}"
        echo "      输出 SQLite: ${DIAPHORA_SQLITE_PATH}"

        # 配置 Diaphora 环境变量
        export DIAPHORA_EXPORT_FILE="${DIAPHORA_SQLITE_PATH}"
        export DIAPHORA_AUTO=1

        # 执行 IDA Pro 无头模式命令
        "${IDA_EXECUTABLE}" -A -B \
            -o"${IDA_IDB_PATH}" \
            -L"${IDA_LOG_PATH}" \
            -S"${DIAPHORA_SCRIPT}" \
            "${object_file}"

        if [ $? -ne 0 ]; then
            echo "      !!! 警告: IDA Pro 分析 ${object_base}.o 失败 (请检查 ${IDA_LOG_PATH})"
        else
            echo "      <<< 分析成功: ${DIAPHORA_SQLITE_PATH} 已生成"
        fi

        # 清除环境变量，确保下次循环是干净的
        unset DIAPHORA_EXPORT_FILE
        unset DIAPHORA_AUTO

    done

    # 可选：删除提取出的 .o 文件以节省空间
    # rm -rf "${EXTRACTION_DIR}"

done

echo ""
echo "--- 所有归档文件处理完毕 ---"
echo "分析结果 (IDB/SQLITE/LOG) 位于目录: ${WORK_DIR}"
