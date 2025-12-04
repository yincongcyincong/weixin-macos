#!/bin/zsh

# --- 配置区 ---
# 1. 存放所有源 SQLite 文件的目录
WORK_DIR="/tmp/diaphora_batch_1764836774/"
# 2. 最终合并生成的主数据库文件名
MASTER_DB_NAME="diaphora_merged_results.sqlite"

# 排除 SQLite 内部使用的特殊表
IGNORED_TABLES="(sqlite_sequence|android_metadata)"

# ------------------------------------------------------------------------------

echo "--- SQLite 数据库批量合并开始 ---"
echo "工作目录: ${WORK_DIR}"
echo "主数据库: ${MASTER_DB_NAME}"
echo "--------------------------------------"

# 查找所有源文件（排除目标主文件自身）
source_files=$(find "$WORK_DIR" -maxdepth 1 -name "*.sqlite" -not -name "$MASTER_DB_NAME" | sort)

if [ -z "$source_files" ]; then
    echo "⚠️ 警告: 未找到任何源数据库文件 (.sqlite)。"
    exit 0
fi

# 确保主数据库文件存在 (如果不存在则创建)
if [ ! -f "$MASTER_DB_NAME" ]; then
    echo "-> 主数据库文件不存在，正在创建: ${MASTER_DB_NAME}"
    sqlite3 "$MASTER_DB_NAME" "VACUUM;"
fi

# 尝试从第一个源数据库中获取所有表名 (用于定义结构和合并)
FIRST_SOURCE=$(echo "$source_files" | head -n 1)

# 使用 sqlite3 的 .tables 命令和一些文本处理来获取表名列表
TABLES=$(sqlite3 "$FIRST_SOURCE" ".tables" | tr ' ' '\n' | grep -v '^$' | sort | uniq | grep -vE "$IGNORED_TABLES")

if [ -z "$TABLES" ]; then
    echo "❌ 错误: 无法从第一个源数据库 (${FIRST_SOURCE}) 中获取可合并的表名。" >&2
    exit 1
fi

echo "找到以下需要合并的表: ${TABLES}"
echo "--------------------------------------"


## 🛠️ 关键步骤 1: 复制表结构到主数据库
echo ">>> 正在从 ${FIRST_SOURCE} 复制表结构到 ${MASTER_DB_NAME}..."

# 附加第一个源数据库，用于结构复制
sqlite3 "$MASTER_DB_NAME" "ATTACH DATABASE '$FIRST_SOURCE' AS source;"

# 循环创建表结构
for table_name in $TABLES; do
    echo "   -> 确保表结构存在: ${table_name}"

    # 使用双引号 \"...\" 包裹表名，防止关键字冲突
    sqlite3 "$MASTER_DB_NAME" "
        CREATE TABLE IF NOT EXISTS \"${table_name}\" AS
        SELECT * FROM source.\"${table_name}\" LIMIT 0;
    "
done

# 分离数据库
sqlite3 "$MASTER_DB_NAME" "DETACH DATABASE source;"

echo "<<< 表结构复制完成"
echo "--------------------------------------"


## 💾 关键步骤 2: 循环合并数据 (已修复连接问题)
for source_db in $source_files; do

    SOURCE_BASE=$(basename "$source_db")
    echo ">>> 正在合并源数据库: ${SOURCE_BASE}"

    # 1. 构建完整的 SQL 批处理命令 (包含 ATTACH)
    #    这样所有操作都在同一个 sqlite3 进程中执行
    SQL_BATCH_COMMAND="ATTACH DATABASE '$source_db' AS source;"

    # 2. 循环插入数据
    for table_name in $TABLES; do
        # 使用双引号 \"...\" 包裹表名，防止关键字冲突
        SQL_BATCH_COMMAND="${SQL_BATCH_COMMAND} INSERT OR IGNORE INTO \"${table_name}\" SELECT * FROM source.\"${table_name}\";"
    done

    # 3. 添加分离命令（在同一批次执行）
    SQL_BATCH_COMMAND="${SQL_BATCH_COMMAND} DETACH DATABASE source;"

    echo "   -> 正在执行数据插入批处理..."

    # 4. 集中执行所有命令 (ATTACH, INSERTS, DETACH)
    sqlite3 -batch --bail "$MASTER_DB_NAME" "$SQL_BATCH_COMMAND"

    if [ $? -ne 0 ]; then
        echo "❌ 错误: 数据插入过程中发生错误，停止合并。" >&2
        # 此时 DETACH 应该已在批处理中被执行，但如果 ATTACH 失败，DETACH 也会失败。
        # 我们已经停止脚本，不再需要额外的清理 DETACH。
        exit 1
    fi

    echo "<<< ${SOURCE_BASE} 合并完成"
    echo "--------------------------------------"

done

echo "🎉 所有数据库已成功合并到 ${MASTER_DB_NAME}。"
echo "--- 合并脚本结束 ---"