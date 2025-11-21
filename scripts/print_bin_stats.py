
import msgpack
import os

def load_msgpack(file):
    """安全加载 MessagePack 格式的文件"""
    if os.path.isfile(file):
        try:
            with open(file, 'rb') as f:
                return msgpack.load(f)
        except msgpack.exceptions.UnpackException as e:
            print(f"反序列化文件 {file} 时出错: {e}")
        except Exception as e:
            print(f"读取文件 {file} 时发生未知错误: {e}")
    else:
        print(f"文件 {file} 不存在或不是有效的文件")
    return {}

# ===============================
# delete_counter
# ===============================
dc_file = 'dist/delete_counter.bin'
dc = load_msgpack(dc_file)
dc_counts = {}

# 处理 delete_counter 中的失败次数，支持任意形式的失败次数
for v in dc.values():
    if isinstance(v, (int, str)):  # 支持整数和字符串（例如 "27/4"）
        # 如果是字符串（例如 "27/4"），按斜杠分割成两个部分
        if isinstance(v, str) and '/' in v:
            num, denom = v.split('/')
            try:
                num, denom = int(num), int(denom)
                dc_counts[f"{num}/{denom}"] = dc_counts.get(f"{num}/{denom}", 0) + 1
            except ValueError:
                print(f"无效的失败次数格式: {v}")
        else:
            dc_counts[v] = dc_counts.get(v, 0) + 1

print("📊 delete_counter 读取统计:")
if dc_counts:
    for k in sorted(dc_counts):
        print(f"    ⚠ 连续失败 {k}/4 的规则条数: {dc_counts[k]}")
else:
    print("    ℹ️ 当前没有规则计数")

# ===============================
# not_written_counter
# ===============================
nw_file = 'dist/not_written_counter.bin'
nw = load_msgpack(nw_file)

nw_counts = {}
total_rules = 0

def flatten_counts(obj):
    """递归统计 not_written_counter 计数"""
    global total_rules
    if isinstance(obj, dict):
        for v in obj.values():
            flatten_counts(v)
    elif isinstance(obj, list):
        for v in obj:
            flatten_counts(v)
    elif isinstance(obj, int):
        nw_counts[obj] = nw_counts.get(obj, 0) + 1
        total_rules += 1

flatten_counts(nw)

print("\n📊 not_written_counter 读取统计:")
if nw_counts:
    for k in sorted(nw_counts):
        print(f"    ⚠ write_counter {k}/4 的规则条数: {nw_counts[k]}")
else:
    print("    ℹ️ 当前没有 write_counter 记录")
