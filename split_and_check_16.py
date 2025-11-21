import os
import msgpack
import requests
import argparse
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import hashlib

# ===============================
# 配置区（Config）
# ===============================
URLS_TXT = "urls.txt"
TMP_DIR = "tmp"
DIST_DIR = "dist"
MASTER_RULE = "merged_rules.txt"
PARTS = 16
DNS_TIMEOUT = 2
DELETE_COUNTER_FILE = os.path.join(DIST_DIR, "delete_counter.bin")
NOT_WRITTEN_FILE = os.path.join(DIST_DIR, "not_written_counter.bin")
RETRY_FILE = os.path.join(DIST_DIR, "retry_rules.txt")
DELETE_THRESHOLD = 4
DNS_BATCH_SIZE = 540
WRITE_COUNTER_MAX = 6
DNS_THREADS = 80
BALANCE_THRESHOLD = 1
BALANCE_MOVE_LIMIT = 50

os.makedirs(TMP_DIR, exist_ok=True)
os.makedirs(DIST_DIR, exist_ok=True)

# ===============================
# 文件确保函数（写入空 msgpack dict）
# ===============================
def ensure_bin_file(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        try:
            with open(path, "wb") as f:
                f.write(msgpack.packb({}, use_bin_type=True))
        except Exception as e:
            print(f"⚠ 初始化 {path} 失败: {e}")

ensure_bin_file(DELETE_COUNTER_FILE)
ensure_bin_file(NOT_WRITTEN_FILE)
if not os.path.exists(RETRY_FILE):
    open(RETRY_FILE, "w", encoding="utf-8").close()

# ===============================
# 二进制读写（msgpack）
# ===============================
def load_bin(path, print_stats=False):
    if os.path.exists(path):
        try:
            with open(path, "rb") as f:
                raw = f.read()
                if not raw:
                    return {}
                data = msgpack.unpackb(raw, raw=False)
            return data
        except Exception as e:
            print(f"⚠ 读取 {path} 错误: {e}")
            return {}
    return {}

def save_bin(path, data):
    try:
        with open(path, "wb") as f:
            f.write(msgpack.packb(data, use_bin_type=True))      
    except Exception as e:
        print(f"⚠ 保存 {path} 错误: {e}")

# ===============================
# 下载并合并规则源
# ===============================
def download_all_sources():
    """
    下载所有规则源，合并规则，过滤并更新删除计数
    """
    if not os.path.exists(URLS_TXT):
        print("❌ urls.txt 不存在")
        return False
    print("📥 下载规则源...")

    merged = set()
    with open(URLS_TXT, "r", encoding="utf-8") as f:
        urls = [u.strip() for u in f if u.strip()]

    for url in urls:
        print(f"🌐 获取 {url}")
        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            for line in r.text.splitlines():
                line = line.strip()
                if line:
                    merged.add(line)
        except Exception as e:
            print(f"⚠ 下载失败 {url}: {e}")

    print(f"✅ 合并 {len(merged)} 条规则")

    # 保存合并规则到临时文件
    temp_file = os.path.join(TMP_DIR, "merged_rules_temp.txt")
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(merged)))

    return temp_file  # 返回临时文件的路径

# ===============================
# 哈希分片 + 负载均衡优化
# ===============================
def split_parts(merged_rules):
    sorted_rules = sorted(merged_rules)
    total = len(sorted_rules)
    part_buckets = [[] for _ in range(PARTS)]
    
    # 首先，根据规则的哈希值进行初步分配
    for rule in sorted_rules:
        h = int(hashlib.sha256(rule.encode("utf-8")).hexdigest(), 16)
        idx = h % PARTS
        part_buckets[idx].append(rule)

    # 然后，进行负载均衡优化
    while True:
        lens = [len(b) for b in part_buckets]
        max_len, min_len = max(lens), min(lens)
        
        # 如果负载差距足够小，则结束
        if max_len - min_len <= BALANCE_THRESHOLD:
            break
        
        max_idx, min_idx = lens.index(max_len), lens.index(min_len)
        move_count = min(BALANCE_MOVE_LIMIT, (max_len - min_len) // 2)
        
        # 如果移动数量小于等于 0，则退出
        if move_count <= 0:
            break
        
        # 从负载最大的分片移至负载最小的分片
        part_buckets[min_idx].extend(part_buckets[max_idx][-move_count:])
        part_buckets[max_idx] = part_buckets[max_idx][:-move_count]
    
    # 将分配好的规则写入文件
    for i, bucket in enumerate(part_buckets):
        filename = os.path.join(TMP_DIR, f"part_{i+1:02d}.txt")
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(bucket))
        print(f"📄 分片 {i+1}: {len(bucket)} 条规则 → {filename}")

# ===============================
# DNS 验证
# ===============================
def dns_validate(rules, part):
    valid_rules = []
    total_rules = len(rules)
    
    # 使用线程池并行处理 DNS 验证
    with ThreadPoolExecutor(max_workers=DNS_THREADS) as executor:
        futures = {executor.submit(check_domain, r): r for r in rules}
        completed, start_time = 0, time.time()
        
        # 逐个处理验证结果
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    valid_rules.append(res)
            except Exception as e:
                # 捕获线程中的异常
                print(f"⚠ DNS 验证失败: {e}")
            completed += 1
            
            # 输出进度信息
            if completed % DNS_BATCH_SIZE == 0 or completed == total_rules:
                elapsed = time.time() - start_time
                speed = completed / elapsed if elapsed > 0 else 0
                eta = (total_rules - completed) / speed if speed > 0 else 0
                print(f"✅ 已验证 {completed}/{total_rules} 条 | 有效 {len(valid_rules)} 条 | 速度 {speed:.1f}/秒 | 预计完成 {eta:.1f}s")
    
    return valid_rules

# ===============================
# 更新 not_written_counter
# ===============================
def update_not_written_counter(part_num, validated_rules):
    counter = load_bin(NOT_WRITTEN_FILE)

    # 初始化每个 part 的计数器
    part_key = f"validated_part_{part_num}"
    counter.setdefault(part_key, {})

    validated_file = os.path.join(DIST_DIR, f"validated_part_{part_num}.txt")

    # 确保文件存在后读取
    existing_rules = set()
    if os.path.exists(validated_file):
        with open(validated_file, "r", encoding="utf-8") as f:
            existing_rules = set(f.read().splitlines())

    # 更新计数器：如果验证成功，设置为 6；否则递减。
    for rule in validated_rules:
        counter[part_key][rule] = WRITE_COUNTER_MAX  # 验证成功的规则设置为 6

    for rule in existing_rules - set(validated_rules):
        counter[part_key][rule] = max(counter[part_key].get(rule, WRITE_COUNTER_MAX) - 1, 0)

    # 保存更新后的计数器
    save_bin(NOT_WRITTEN_FILE, counter)

    # 查找 write_counter <= 0 的规则，并准备重试
    to_retry = [r for r in existing_rules if counter[part_key].get(r, 0) <= 0]

    if to_retry:
        # 将需要重试的规则写入 retry_rules.txt 文件
        with open(RETRY_FILE, "a", encoding="utf-8") as rf:
            rf.write("\n".join(to_retry) + "\n")
        print(f"🔥 {len(to_retry)} 条 write_counter ≤ 0 的规则写入 {RETRY_FILE}")
        
        # 从已验证规则中删除这些重试的规则
        existing_rules -= set(to_retry)

    # 保存更新后的 validated_part_X.txt 文件
    with open(validated_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(existing_rules.union(validated_rules))))

    return len(to_retry)

# ===============================
# 处理分片
# ===============================
def process_part(part):
    part = int(part)
    part_file = os.path.join(TMP_DIR, f"part_{part:02d}.txt")
    
    # 确保分片文件存在，如果不存在，尝试下载并更新合并规则
    if not os.path.exists(part_file):
        print(f"⚠ 分片 {part} 缺失，重新拉取规则…")
        temp_file = download_all_sources()  # 获取合并规则临时文件路径
        if not temp_file:
            print("❌ 无法获取合并规则，终止")
            return
    else:
        # 如果分片存在，直接使用已加载的合并规则
        temp_file = os.path.join(TMP_DIR, "merged_rules_temp.txt")  # 使用已存在的临时文件

    if not os.path.exists(part_file):
        print("❌ 分片仍不存在，终止")
        return

    # 读取并合并重试规则和当前需要验证的规则
    retry_rules = []
    if os.path.exists(RETRY_FILE):
        with open(RETRY_FILE, "r", encoding="utf-8") as rf:
            retry_rules = [l.strip() for l in rf if l.strip()]

    if retry_rules:
        print(f"🔁 将 {len(retry_rules)} 条 retry_rules 插入分片顶部并清空 {RETRY_FILE}")

    combined_rules = retry_rules + [l.strip() for l in open(part_file, "r", encoding="utf-8").read().splitlines()] if retry_rules else [l.strip() for l in open(part_file, "r", encoding="utf-8").read().splitlines()]

    # 清空 retry_rules.txt 文件
    if retry_rules:
        with open(RETRY_FILE, "w", encoding="utf-8") as f:
            f.write("")  # 清空文件

    retry_count = len(retry_rules)  # 记录 retry_rules 的数量
    initial_rule_count = len(combined_rules) - retry_count  # 插入 retry_rules 之前的规则数量
    total_rules = len(combined_rules)
    print(f"⏱ 分片 {part}: {initial_rule_count} 条规则 插入{retry_count} 条 retry_rules 后 共 {total_rules} 条规则")

    out_file = os.path.join(DIST_DIR, f"validated_part_{part}.txt")
    old_rules = set(open(out_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(out_file) else set()

    delete_counter = load_bin(DELETE_COUNTER_FILE)
    rules_to_validate = [r for r in combined_rules if int(delete_counter.get(r, 4)) < 7]

    # 加载临时合并规则
    with open(temp_file, "r", encoding="utf-8") as f:
        merged = set(f.read().splitlines())

    # 执行 DNS 验证并且并行化处理
    valid = dns_validate(rules_to_validate, part)

    final_rules = set(old_rules)
    added_count = 0
    failure_counts = {}
    discarded_rules = []  # 用来记录丢弃的规则
    retry_rules = []  # 用来记录需要重试的规则

    # 处理验证结果
    for r in rules_to_validate:
        write_counter = int(delete_counter.get(r, 0))

        if r in valid:
            final_rules.add(r)
            delete_counter[r] = 6  # 将 write_counter 设置为 6
            added_count += 1
        else:
            # 更新失败计数
            delete_counter[r] = write_counter + 1
            fc = min(delete_counter[r], 27)  # 只统计 1/4 至 27/4 的失败计数
            failure_counts[fc] = failure_counts.get(fc, 0) + 1
            if delete_counter[r] >= DELETE_THRESHOLD:
                final_rules.discard(r)
                discarded_rules.append(r)  # 记录丢弃的规则
                retry_rules.append(r)

    # 保存 delete_counter    
    save_bin(DELETE_COUNTER_FILE, delete_counter)

    # 打印连续失败统计（包括 1/4 至 7/4）
    print("\n📊 当前分片连续失败统计:")
    for i in range(1, 8):  # 扩展统计范围，打印 1/4 至 7/4
        if failure_counts.get(i, 0) > 0:
            print(f"    ⚠ 连续失败 {i}/4 的规则条数: {failure_counts[i]}")

    # 打印 write_counter 规则统计
    print("📊 当前分片 write_counter 规则统计:")
    part_key = f"validated_part_{part}"
    counter = load_bin(NOT_WRITTEN_FILE)
    part_counter = counter.get(part_key, {})

    # 初始化每个 write_counter 的计数
    counts = {i: 0 for i in range(1, 8)}  # 支持 1 至 7 的统计

    for v in part_counter.values():
        v = int(v)
        if 1 <= v <= 7:  # 只统计 1 至 7 的范围
            counts[v] += 1

    total_rules = sum(counts.values())   
    for i in range(1, 8):
        if counts[i] > 0:
            print(f"    ⚠ write_counter {i}/4 的规则条数: {counts[i]}")

    print("--------------------------------------------------")

    # 保存丢弃规则到 retry_rules.txt 文件
    if retry_rules:
        print(f"🔁 写入 {len(retry_rules)} 条丢弃规则到 {RETRY_FILE}")
        with open(RETRY_FILE, "a", encoding="utf-8") as f:
            f.write("\n".join(retry_rules) + "\n")
        print(f"🔥 {len(retry_rules)} 条规则丢弃，写入 {RETRY_FILE} 以待重试")

    # 保存最终规则
    print(f"保存最终规则到 {out_file}, 规则数量: {len(final_rules)}")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(final_rules)))

    # 更新未写入计数器
    deleted_validated = update_not_written_counter(part, valid)
    total_count = len(final_rules)

    print(f"✅ 分片 {part} 完成: 总{total_count}, 新增{added_count}, 删除{deleted_validated}, 过滤{len(rules_to_validate) - len(valid)}")
    print(f"COMMIT_STATS: 总 {total_count}, 新增 {added_count}, 删除 {deleted_validated}, 过滤 {len(rules_to_validate) - len(valid)}")

# ===============================
# 主入口
# ===============================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--part", help="验证指定分片 1~16")
    parser.add_argument("--force-update", action="store_true", help="强制重新下载规则源并切片")
    args = parser.parse_args()

    if args.force_update:
        download_all_sources()
    if not os.path.exists(MASTER_RULE) or not os.path.exists(os.path.join(TMP_DIR, "part_01.txt")):
        print("⚠ 缺少规则或分片，自动拉取")
        download_all_sources()
    if args.part:
        process_part(args.part)
