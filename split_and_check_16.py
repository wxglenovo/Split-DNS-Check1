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
# 确保文件存在并初始化为空字典
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

# ================================
# 其他功能函数，如 load_bin, 更新 not_written_counter 等
# ================================
def load_bin(path):
    """加载二进制数据，确保返回的是字典类型"""
    if os.path.exists(path):
        try:
            with open(path, "rb") as f:
                raw = f.read()
                if not raw:
                    return {}  # 如果文件为空，返回空字典
                data = msgpack.unpackb(raw, raw=False)
                # 确保返回的数据是字典类型
                if not isinstance(data, dict):
                    print(f"⚠ 警告：{path} 内容不是字典类型，已重置为空字典")
                    data = {}
            return data
        except msgpack.exceptions.ExtraData as e:
            print(f"⚠ {path} 读取错误: {e}. 重新初始化该文件为空字典。")
            return {}  # 如果有额外数据，返回空字典
        except Exception as e:
            print(f"⚠ 读取 {path} 错误: {e}")
            return {}
    return {}


# ================================
# 二进制读写（msgpack）
# ================================
def save_bin(path, data):
    """保存数据到文件，确保数据是字典类型"""
    try:
        if not isinstance(data, dict):
            print(f"⚠ 警告：试图保存非字典类型的数据到 {path}")
            data = {}  # 如果不是字典类型，重置为字典
        with open(path, "wb") as f:
            f.write(msgpack.packb(data, use_bin_type=True))
    except Exception as e:
        print(f"⚠ 保存 {path} 错误: {e}")

# 读取 delete_counter 时进行类型检查，确保它是字典类型
delete_counter = load_bin(DELETE_COUNTER_FILE)
if not isinstance(delete_counter, dict):
    print(f"⚠ delete_counter 不是字典类型，已重置为空字典")
    delete_counter = {}

# ===============================
# DNS 验证规则
# ===============================
def check_domain(rule):
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    domain = rule.lstrip("|").split("^")[0].replace("*", "")
    if not domain:
        return None
    try:
        resolver.resolve(domain)
        return rule
    except Exception:
        return None

# ===============================
# 处理 `write_counter <= 0` 的规则，使用并行化加速
# ===============================
def process_write_counter_zero_parallel(rules_to_validate, delete_counter, part, merged_rules):
    # 检查 delete_counter 是否为字典
    if not isinstance(delete_counter, dict):
        print(f"⚠ 错误：delete_counter 不是字典类型，类型为: {type(delete_counter)}")
        delete_counter = {}  # 如果不是字典，重新初始化为字典

    def process_rule(rule):
        """
        处理单个规则，递减 `write_counter`，并判断是否需要删除或重试。
        """
        write_count = delete_counter.get(rule, 4)  # 获取当前规则的 `write_counter`
        to_retry = []
        discarded = []

        if write_count <= 0:
            # 从 validated_part_X.txt 中移除规则
            part_file = os.path.join(DIST_DIR, f"validated_part_{part}.txt")
            with open(part_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # 移除该规则
            lines = [line for line in lines if line.strip() != rule]

            # 将删除后的规则重新写回文件
            with open(part_file, "w", encoding="utf-8") as f:
                f.writelines(lines)

            # 检查该规则是否在合并规则中
            if rule in merged_rules:
                # 如果规则在合并规则中，记录到 retry_rules.txt
                to_retry.append(rule)
            else:
                # 如果规则不在合并规则中，丢弃
                discarded.append(rule)

        return to_retry, discarded

    # 使用多线程并行化处理规则
    to_retry_rules = []
    discarded_rules = []
    with ThreadPoolExecutor(max_workers=DNS_THREADS) as executor:
        futures = {executor.submit(process_rule, rule): rule for rule in rules_to_validate if delete_counter.get(rule, 4) <= 0}
        for future in as_completed(futures):
            to_retry, discarded = future.result()
            to_retry_rules.extend(to_retry)
            discarded_rules.extend(discarded)

    # 写入重试的规则到 retry_rules.txt
    if to_retry_rules:
        with open(RETRY_FILE, "a", encoding="utf-8") as rf:
            rf.write("\n".join(to_retry_rules) + "\n")
        print(f"🔥 {len(to_retry_rules)} 条 write_counter ≤ 0 的规则写入 {RETRY_FILE}")

    # 输出丢弃的规则信息
    if discarded_rules:
        for rule in discarded_rules[:10]:  # 仅输出前 10 条丢弃的规则
            print(f"❌ 规则 {rule} 不在合并规则中，已丢弃")

    # 返回需要重试的规则
    return to_retry_rules

# ===============================
# 更新 not_written_counter.bin
# ===============================
def update_not_written_counter(part_num, tmp_rules, validated_rules):
    """
    更新 `not_written_counter.bin`，递减未验证规则的 `write_counter`，并删除 `write_counter <= 0` 的规则。
    """
    part_key = f"validated_part_{part_num}"
    counter = load_bin(NOT_WRITTEN_FILE)

    # 初始化计数器
    for i in range(1, PARTS + 1):
        counter.setdefault(f"validated_part_{i}", {})

    part_counter = counter.get(part_key, {})

    # 将验证成功的规则的 `write_counter` 设置为最大值
    for r in tmp_rules:
        part_counter[r] = WRITE_COUNTER_MAX

    # 递减没有验证成功的规则的 `write_counter`
    for r in validated_rules - tmp_rules:
        part_counter[r] = max(part_counter.get(r, WRITE_COUNTER_MAX) - 1, 0)

    # 找出 `write_counter <= 0` 的规则，准备重试
    to_retry = [r for r in validated_rules if part_counter.get(r, 0) <= 0]
    
    # 删除 `write_counter <= 0` 的规则，并更新 counter
    for rule in to_retry:
        part_counter.pop(rule, None)

    # 将更新后的 `part_counter` 写回 `not_written_counter.bin`
    counter[part_key] = part_counter
    save_bin(NOT_WRITTEN_FILE, counter)

    # 返回需要重试的规则
    return to_retry

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
    with open(MASTER_RULE, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(merged)))
    
    # 过滤和更新删除计数 >=7 的规则
    filtered_rules, updated_delete_counter, skipped_count = filter_and_update_high_delete_count_rules(merged)
    save_bin(DELETE_COUNTER_FILE, updated_delete_counter)

    print(f"📚 规则源合并规则 {len(merged)} 条，⏩共 {skipped_count} 条规则被跳过验证，🧮需要验证 {len(filtered_rules)} 条规则，🪓 分为 {PARTS} 片")

    # 切分规则
    split_parts(filtered_rules)
    
    return True

# ===============================
# 函数定义区
# ===============================

DELETE_THRESHOLD = 7  # 示例阈值
delete_counter = {}

def filter_and_update_high_delete_count_rules(rules):
    """
    过滤掉删除计数器高于阈值的规则，并返回更新后的规则列表和计数器。
    """
    filtered_rules = []
    updated_delete_counter = {}
    skipped_count = 0

    for rule in rules:
        delete_count = delete_counter.get(rule, 0)
        
        if delete_count >= DELETE_THRESHOLD:
            skipped_count += 1
            continue
        
        filtered_rules.append(rule)
        updated_delete_counter[rule] = delete_count

    return filtered_rules, updated_delete_counter, skipped_count

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
# 保留已有验证次数较多的规则的分配
# ===============================
def prioritize_high_success_rules(part_buckets, counter):
    """
    优先保留验证成功次数较多的规则，避免重新验证。
    通过判断 `write_counter` 来确定规则的验证状态。
    """
    for i, bucket in enumerate(part_buckets):
        for rule in bucket[:]:
            write_count = counter.get(rule, WRITE_COUNTER_MAX)
            if write_count > 4:
                # 如果验证次数较多，则优先保留在当前分片
                continue
            # 对验证失败次数多的规则，重新计算哈希并调整分片
            h = int(hashlib.sha256(rule.encode("utf-8")).hexdigest(), 16)
            idx = h % PARTS
            if idx != i:
                # 将规则移动到新的分片
                part_buckets[idx].append(rule)
                part_buckets[i].remove(rule)

    return part_buckets

# ===============================
# 负载均衡优化（针对验证失败的规则）
# ===============================
def load_balance_failed_rules(part_buckets, counter):
    """
    对验证失败次数多的规则重新计算哈希，进行负载均衡优化。
    """
    failed_rules = []
    for i, bucket in enumerate(part_buckets):
        for rule in bucket:
            write_count = counter.get(rule, WRITE_COUNTER_MAX)
            if write_count <= 1:  # 失败次数较多
                failed_rules.append(rule)
    
    # 重新分配失败规则
    for rule in failed_rules:
        h = int(hashlib.sha256(rule.encode("utf-8")).hexdigest(), 16)
        idx = h % PARTS
        for i, bucket in enumerate(part_buckets):
            if rule in bucket:
                bucket.remove(rule)
        part_buckets[idx].append(rule)

    return part_buckets

# ===============================
# DNS 验证
# ===============================
def dns_validate(rules, part):
    retry_rules = []
    if os.path.exists(RETRY_FILE):
        with open(RETRY_FILE, "r", encoding="utf-8") as rf:
            retry_rules = [l.strip() for l in rf if l.strip()]
    combined_rules = retry_rules + rules if retry_rules else rules
    tmp_file = os.path.join(TMP_DIR, f"vpart_{part}.tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write("\n".join(combined_rules))
    if retry_rules:
        with open(RETRY_FILE, "w", encoding="utf-8") as f:
            f.write("")
        print(f"🔁 将 {len(retry_rules)} 条 retry_rules 插入分片顶部并清空 {RETRY_FILE}")
    valid_rules = []
    total_rules = len(combined_rules)
    with ThreadPoolExecutor(max_workers=DNS_THREADS) as executor:
        futures = {executor.submit(check_domain, r): r for r in combined_rules}
        completed, start_time = 0, time.time()
        for future in as_completed(futures):
            res = future.result()
            if res:
                valid_rules.append(res)
            completed += 1
            if completed % DNS_BATCH_SIZE == 0 or completed == total_rules:
                elapsed = time.time() - start_time
                speed = completed / elapsed if elapsed > 0 else 0
                eta = (total_rules - completed) / speed if speed > 0 else 0
                print(f"✅ 已验证 {completed}/{total_rules} 条 | 有效 {len(valid_rules)} 条 | 速度 {speed:.1f}/秒 | 预计完成 {eta:.1f}s")
    return valid_rules

# ===============================
# 主要处理流程
# ===============================
def process_part(part_num):
    """
    主处理函数：验证规则、更新计数器和分片
    """
    part_key = f"validated_part_{part_num}"

    # 读取当前分片的规则文件
    part_file = os.path.join(TMP_DIR, f"part_{part_num}.txt")
    tmp_rules = set(open(part_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(part_file) else set()

    # 读取合并规则文件
    with open(MASTER_RULE, "r", encoding="utf-8") as f:
        merged_rules = set(f.read().splitlines())

    # 获取当前已验证的规则
    validated_file = os.path.join(DIST_DIR, f"{part_key}.txt")
    validated_rules = set(open(validated_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(validated_file) else set()

    # 更新 `not_written_counter.bin`
    to_retry = update_not_written_counter(part_num, tmp_rules, validated_rules)

    # 使用并行化处理
    retry_rules = process_write_counter_zero_parallel(to_retry, validated_rules, part_num, merged_rules)

    # 返回重试规则
    return retry_rules

# 执行所有分片的处理
for part_num in range(1, PARTS + 1):
    retry_rules = process_part(part_num)
    if retry_rules:
        print(f"🔥 {len(retry_rules)} 条规则需要重试，写入 {RETRY_FILE}")

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
