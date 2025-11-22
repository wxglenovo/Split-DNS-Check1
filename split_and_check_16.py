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
# 打印 not_written_counter 统计（单独函数）
# ===============================
def print_not_written_stats():
    data = load_bin(NOT_WRITTEN_FILE)
    flat_counts = {}
    total_rules = 0
    for part_rules in data.values():
        if not isinstance(part_rules, dict):
            continue
        for cnt in part_rules.values():
            total_rules += 1
            c = min(int(cnt), 4)
            flat_counts[c] = flat_counts.get(c, 0) + 1
    return flat_counts

# ===============================
# 单条规则 DNS 验证
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

    all_rules = []  # 用列表来存储所有规则，不去重
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
                    all_rules.append(line)  # 不去重，直接添加到列表
        except Exception as e:
            print(f"⚠ 下载失败 {url}: {e}")
    
    print(f"✅ 合并 {len(all_rules)} 条规则")
    
    # 将所有规则写入临时文件
    temp_file = os.path.join(TMP_DIR, "merged_rules_temp.txt")
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write("\n".join(all_rules))
    
    # 过滤和更新删除计数 >=7 的规则
    filtered_rules, updated_delete_counter, skipped_count = filter_and_update_high_delete_count_rules(all_rules)
    save_bin(DELETE_COUNTER_FILE, updated_delete_counter)

    # 打印统计信息
    print(f"📚 规则源合并规则 {len(all_rules)} 条，⏩共 {skipped_count} 条规则被跳过验证，🧮需要验证 {len(filtered_rules)} 条规则，🪓 分为 {PARTS} 片")

    # 切分规则
    split_parts(filtered_rules)

    # 如果有重试规则，加入合并规则中
    if os.path.exists(RETRY_FILE):
        with open(RETRY_FILE, "r", encoding="utf-8") as rf:
            retry_rules = [r.strip() for r in rf if r.strip()]
        if retry_rules:
            print(f"🔁 检测到 {len(retry_rules)} 条重试规则，将加入合并规则")
            all_rules.extend(retry_rules)  # 直接添加重试规则
            with open(temp_file, "a", encoding="utf-8") as f:  # 追加重试规则到临时文件
                f.write("\n" + "\n".join(retry_rules))

    return True

# ===============================
# 删除计数 >=7 的规则过滤
# ===============================
def filter_and_update_high_delete_count_rules(all_rules_set):
    """
    过滤和更新删除计数 >=7 的规则
    1. 如果规则在 merged_rules_temp.txt 的规则列表中，重置删除计数为 6；
    2. 如果不在 merged_rules_temp.txt 规则列表中，继续增加删除计数，直到删除计数达到 28 时，删除该规则的删除计数记录。
    """
    delete_counter = load_bin(DELETE_COUNTER_FILE)  # 加载删除计数器
    low_delete_count_rules = set()  # 计数小于 7 的规则
    updated_delete_counter = delete_counter.copy()  # 初始化更新后的删除计数器
    skipped_rules = []  # 被跳过的规则
    reset_rules = []  # 被重置删除计数为 6 的规则
    removed_rules = []  # 删除计数超过 28 的规则

    # 读取合并规则文件 merged_rules_temp.txt 中的所有规则
    with open(os.path.join(TMP_DIR, "merged_rules_temp.txt"), "r", encoding="utf-8") as f:
        merged_rules = set(f.read().splitlines())  # 合并规则列表

    # 处理每个规则
    for rule in all_rules_set:
        del_cnt = int(delete_counter.get(rule, 4))  # 获取规则的删除计数，默认值为 4
        if del_cnt < 7:
            low_delete_count_rules.add(rule)  # 保留删除计数小于 7 的规则
        else:
            skipped_rules.append(rule)  # 删除计数大于等于 7 的规则，跳过验证
            updated_delete_counter[rule] = del_cnt + 1  # 增加删除计数

            # 处理删除计数达到 24 的规则
            if updated_delete_counter[rule] >= 24:
                if rule in merged_rules:
                    updated_delete_counter[rule] = 6  # 删除计数重置为 6
                    reset_rules.append(rule)  # 重置计数的规则
                elif updated_delete_counter[rule] >= 28:
                    # 删除计数超过 28 的规则，移除计数记录
                    removed_rules.append(rule)
                    updated_delete_counter.pop(rule, None)

    # 输出删除计数的日志
    if reset_rules:
        for rule in reset_rules[:20]:  # 输出前 20 条规则
            print(f"🔁 删除计数达到24，重置为 6：{rule}")
        print(f"🔢 共 {len(reset_rules)} 条规则的删除计数达到24，已重置为 6")
    
    if skipped_rules:
        for rule in skipped_rules[:20]:  # 输出前 20 条被跳过的规则
            print(f"⚠ 删除计数 ≥7，跳过验证：{rule}")
        print(f"🔢 共 {len(skipped_rules)} 条规则被跳过验证（删除计数≥7）")
    
    if removed_rules:
        print(f"❌ 共 {len(removed_rules)} 条规则的删除计数超过 28，已从计数器中移除。")

    skipped_count = len(skipped_rules)
    return low_delete_count_rules, updated_delete_counter, skipped_count

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
    """
    对给定规则集进行 DNS 验证，并返回有效的规则列表。
    1. 如果有重试规则（存在 retry_rules.txt 文件），则将其与当前规则合并。
    2. 将合并后的规则写入临时文件以供后续处理。
    3. 使用线程池并行化 DNS 验证过程，验证每条规则的有效性。
    4. 输出验证进度和统计信息。
    """
    retry_rules = []
    
    # 1. 检查是否存在重试规则文件 retry_rules.txt，如果存在则读取其中的规则
    if os.path.exists(RETRY_FILE):
        with open(RETRY_FILE, "r", encoding="utf-8") as rf:
            retry_rules = [l.strip() for l in rf if l.strip()]  # 清理空行
    
    # 打印日志：重试规则的数量，并表示将插入分片顶部
    if retry_rules:
        print(f"🔁 将 {len(retry_rules)} 条 retry_rules 插入分片顶部并清空 {RETRY_FILE}")
    
    # 2. 合并重试规则和当前需要验证的规则
    # 如果有重试规则，将它们放在规则集的顶部；如果没有重试规则，则直接使用当前规则
    combined_rules = retry_rules + rules if retry_rules else rules

    # 3. 将合并后的规则写入临时文件，为后续的验证过程做准备
    tmp_file = os.path.join(TMP_DIR, f"vpart_{part}.tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write("\n".join(combined_rules))  # 将规则写入临时文件
    
    # 4. 清空 retry_rules.txt 文件，防止重复使用重试规则
    if retry_rules:
        with open(RETRY_FILE, "w", encoding="utf-8") as f:
            f.write("")  # 清空文件内容，准备下一次重试
    
    valid_rules = []  # 用于存放验证成功的规则
    total_rules = len(combined_rules)  # 计算合并后的规则总数

    # 5. 使用线程池并行化 DNS 验证过程
    # 利用线程池异步验证每个规则，提高处理效率
    with ThreadPoolExecutor(max_workers=DNS_THREADS) as executor:
        futures = {executor.submit(check_domain, r): r for r in combined_rules}  # 提交任务到线程池
        completed, start_time = 0, time.time()  # 初始化计数器和开始时间
        
        # 6. 逐个处理验证结果
        for future in as_completed(futures):
            res = future.result()  # 获取当前任务的执行结果
            if res:
                valid_rules.append(res)  # 如果验证成功，加入有效规则列表
            completed += 1  # 完成任务数增加
            
            # 7. 输出验证进度：每完成一批规则（DNS_BATCH_SIZE）或者完成所有验证时，输出进度信息
            if completed % DNS_BATCH_SIZE == 0 or completed == total_rules:
                elapsed = time.time() - start_time  # 计算已用时间
                speed = completed / elapsed if elapsed > 0 else 0  # 计算验证速度
                eta = (total_rules - completed) / speed if speed > 0 else 0  # 估算剩余时间
                print(f"✅ 已验证 {completed}/{total_rules} 条 | 有效 {len(valid_rules)} 条 | 速度 {speed:.1f}/秒 | 预计完成 {eta:.1f}s")
    
    # 8. 返回所有有效的规则
    return valid_rules

# ===============================
# 更新 not_written_counter
# ===============================
def update_not_written_counter(part_num):
    """
    更新每个规则的 `write_counter`，并根据验证结果处理规则的重试逻辑。
    1. 将新验证的规则的 `write_counter` 设置为最大值。
    2. 对于已验证但未出现在新规则中的规则，递减 `write_counter`。
    3. 如果 `write_counter <= 0`，将规则移入 `retry_rules.txt` 文件，并从已验证规则中删除。
    4. 最终更新规则文件，并保存更新后的 `not_written_counter`。
    """
    part_key = f"validated_part_{part_num}"  # 获取当前分片的 key
    counter = load_bin(NOT_WRITTEN_FILE)  # 加载现有的 `not_written_counter` 文件
    
    # 1. 初始化每个 part 的计数器
    # 确保所有分片的计数器都已初始化，即使某些分片没有规则
    for i in range(1, PARTS + 1):
        counter.setdefault(f"validated_part_{i}", {})  # 初始化所有分片的计数器为空字典

    validated_file = os.path.join(DIST_DIR, f"{part_key}.txt")  # 获取当前分片已验证规则文件路径
    tmp_file = os.path.join(TMP_DIR, f"vpart_{part_num}.tmp")  # 获取当前分片临时文件路径

    # 2. 读取已验证和临时文件中的规则
    # 从文件中读取当前分片的已验证规则和临时规则
    existing_rules = set(open(validated_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(validated_file) else set()
    tmp_rules = set(open(tmp_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(tmp_file) else set()

    part_counter = counter.get(part_key, {})  # 获取当前分片的计数器，若没有则初始化为空字典

    # 3. 将新验证的规则的 `write_counter` 设置为最大值
    # 对于新验证的规则（即临时规则中存在但已验证规则中不存在的规则），将它们的 `write_counter` 设置为最大值
    for r in tmp_rules:
        part_counter[r] = WRITE_COUNTER_MAX  # 设置 `write_counter` 为最大值

    # 4. 递减已验证但未出现在新规则中的规则的 `write_counter`
    # 对于已验证规则集中存在，但在新临时规则集（`tmp_rules`）中不再出现的规则，递减它们的 `write_counter`
    for r in existing_rules - tmp_rules:
        part_counter[r] = max(part_counter.get(r, WRITE_COUNTER_MAX) - 1, 0)  # 确保 `write_counter` 不小于 0 且不超过 `WRITE_COUNTER_MAX`

    # 5. 找出 `write_counter <= 0` 的规则，准备重试
    # 找出 `write_counter` 小于等于 0 的规则，准备将它们写入 `retry_rules.txt` 文件进行重试
    to_retry = [r for r in existing_rules if part_counter.get(r, 0) <= 0]
    
    # 如果有规则需要重试，进行处理
    if to_retry:
        # 将这些规则写入 `retry_rules.txt` 文件
        with open(RETRY_FILE, "a", encoding="utf-8") as rf:
            rf.write("\n".join(to_retry) + "\n")
        print(f"🔥 {len(to_retry)} 条 write_counter ≤ 0 的规则写入 {RETRY_FILE}")
        
        # 6. 从已验证规则中删除这些重试的规则
        # 如果某些规则需要重试，则从已验证的规则集中删除这些规则
        existing_rules -= set(to_retry)

    # 7. 保存更新后的规则文件
    # 将更新后的规则（包括新临时规则和未重试的已验证规则）保存回文件
    with open(validated_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(existing_rules.union(tmp_rules))))  # 合并已验证规则和新临时规则，并按字母顺序保存
    
    # 8. 清理已重试规则的计数器
    # 对于需要重试的规则，清除它们在计数器中的记录
    for r in to_retry:
        part_counter.pop(r, None)

    # 9. 更新 `part_counter`
    # 将更新后的计数器保存回 `not_written_counter` 文件中
    counter[part_key] = part_counter
    save_bin(NOT_WRITTEN_FILE, counter)

    # 10. 返回需要重试的规则数量
    return len(to_retry)  # 返回重试规则的数量


# ===============================
# 处理分片
# ===============================
def process_part(part):
    part = int(part)
    part_file = os.path.join(TMP_DIR, f"part_{part:02d}.txt")
    if not os.path.exists(part_file):
        print(f"⚠ 分片 {part} 缺失，重新拉取规则…")
        download_all_sources()
    if not os.path.exists(part_file):
        print("❌ 分片仍不存在，终止")
        return
    lines = [l.strip() for l in open(part_file, "r", encoding="utf-8").read().splitlines()]
    print(f"⏱ 验证分片 {part}, 共 {len(lines)} 条规则")
    out_file = os.path.join(DIST_DIR, f"validated_part_{part}.txt")
    old_rules = set(open(out_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(out_file) else set()
    delete_counter = load_bin(DELETE_COUNTER_FILE)
    rules_to_validate = [r for r in lines if int(delete_counter.get(r, 4)) < 7]
    for r in lines:
        if int(delete_counter.get(r, 4)) >= 7:
            delete_counter[r] = int(delete_counter.get(r, 4)) + 1
    final_rules = set(old_rules)
    valid = dns_validate(rules_to_validate, part)
    added_count = 0
    failure_counts = {}
    for r in rules_to_validate:
        if r in valid:
            final_rules.add(r)
            delete_counter[r] = 0
            added_count += 1
        else:
            delete_counter[r] = int(delete_counter.get(r, 0)) + 1
            fc = min(int(delete_counter[r]), 4)  # 只统计 1/4 至 4/4 的失败计数
            failure_counts[fc] = failure_counts.get(fc, 0) + 1
            if delete_counter[r] >= DELETE_THRESHOLD:
                final_rules.discard(r)
    save_bin(DELETE_COUNTER_FILE, delete_counter)
    deleted_validated = update_not_written_counter(part)
    total_count = len(final_rules)

    # 打印连续失败统计（包括 1/4 至 7/4）
    print("\n📊 当前分片连续失败统计:")
    for i in range(1, 8):  # 扩展统计范围，打印 1/4 至 7/4
        if failure_counts.get(i, 0) > 0:
            print(f"    ⚠ 连续失败 {i}/4 的规则条数: {failure_counts[i]}")

    print("\n📊 当前分片 write_counter 规则统计:")
    part_key = f"validated_part_{part}"
    counter = load_bin(NOT_WRITTEN_FILE)
    part_counter = counter.get(part_key, {})

    # 初始化每个 write_counter 的计数
    counts = {i: 0 for i in range(1, 8)}  # 支持 1/4 至 7/4 的统计

    for v in part_counter.values():
        v = int(v)
        if 1 <= v <= 7:  # 只统计 1 至 7 的范围
            counts[v] += 1

    total_rules = sum(counts.values())
    print(f"    ℹ️ 总规则条数: {total_rules}")
    for i in range(1, 8):
        if counts[i] > 0:
            print(f"    ⚠ write_counter {i}/4 的规则条数: {counts[i]}")

    print("--------------------------------------------------")

    # 保存最终规则
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(final_rules)))

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
