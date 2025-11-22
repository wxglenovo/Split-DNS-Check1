import os
import msgpack
import requests
import argparse
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import hashlib
import pickle
import concurrent.futures


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
HASH_LIST_FILE = os.path.join(DIST_DIR, "hash_list.bin")
RETRY_FILE = os.path.join(DIST_DIR, "retry_rules.txt")
DELETE_THRESHOLD = 4
DNS_BATCH_SIZE = 540
WRITE_COUNTER_MAX = 6
DNS_THREADS = 80
BALANCE_THRESHOLD = 1
BALANCE_MOVE_LIMIT = 50

# 确保文件夹存在
os.makedirs(TMP_DIR, exist_ok=True)
os.makedirs(DIST_DIR, exist_ok=True)  # 确保 dist 目录存在

# ===============================
# 文件确保函数（写入空 msgpack dict）
# ===============================
def ensure_bin_file(path, default_data={}):
    """
    确保给定路径的二进制文件存在。如果文件不存在，则初始化为空的 msgpack 文件。
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    if not os.path.exists(path):
        try:
            with open(path, "wb") as f:
                f.write(msgpack.packb(default_data, use_bin_type=True))
            print(f"✅ 已创建 {path} 并初始化为默认数据")
        except Exception as e:
            print(f"⚠ 初始化 {path} 失败: {e}")

ensure_bin_file(DELETE_COUNTER_FILE, default_data={})  # 空字典
ensure_bin_file(NOT_WRITTEN_FILE, default_data={})     # 空字典
ensure_bin_file(HASH_LIST_FILE, default_data=[])       # 空列表

if not os.path.exists(RETRY_FILE):
    open(RETRY_FILE, "w", encoding="utf-8").close()
    print(f"✅ {RETRY_FILE} 已创建")
else:
    print(f"ℹ️ {RETRY_FILE} 已存在")

# ===============================
# 二进制读取（msgpack）
# ===============================
def load_bin(path, print_stats=False):
    """
    读取给定路径的二进制文件（msgpack 格式）。
    """
    if os.path.exists(path):
        try:
            file_size = os.path.getsize(path)
            if print_stats:
                print(f"🗂 读取文件 {path}，大小 {file_size} 字节")
            
            with open(path, "rb") as f:
                raw = f.read()
                if not raw:
                    print(f"⚠ {path} 为空文件，返回空字典")
                    return {}
                data = msgpack.unpackb(raw, raw=False)
                if print_stats:
                    print(f"✅ 加载 {path} 数据成功，大小 {len(data)} 条记录")
            return data
        
        except Exception as e:
            print(f"⚠ 读取 {path} 错误: {e}")
            return {}
    else:
        print(f"⚠ 文件 {path} 不存在")
    
    return {}  # 如果文件不存在，返回空字典

# ===============================
# 二进制写入（msgpack）
# ===============================
def save_bin(path, data):
    """
    将数据保存到指定路径的二进制文件（msgpack 格式）。
    """
    try:
        with open(path, "wb") as f:
            f.write(msgpack.packb(data, use_bin_type=True))
        print(f"✅ {path} 已保存")
    except Exception as e:
        print(f"⚠ 保存 {path} 错误: {e}")

# ===============================
# 打印 not_written_counter 统计（单独函数）
# ===============================
def print_not_written_stats():
    """
    打印并返回 `not_written_counter` 文件中的规则统计信息。
    1. 加载 `not_written_counter` 文件的数据。
    2. 统计每个 `write_counter` 值的规则数量。
    3. 输出统计信息，包括规则的总数和每个 `write_counter` 值对应的规则数量。
    """
    # 1. 加载 `not_written_counter` 文件的数据
    data = load_bin(NOT_WRITTEN_FILE)

    flat_counts = {}  # 用于存储不同 `write_counter` 值的规则数量
    total_rules = 0  # 统计规则的总数量

    # 2. 遍历所有分片的数据（每个分片的规则存储在字典中）
    for part_rules in data.values():
        if not isinstance(part_rules, dict):
            continue  # 如果该分片的数据不是字典，跳过
        # 3. 遍历当前分片规则的计数值
        for cnt in part_rules.values():
            total_rules += 1  # 每遇到一个规则，规则总数加 1
            c = min(int(cnt), 4)  # 将 `write_counter` 值限定在 4 以内
            flat_counts[c] = flat_counts.get(c, 0) + 1  # 统计每个 `write_counter` 值的规则数量

    # 4. 返回统计结果
    return flat_counts

# ===============================
# 单条规则 DNS 验证
# ===============================
def check_domain(rule):
    """
    用于验证给定的规则是否能够解析其域名。
    1. 解析规则中的域名。
    2. 尝试解析域名。
    3. 如果解析成功，返回原始规则；如果失败，返回 None。
    """
    # 创建 DNS 解析器实例，并设置超时
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    
    # 从规则中提取域名，去除前导 | 和其他字符
    domain = rule.lstrip("|").split("^")[0].replace("*", "")
    
    # 如果域名为空，返回 None 表示无效规则
    if not domain:
        return None
    
    try:
        # 尝试解析域名
        resolver.resolve(domain)
        return rule  # 如果解析成功，返回原规则
    except dns.resolver.NXDOMAIN:
        # 如果域名不存在，不做任何处理，直接返回 None
        pass
    except dns.resolver.Timeout:
        # 如果域名解析超时，不做任何处理，直接返回 None
        pass
    except Exception:
        # 其他异常错误，不做任何处理，直接返回 None
        pass
    
    # 如果无法解析，返回 None
    return None

# ===============================
# 下载并合并规则源
# ===============================
def download_all_sources():
    """
    下载所有规则源，合并规则，过滤并更新删除计数
    1. 下载所有规则源并合并为一个规则列表。
    2. 对规则列表中的每条规则进行过滤，更新删除计数。
    3. 根据规则是否在 merged_rules_temp.txt 中，重置或增加删除计数。
    """
    # 检查规则源文件是否存在
    if not os.path.exists(URLS_TXT):
        print("❌ urls.txt 不存在")
        return False
    print("📥 下载规则源...")

    all_rules = []  # 用列表来存储所有规则，不去重
    # 读取 URL 列表并下载规则
    with open(URLS_TXT, "r", encoding="utf-8") as f:
        urls = [u.strip() for u in f if u.strip()]
    
    # 下载所有规则源
    for url in urls:
        print(f"🌐 获取 {url}")
        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()  # 确保请求成功
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
    
    # 过滤并更新删除计数 >= 7 的规则
    filtered_rules, updated_delete_counter, skipped_count = filter_and_update_high_delete_count_rules(all_rules)
    
    # 将更新后的删除计数保存到文件
    save_bin(DELETE_COUNTER_FILE, updated_delete_counter)

    # 打印规则源合并后的统计信息
    print(f"📚 规则源合并规则 {len(all_rules)} 条，⏩共 {skipped_count} 条规则被跳过验证，🧮需要验证 {len(filtered_rules)} 条规则，🪓 分为 {PARTS} 片")

    # 切分规则，并传递删除计数器给分片处理函数
    split_parts(filtered_rules, updated_delete_counter)  # 传递 updated_delete_counter

    # 如果存在重试规则，加入合并规则中
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
    过滤和更新删除计数 >=7 的规则。
    1. 如果规则在 merged_rules_temp.txt 的规则列表中，重置删除计数为 6；
    2. 如果不在 merged_rules_temp.txt 规则列表中，继续增加删除计数，直到删除计数达到 28 时，删除该规则的删除计数记录。
    """
    delete_counter = load_bin(DELETE_COUNTER_FILE)  # 加载删除计数器
    low_delete_count_rules = set()  # 删除计数小于 7 的规则
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
        
    if removed_rules:
        print(f"🗑️ 共 {len(removed_rules)} 条规则的删除计数超过 28，已从计数器中移除。")
    
    if skipped_rules:
        for rule in skipped_rules[:20]:  # 输出前 20 条被跳过的规则
            print(f"⚠ 删除计数 ≥7，跳过验证：{rule}")
        print(f"🔢 共 {len(skipped_rules)} 条规则被跳过验证（删除计数≥7）")
    

    skipped_count = len(skipped_rules)
    return low_delete_count_rules, updated_delete_counter, skipped_count


# ===============================
# 哈希分片 + 负载均衡优化
# ===============================
def split_parts(merged_rules, balance_threshold=1, balance_move_limit=50):
    """
    使用哈希值将规则分片，并通过负载均衡优化规则分配到各个分片中。
    1. 规则首先通过哈希值进行初步分配。
    2. 然后，通过负载均衡优化，确保每个分片的规则数量尽量均衡。
    3. 最终将分片的规则保存到不同的文件中。
    """
    sorted_rules = sorted(merged_rules)  # 对规则进行排序，确保每次分配规则的顺序一致
    total = len(sorted_rules)  # 总规则数
    part_buckets = [[] for _ in range(PARTS)]  # 初始化 PARTS 个分片，作为规则容器
    hash_list = []  # 存储每条规则的哈希值

    # 1. 初步分配规则：根据规则的哈希值分配到不同的分片
    for rule in sorted_rules:
        h = int(hashlib.sha256(rule.encode("utf-8")).hexdigest(), 16)  # 计算规则的哈希值
        idx = h % PARTS  # 使用哈希值取余来确定分配到哪个分片
        part_buckets[idx].append(rule)  # 将规则加入对应的分片

        # 保存规则的哈希值，便于后续的操作
        hash_list.append(h)

    # 2. 负载均衡优化：将规则数量不均衡的分片进行调整
    while True:
        lens = [len(b) for b in part_buckets]  # 计算每个分片的规则数量
        max_len, min_len = max(lens), min(lens)  # 找出规则数量最多和最少的分片

        # 如果负载差距足够小，则结束负载均衡
        if max_len - min_len <= balance_threshold:
            break

        max_idx, min_idx = lens.index(max_len), lens.index(min_len)  # 获取负载最多和最少的分片索引
        move_count = min(balance_move_limit, (max_len - min_len) // 2)  # 计算需要移动的规则数量
        
        # 如果移动数量小于等于 0，则退出
        if move_count <= 0:
            break

        # 将规则从负载最大的分片移动到负载最小的分片
        part_buckets[min_idx].extend(part_buckets[max_idx][-move_count:])
        part_buckets[max_idx] = part_buckets[max_idx][:-move_count]

    # 3. 保存每个分片的规则
    for i, bucket in enumerate(part_buckets):
        filename = os.path.join(TMP_DIR, f"part_{i+1:02d}.txt")  # 为每个分片创建一个文件
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(bucket))  # 将分片中的规则写入文件
        print(f"📄 分片 {i+1}: {len(bucket)} 条规则 → {filename}")

    # 4. 将哈希值列表保存到文件，供后续验证或同步操作使用
    hash_list_file = os.path.join(TMP_DIR, "hash_list.bin")
    with open(hash_list_file, "wb") as f:
        msgpack.dump(hash_list, f)
    print(f"🔢 哈希值已保存至 {hash_list_file}")
        
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
def update_not_written_counter(part_num, valid_rules):
    """
    更新每个规则的 `write_counter`，并根据验证结果处理规则的重试逻辑。
    1. 将新验证成功规则valid_rules的 `write_counter` 重置为 6。
    2. 对于当前分片对应 validated_part_X.txt 中的规则，但未出现在新验证成功规则valid_rules 列表中的规则，递减 `write_counter`。
    3. write_counter = 1 规则，如果不在 merged_rules_temp.txt 列表中的，从分片对应 validated_part_X.txt 中的规则中删除，并将 `write_counter = 1` 规则不在 merged_rules_temp.txt 列表中的规则对应这条 `write_counter=1` 记录从 not_written_counter 删除；在 merged_rules_temp.txt 列表中的，按原来的方式处理。
    4. 如果 `write_counter <= 0`，将规则移入 retry_rules.txt 文件，并从分片对应 validated_part_X.txt 中的规则中删除，并 `write_counter <= 0` 这条记录从 not_written_counter 删除。
    5. 最终更新规则文件，并保存更新后的 `not_written_counter`。
    """
    part_key = f"validated_part_{part_num}"  # 当前分片的 key
    counter = load_bin(NOT_WRITTEN_FILE)  # 加载现有的 `not_written_counter` 文件

    # 1. 初始化每个 part 的计数器
    for i in range(1, PARTS + 1):
        counter.setdefault(f"validated_part_{i}", {})  # 初始化所有分片的计数器为空字典

    validated_file = os.path.join(DIST_DIR, f"{part_key}.txt")  # 当前分片已验证规则文件路径
    tmp_file = os.path.join(TMP_DIR, f"vpart_{part_num}.tmp")  # 当前分片临时文件路径
    merged_rules_file = os.path.join(TMP_DIR, "merged_rules_temp.txt")  # 临时合并规则文件路径

    # 2. 读取已验证、临时文件和合并规则文件中的规则
    existing_rules = set(open(validated_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(validated_file) else set()
    tmp_rules = set(open(tmp_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(tmp_file) else set()
    merged_rules = set(open(merged_rules_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(merged_rules_file) else set()

    part_counter = counter.get(part_key, {})  # 当前分片的计数器

    # 3. 将新验证成功的规则的 `write_counter` 重置为 6
    for r in valid_rules:
        part_counter[r] = 6  # 设置 `write_counter` 为 6，表示这些规则验证成功

    # 4. 对于当前分片对应 validated_part_X.txt 中的规则，但未出现在新验证成功规则 `valid_rules` 中的规则，递减 `write_counter`
    for r in existing_rules - set(valid_rules):  # 将 valid_rules 转换为 set
        part_counter[r] = max(part_counter.get(r, 6) - 1, 0)  # 如果规则在临时验证列表中没有出现，递减 `write_counter`

    # 5. 处理 `write_counter = 1` 的规则
    to_remove = [r for r in existing_rules if part_counter.get(r, 0) == 1 and r not in merged_rules]

    # 如果这些规则不在 `merged_rules_temp.txt` 中，删除它们
    if to_remove:
        for r in to_remove:
            print(f"❌ 删除规则 {r}，因为 `write_counter = 1` 且不在 merged_rules_temp.txt 列表中")
            existing_rules.remove(r)  # 从验证的规则中删除该规则
            part_counter.pop(r, None)  # 从计数器中删除该规则

    # 6. 如果 `write_counter <= 0`，将规则移入 retry_rules.txt 文件，并从分片对应 validated_part_X.txt 中的规则中删除
    to_retry = [r for r in existing_rules if part_counter.get(r, 0) <= 0]  # 找出需要重试的规则

    # 如果有规则需要重试，进行处理
    if to_retry:
        with open(RETRY_FILE, "a", encoding="utf-8") as rf:
            rf.write("\n".join(to_retry) + "\n")
        print(f"🔥 {len(to_retry)} 条 `write_counter <= 0` 的规则写入 {RETRY_FILE}")

        # 从已验证规则中删除这些重试的规则
        existing_rules -= set(to_retry)

    # 7. 从 `not_written_counter` 中删除 `write_counter <= 0` 的规则
    for r in to_retry:
        part_counter.pop(r, None)  # 从 `not_written_counter` 中删除该规则的记录

    # 8. 将更新后的规则写入验证文件
    with open(validated_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(existing_rules.union(valid_rules))))  # 合并已验证规则和新验证成功规则，并按字母顺序保存

    # 9. 更新 `part_counter`
    counter[part_key] = part_counter
    save_bin(NOT_WRITTEN_FILE, counter)  # 保存更新后的 `not_written_counter`

    # 10. 返回重试规则的数量
    return len(to_retry)  # 返回重试规则的数量



# ===============================
# 处理分片
# ===============================
def process_part(part):
    """
    处理每个分片的规则，验证规则并更新相关计数，最终保存验证结果。
    1. 如果分片文件不存在，尝试重新拉取规则源。
    2. 读取当前分片的规则，并根据规则的验证结果更新相关的计数器。
    3. 将验证通过的规则加入最终规则集，失败的规则增加删除计数，并根据删除计数更新规则的状态。
    4. 打印当前分片的验证统计信息，包括连续失败规则的统计和 `write_counter` 的规则分布。
    5. 最终保存更新后的规则并记录统计信息。
    """
    part = int(part)
    part_file = os.path.join(TMP_DIR, f"part_{part:02d}.txt")

    # 1. 如果分片文件不存在，尝试重新拉取规则源
    if not os.path.exists(part_file):
        print(f"⚠ 分片 {part} 缺失，重新拉取规则…")
        download_all_sources()  # 重新拉取所有规则源

    # 2. 如果分片仍然不存在，终止处理
    if not os.path.exists(part_file):
        print("❌ 分片仍不存在，终止")
        return

    # 读取当前分片的规则
    lines = [l.strip() for l in open(part_file, "r", encoding="utf-8").read().splitlines()]
    print(f"⏱ 验证分片 {part}, 共 {len(lines)} 条规则")

    out_file = os.path.join(DIST_DIR, f"validated_part_{part}.txt")
    
    # 3. 读取已有的已验证规则
    old_rules = set(open(out_file, "r", encoding="utf-8").read().splitlines()) if os.path.exists(out_file) else set()

    # 4. 加载删除计数器
    delete_counter = load_bin(DELETE_COUNTER_FILE)
    
    # 5. 过滤掉删除计数 >= 7 的规则，准备待验证规则
    rules_to_validate = [r for r in lines if int(delete_counter.get(r, 4)) < 7]
    
    # 6. 增加已验证失败规则的删除计数
    for r in lines:
        if int(delete_counter.get(r, 4)) >= 7:
            delete_counter[r] = int(delete_counter.get(r, 4)) + 1  # 更新已失败规则的删除计数

    final_rules = set(old_rules)  # 初始化最终规则集为已有验证规则
    valid = dns_validate(rules_to_validate, part)  # 进行 DNS 验证，返回有效规则
    added_count = 0
    failure_counts = {}

    # 7. 更新验证结果，处理失败计数并统计连续失败的规则
    for r in rules_to_validate:
        if r in valid:
            final_rules.add(r)  # 验证通过的规则加入最终规则
            delete_counter[r] = 0  # 验证成功规则的删除计数重置为 0
            added_count += 1
        else:
            # 失败规则增加删除计数，统计不同失败等级
            delete_counter[r] = int(delete_counter.get(r, 0)) + 1
            fc = min(int(delete_counter[r]), 4)  # 统计失败等级，只统计 1/4 至 4/4
            failure_counts[fc] = failure_counts.get(fc, 0) + 1
            if delete_counter[r] >= DELETE_THRESHOLD:  # 删除计数达到阈值，删除该规则
                final_rules.discard(r)

    # 8. 保存更新后的删除计数器
    save_bin(DELETE_COUNTER_FILE, delete_counter)

    # 9. 更新 `not_written_counter` 计数器，并获取删除的规则数量
    deleted_validated = update_not_written_counter(part, valid)  # 传入 valid_rules

    total_count = len(final_rules)  # 最终规则总数

    # 10. 打印当前分片连续失败统计（包括 1/4 至 7/4）
    print("\n📊 当前分片连续失败统计:")
    for i in range(1, 8):  # 扩展统计范围，打印 1/4 至 7/4
        if failure_counts.get(i, 0) > 0:
            print(f"    ⚠ 连续失败 {i}/4 的规则条数: {failure_counts[i]}")

    # 11. 打印当前分片 `write_counter` 规则统计
    print("\n📊 当前分片 write_counter 规则统计:")
    part_key = f"validated_part_{part}"
    counter = load_bin(NOT_WRITTEN_FILE)
    part_counter = counter.get(part_key, {})

    # 初始化每个 `write_counter` 的计数
    counts = {i: 0 for i in range(1, 8)}  # 支持 1/4 至 7/4 的统计

    for v in part_counter.values():
        v = int(v)
        if 1 <= v <= 7:  # 只统计 1 至 7 的范围
            counts[v] += 1

    total_rules = sum(counts.values())  # 总规则数
    print(f"    ℹ️ 总规则条数: {total_rules}")
    for i in range(1, 8):
        if counts[i] > 0:
            print(f"    ⚠ write_counter {i}/4 的规则条数: {counts[i]}")

    print("--------------------------------------------------")

    # 12. 保存最终规则
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(final_rules)))  # 将最终规则写入文件

    # 13. 打印统计信息并输出
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
