import os
import msgpack
import requests
import argparse
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import hashlib
import pickle

# ===============================
# 配置区（Config）
# ===============================
URLS_TXT = "urls.txt"
TMP_DIR = "tmp"
DIST_DIR = "dist"
MASTER_RULE = "merged_rules.txt"


PARTS = 16
DNS_TIMEOUT = 2
HASH_LIST_FILE =os.path.join(DIST_DIR, "hash_list.bin") 
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
    """
    确保给定路径的二进制文件存在。如果文件不存在，则初始化为空的 msgpack 文件。
    1. 检查目标路径的目录是否存在，如果不存在则创建。
    2. 如果目标文件不存在，则尝试创建并写入一个空的 msgpack 数据。
    3. 如果发生异常，捕获并输出错误信息。
    """
    # 1. 确保目标文件所在的目录存在
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    # 2. 如果文件不存在，则尝试初始化文件
    if not os.path.exists(path):
        try:
            with open(path, "wb") as f:
                # 使用 msgpack 序列化空字典 {}，并写入文件
                f.write(msgpack.packb({}, use_bin_type=True))
        except Exception as e:
            # 3. 如果在创建或写入文件时发生异常，捕获并输出错误信息
            print(f"⚠ 初始化 {path} 失败: {e}")

# 确保删除计数器文件存在，如果不存在则初始化
ensure_bin_file(DELETE_COUNTER_FILE)
# 确保未写入计数器文件存在，如果不存在则初始化
ensure_bin_file(NOT_WRITTEN_FILE)

# 如果重试规则文件不存在，则创建空文件
if not os.path.exists(RETRY_FILE):
    open(RETRY_FILE, "w", encoding="utf-8").close()

# ===============================
# 二进制读取（msgpack）
# ===============================
def load_bin(path, print_stats=False):
    """
    读取给定路径的二进制文件（msgpack 格式）。
    1. 检查文件是否存在，如果存在则尝试加载文件。
    2. 使用 msgpack 解码数据，如果文件为空或发生错误，则返回空字典。
    3. 如果加载数据时发生异常，捕获异常并打印错误信息。
    4. 可选地打印统计信息（当前未启用）。
    """
    # 1. 检查文件是否存在，如果存在则尝试读取
    if os.path.exists(path):
        try:
            with open(path, "rb") as f:
                raw = f.read()  # 读取文件的原始数据
                if not raw:
                    return {}  # 如果文件为空，则返回空字典
                data = msgpack.unpackb(raw, raw=False)  # 使用 msgpack 解码数据
            return data  # 返回解码后的数据
        except Exception as e:
            # 2. 如果读取文件或解码过程中发生异常，打印错误并返回空字典
            print(f"⚠ 读取 {path} 错误: {e}")
            return {}
    return {}  # 如果文件不存在，返回空字典
# ===============================
# 二进制写入（msgpack）
# ===============================
def save_bin(path, data):
    """
    将数据保存到指定路径的二进制文件（msgpack 格式）。
    1. 尝试将数据序列化并保存为二进制文件。
    2. 如果发生错误，捕获异常并打印错误信息。
    """
    try:
        # 1. 打开文件进行写操作，并将数据序列化为 msgpack 格式
        with open(path, "wb") as f:
            f.write(msgpack.packb(data, use_bin_type=True))  # 使用 msgpack 序列化数据并写入文件
    except Exception as e:
        # 2. 如果保存数据过程中发生异常，打印错误信息
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
def save_hash_list(hashes, filename):
    """
    将哈希值列表以二进制格式保存到文件。
    """
    try:
        # 确保 dist 目录存在
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        print(f"🔐 正在保存哈希值列表到 {filename}, 哈希数量: {len(hashes)}")
        with open(filename, 'wb') as f:
            pickle.dump(hashes, f)
        print(f"🔐 哈希值列表已保存到 {filename}")
    except Exception as e:
        print(f"⚠ 保存哈希值列表到 {filename} 时发生错误: {e}")
        
def load_hash_list(filename):
    """
    从二进制文件中加载哈希值列表。
    """
    if os.path.exists(filename):
        try:
            with open(filename, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print(f"⚠ 加载哈希值列表时发生错误: {e}")
    return []  # 如果文件不存在，返回空列表

def split_parts(merged_rules, delete_counter, use_existing_hashes=False):
    """
    将规则列表分割成多个分片，并进行负载均衡。
    1. 根据 delete_counter 值结合哈希值将规则分配到不同的分片中，并生成哈希值列表文件，使用二进制存储。
    2. 每次调整后更新哈希值列表文件以便下轮使用。
    3. 后面每次采用哈希值列表文件切割分片，并进行负载均衡。
    4. 将分片的规则保存到文件中。
    """
    
    # 1. 如果使用现有的哈希值列表文件，则直接加载哈希值列表
    if use_existing_hashes:
        hash_list = load_hash_list(HASH_LIST_FILE)  # 加载现有的哈希列表
        if not hash_list:  # 如果哈希列表为空
            print("⚠ 哈希值列表为空，将重新计算并分配规则。")
            use_existing_hashes = False  # 设置为 False，重新计算哈希
    else:
        hash_list = []  # 如果不使用现有哈希值，则初始化为空列表

    # 2. 计算不同 delete_counter 值的规则
    counter_buckets = {i: [] for i in range(29)}  # 假设 delete_counter 最大为 28
    for rule, count in delete_counter.items():
        counter_buckets[count].append(rule)
    
    # 3. 初始化 PARTS 个分片（列表，存储分片内的规则）
    part_buckets = [[] for _ in range(PARTS)]  # PARTS 为分片数量，通常为 16

    # 4. 依次处理每个 delete_counter 值的规则
    for delete_val in range(29):  # 假设最大删除计数为 28
        rules_for_counter = counter_buckets[delete_val]  # 获取该删除计数对应的规则集合
        # 根据规则的哈希值将规则分配到分片中
        for rule in rules_for_counter:
            if use_existing_hashes:
                # 使用现有哈希值列表来获取规则的哈希值
                h = hash_list.pop(0)
            else:
                # 使用 SHA-256 哈希计算规则的哈希值，并转为十六进制整数
                h = int(hashlib.sha256(rule.encode("utf-8")).hexdigest(), 16)
                hash_list.append(h)  # 保存规则的哈希值

            idx = h % PARTS  # 使用哈希值对分片进行分配，确保规则的均匀分布
            part_buckets[idx].append(rule)

    # 5. 进行负载均衡优化
    while True:
        # 计算每个分片的规则数量
        lens = [len(b) for b in part_buckets]  # 获取每个分片内规则的数量
        max_len, min_len = max(lens), min(lens)  # 找到最大和最小规则数

        # 6. 如果负载差距足够小，则结束负载均衡
        if max_len - min_len <= BALANCE_THRESHOLD:
            break  # 如果差距小于或等于阈值，结束负载均衡

        # 7. 找到最大负载和最小负载的分片
        max_idx, min_idx = lens.index(max_len), lens.index(min_len)

        # 计算可以移动的规则数量（限制每次移动的最大数量）
        move_count = min(BALANCE_MOVE_LIMIT, (max_len - min_len) // 2)

        # 8. 如果需要移动的规则数小于等于 0，则退出负载均衡
        if move_count <= 0:
            break

        # 9. 将规则从负载最大的分片移动到负载最小的分片
        part_buckets[min_idx].extend(part_buckets[max_idx][-move_count:])
        part_buckets[max_idx] = part_buckets[max_idx][:-move_count]

    # 10. 将分配好的规则写入文件
    for i, bucket in enumerate(part_buckets):
        filename = os.path.join("tmp", f"part_{i+1:02d}.txt")  # 分片文件名
        os.makedirs("tmp", exist_ok=True)  # 确保临时目录存在
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(bucket))  # 将规则写入文件中
        print(f"📄 分片 {i+1}: {len(bucket)} 条规则 → {filename}")  # 输出每个分片的日志

    # 11. 更新哈希值列表文件
    save_hash_list(hash_list, HASH_LIST_FILE)  # 确保路径是 dist/hash_list.bin

def balance_parts(part_buckets):
    """
    对分片进行负载均衡优化。
    """
    avg = sum(len(b) for b in part_buckets) // PARTS

    # 进行负载均衡：将多余的规则从负载大的分片移动到负载小的分片
    for i, bucket in enumerate(part_buckets):
        while len(bucket) > avg * 1.2:  # 如果负载大于平均值的 120%
            rule = bucket.pop()
            target = find_lowest_part(part_buckets)  # 寻找负载最小的分片
            part_buckets[target].append(rule)

    return part_buckets

def find_lowest_part(part_buckets):
    """
    查找负载最小的分片索引
    """
    lens = [len(b) for b in part_buckets]
    return lens.index(min(lens))

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
