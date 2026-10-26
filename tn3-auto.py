import argparse
import glob
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time

EXP_TN3_TABLE = [
    (0, 1, 4), (0, 2, 4), (0, 3, 4), (0, 5, 4),
    (1, 1, 4), (1, 2, 4), (1, 3, 4), (1, 5, 4),
    (2, 1, 4), (2, 2, 4), (2, 3, 4), (2, 5, 4),
    (3, 1, 4), (3, 2, 4), (3, 3, 4), (3, 5, 4),
    (5, 1, 4), (5, 2, 4), (5, 3, 4), (5, 5, 4),
    (2, 2, 1), (2, 2, 2), (2, 2, 3), (2, 2, 5),
]

CHAIN_NAMES = {0: "N4_TX", 1: "N3_RLY1", 2: "N2_RLY2", 3: "N1_RLY3", 4: "GW_RX"}


def parse_kv_line(line: str) -> dict:
    line = line.strip()
    idx = line.find(" ")
    if line.startswith("# "):
        parts = line[2:].split(" ", 1)
        if len(parts) < 2:
            return {}
        body = parts[1]
    else:
        body = line[idx + 1:] if idx >= 0 else line
    out = {}
    for item in body.split(";"):
        if "=" in item:
            k, v = item.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def start_sniffer(tool, iface, duration_s, pcap_file):
    cmd = [tool, "-i", iface, "-a", f"duration:{int(duration_s)}", "-w", pcap_file]
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)


def stop_sniffer(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.send_signal(signal.SIGINT)
        proc.wait(timeout=15)
    except Exception:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


class RTTBoardClient:
    def __init__(self, host: str, port: int, name: str = ""):
        self.host = host
        self.port = port
        self.name = name or f"RTT_{port}"
        self.sock = None
        self.lines = []
        self.lock = threading.Lock()
        self.running = False
        self.thread = None
        self.chain_idx = None
        self.role_is_tx = False

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2.0)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.thread.start()
        print(f"[+] Connected {self.name} at {self.host}:{self.port}")

    def _reader_loop(self):
        buf = ""
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    time.sleep(0.05)
                    continue
                buf += data.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.rstrip("\r")
                    with self.lock:
                        self.lines.append(line)
            except socket.timeout:
                continue
            except Exception:
                break

    def clear_rx_buffer(self):
        with self.lock:
            self.lines.clear()

    def get_lines(self):
        with self.lock:
            return list(self.lines)

    def send_cmd(self, cmd: str):
        if not cmd.endswith("\r\n"):
            cmd += "\r\n"
        self.sock.sendall(cmd.encode("ascii"))

    def wait_for_pattern(self, regex: str, timeout_s: float = 10.0):
        pat = re.compile(regex)
        t0 = time.time()
        seen_idx = 0
        while time.time() - t0 < timeout_s:
            lines = self.get_lines()
            while seen_idx < len(lines):
                line = lines[seen_idx]
                seen_idx += 1
                m = pat.search(line)
                if m:
                    return line, m
            time.sleep(0.05)
        return None, None

    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


def parse_and_verify_raw_log(raw_text: str, source_name: str = ""):
    cfg, trig, cache, hopcheck = {}, {}, {}, {}
    csv_lines = []
    in_csv = False
    buffer_overflow = None
    expected_rows = None
    errors = []

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("# CFG "):
            cfg = parse_kv_line(line)
        elif line.startswith("# TRIG "):
            trig = parse_kv_line(line)
        elif line.startswith("# CACHE "):
            cache = parse_kv_line(line)
        elif line.startswith("# HOPCHECK "):
            hopcheck = parse_kv_line(line)
        elif line.startswith("--- BAT DAU XA LOG CSV ---"):
            in_csv = True
            m = re.search(r"SO DONG:\s*(\d+);\s*BI TRAN BUFFER:\s*(\d+)", line)
            if m:
                expected_rows = int(m.group(1))
                buffer_overflow = int(m.group(2))
        elif line.startswith("--- KET THUC XA LOG ---"):
            in_csv = False
        elif in_csv:
            if line.startswith("t_local_us,") or re.match(r"^\d+,0x[0-9A-Fa-f]+,", line):
                csv_lines.append(line)

    tx_row_count = 0
    last_t = -1
    for row in csv_lines[1:]:
        parts = row.split(",")
        if len(parts) >= 3 and parts[2] == "TX":
            tx_row_count += 1
        try:
            t_us = int(parts[0])
            if t_us < last_t:
                errors.append(f"t_local_us regressed ({last_t} -> {t_us})")
                break
            last_t = t_us
        except ValueError:
            pass

    if not cfg:
        errors.append("Missing '# CFG' line")
    else:
        if cfg.get("cfg_match", "1") != "1":
            errors.append(f"cfg_match={cfg.get('cfg_match')}")
        if cfg.get("mid_reset", "0") != "0":
            errors.append("mid_reset=1")
        if int(cfg.get("tx_fail", "0")) > 0:
            errors.append(f"tx_fail={cfg.get('tx_fail')} > 0")
        is_tx_role = (cfg.get("role") == "TX") or (cfg.get("chain_idx") == "0")
        target_msgs = int(cfg.get("num_msgs", "0"))
        if is_tx_role and target_msgs > 0 and tx_row_count != target_msgs:
            errors.append(f"TX rows ({tx_row_count}) != num_msgs ({target_msgs})")

    if buffer_overflow is not None and buffer_overflow > 0:
        errors.append(f"BI TRAN BUFFER: {buffer_overflow} > 0")

    if hopcheck:
        verdict = hopcheck.get("verdict", "")
        if verdict not in ("PASS", "PASS_TTL_BOUND"):
            errors.append(f"HOPCHECK verdict={verdict} (pct={hopcheck.get('pct')}%)")

    return {
        "source": source_name,
        "valid": len(errors) == 0,
        "errors": errors,
        "cfg": cfg,
        "trig": trig,
        "cache": cache,
        "hopcheck": hopcheck,
        "csv_rows": max(0, len(csv_lines) - 1),
        "tx_row_count": tx_row_count,
        "expected_rows": expected_rows,
        "buffer_overflow": buffer_overflow,
        "csv_lines": csv_lines,
    }


def verify_multi_board_logs(log_paths, out_dir=None, run_id=1, cond="open"):
    results = []
    for p in sorted(log_paths):
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            res = parse_and_verify_raw_log(f.read(), os.path.basename(p))
            results.append(res)

    if not results:
        print("[!] No log files found.", file=sys.stderr)
        return False

    idxs = {r["cfg"].get("tn3_idx") for r in results if r["cfg"]}
    tags = {r["cfg"].get("tn3_tag") for r in results if r["cfg"]}
    fws = {r["cfg"].get("fw") for r in results if r["cfg"]}
    nmsgs = {r["cfg"].get("num_msgs") for r in results if r["cfg"]}
    hops_set = {r["cfg"].get("hops") for r in results if r["cfg"]}

    cross_errors = []
    if len(idxs) != 1 or None in idxs:
        cross_errors.append(f"tn3_idx mismatch: {idxs}")
    if len(tags) != 1 or None in tags:
        cross_errors.append(f"tn3_tag mismatch: {tags}")
    if len(fws) != 1 or None in fws:
        cross_errors.append(f"fw mismatch: {fws}")
    if len(nmsgs) != 1 or None in nmsgs:
        cross_errors.append(f"num_msgs mismatch: {nmsgs}")
    if len(hops_set) != 1 or None in hops_set:
        cross_errors.append(f"hops mismatch: {hops_set}")

    cross_ok = len(cross_errors) == 0
    run_ok = cross_ok and all(r["valid"] for r in results)

    print("=" * 78)
    print(f"CROSS-BOARD VERIFICATION ({len(results)} files):")
    print(f"  • tn3_idx={idxs} | tag={tags} | fw={fws} | num_msgs={nmsgs} | hops={hops_set}")
    if not cross_ok:
        for ce in cross_errors:
            print(f"  [!] CROSS ERROR: {ce}")
    print("-" * 78)

    merged_header = "t_local_us,node_id,event,src,dst,seq,ttl_tx,ttl_rx,rssi,class,payload_len,DROP_CACHE"
    merged_rows = []
    common_tag = next(iter(tags)) if len(tags) == 1 and None not in tags else "unknown"

    for r in results:
        c = r["cfg"]
        ch_idx = int(c.get("chain_idx", -1)) if c else -1
        role_name = CHAIN_NAMES.get(ch_idx, f"IDX_{ch_idx}")
        status = "PASS" if (r["valid"] and cross_ok) else "REJECT"
        rho_str = r["cache"].get("rho", "-") if r["cache"] else "-"
        hop_str = r["hopcheck"].get("verdict", "-") if r["hopcheck"] else "-"
        print(f"  [{status}] {r['source']} ({role_name}): "
              f"tag={c.get('tn3_tag','?')} | cfg_match={c.get('cfg_match','?')} | "
              f"mid_reset={c.get('mid_reset','0')} | rows={r['csv_rows']} | "
              f"rho={rho_str} | hopcheck={hop_str}")
        for err in r["errors"]:
            print(f"      -> ERROR: {err}")

        if r["csv_lines"]:
            merged_rows.extend(r["csv_lines"][1:])
            if out_dir:
                base_dir = out_dir if run_ok else os.path.join(out_dir, "rejected")
                per_node_dir = os.path.join(base_dir, "per_node")
                os.makedirs(per_node_dir, exist_ok=True)
                tag = c.get("tn3_tag", "unknown")
                node_csv = os.path.join(per_node_dir, f"EXP3_{tag}_{cond}_run{run_id}_{role_name}.csv")
                with open(node_csv, "w", encoding="utf-8", newline="\n") as f_node:
                    f_node.write("\n".join(r["csv_lines"]) + "\n")

    if out_dir and merged_rows and common_tag != "unknown":
        merged_dir = out_dir if run_ok else os.path.join(out_dir, "rejected")
        os.makedirs(merged_dir, exist_ok=True)
        merged_csv = os.path.join(merged_dir, f"EXP3_{common_tag}_{cond}_run{run_id}.csv")
        with open(merged_csv, "w", encoding="utf-8", newline="\n") as f_merged:
            f_merged.write(merged_header + "\n")
            f_merged.write("\n".join(merged_rows) + "\n")
        print(f"  [✓] Merged CSV for analyze.py -> {merged_csv}")

    print("=" * 78)
    return run_ok


def recover_boards(boards):
    for b in boards:
        try:
            b.clear_rx_buffer()
            b.send_cmd("s")
            line, _ = b.wait_for_pattern(r"^# CFG ", timeout_s=3.0)
            if line and parse_kv_line(line).get("run") == "1":
                b.send_cmd("2")
                time.sleep(0.3)
            b.send_cmd("4")
            time.sleep(0.3)
        except Exception:
            pass


def execute_single_config(boards, tx_boards, rx_boards, idx, num_msgs, stabilize_s, run_id, out_dir, cond, sniffer_iface, sniffer_tool):
    retx, ntx, ttl = EXP_TN3_TABLE[idx]
    tag = f"r{retx}_t{ntx}_ttl{ttl}"

    for b in boards:
        b.clear_rx_buffer()
        b.send_cmd("4")
        time.sleep(0.6)
        b.send_cmd(f"n={num_msgs}")
        b.wait_for_pattern(r"^# \[INFO_RTT\]", timeout_s=3.0)
        b.send_cmd(f"idx={idx}")
        line, _ = b.wait_for_pattern(r"^# \[TN3_PRESET\]", timeout_s=5.0)
        if not line or "match=OK" not in line:
            raise RuntimeError(f"Board {b.name} failed preset idx={idx}: {line}")
        print(f"    [OK] {b.name} ({CHAIN_NAMES.get(b.chain_idx)}): {line}")

    print(f"[*] Waiting {stabilize_s}s for network stabilization...")
    time.sleep(stabilize_s)

    sniffer_proc = None
    pcap_file = os.path.join(out_dir, f"EXP3_{tag}_{cond}_run{run_id}.pcapng")
    if sniffer_iface:
        print(f"[*] Starting Sniffer ({sniffer_tool}) -> {pcap_file}")
        sniffer_proc = start_sniffer(sniffer_tool, sniffer_iface, num_msgs + 60, pcap_file)

    try:
        for b in rx_boards:
            b.clear_rx_buffer()
            b.send_cmd("2")
            line, _ = b.wait_for_pattern(r"# \[ACTION\] BO THU", timeout_s=5.0)
            if not line:
                raise RuntimeError(f"RX/Relay board {b.name} did not enter receive mode")

        time.sleep(1.0)
        for b in tx_boards:
            b.clear_rx_buffer()
            b.send_cmd("2")
            line, _ = b.wait_for_pattern(r"# \[ACTION\] Bat dau run TN3", timeout_s=5.0)
            if not line:
                raise RuntimeError(f"TX board {b.name} refused to start")
            print(f"    [RUN] {line}")

        t_wait = num_msgs + 45
        line_done, _ = tx_boards[0].wait_for_pattern(r"# \[INFO\] Du \d+ goi TN3", timeout_s=t_wait)
        if not line_done:
            raise RuntimeError(f"Timeout ({t_wait}s) waiting for TX completion")
        print(f"    [DONE] {line_done}")
        time.sleep(2.0)
    finally:
        stop_sniffer(sniffer_proc)

    raw_dir = os.path.join(out_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    raw_files = []
    for b in boards:
        b.clear_rx_buffer()
        b.send_cmd("3")
        end_line, _ = b.wait_for_pattern(r"--- KET THUC XA LOG ---", timeout_s=30.0)
        if not end_line:
            raise RuntimeError(f"Board {b.name} failed to finish CSV dump")
        role_label = CHAIN_NAMES.get(b.chain_idx, f"port{b.port}")
        raw_path = os.path.join(raw_dir, f"raw_EXP3_{tag}_{cond}_run{run_id}_{role_label}.log")
        with open(raw_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(b.get_lines()) + "\n")
        raw_files.append(raw_path)

    if not verify_multi_board_logs(raw_files, out_dir=out_dir, run_id=run_id, cond=cond):
        raise RuntimeError(f"Verification failed for idx={idx} ({tag})")


def run_automated_sweep(ports, indices, num_msgs, stabilize_s, run_id, out_dir, cond="open", sniffer_iface=None, sniffer_tool="tshark", max_retries=2):
    os.makedirs(out_dir, exist_ok=True)
    boards = []
    for p in ports:
        b = RTTBoardClient("127.0.0.1", p)
        b.connect()
        boards.append(b)

    failed_indices = []

    try:
        print("\n[*] Identifying board roles...")
        for b in boards:
            b.clear_rx_buffer()
            b.send_cmd("4")
            time.sleep(0.3)
            b.send_cmd("s")
            line, _ = b.wait_for_pattern(r"^# CFG ", timeout_s=5.0)
            if not line:
                raise RuntimeError(f"Board {b.name} did not respond with '# CFG'")
            kv = parse_kv_line(line)
            b.chain_idx = int(kv.get("chain_idx", -1))
            b.role_is_tx = (kv.get("cli_pub", "0") == "1") or (b.chain_idx == 0)
            print(f"    -> {b.name}: chain_idx={b.chain_idx} ({CHAIN_NAMES.get(b.chain_idx, '?')}), "
                  f"is_tx={b.role_is_tx}, mac={kv.get('mac')}")

        tx_boards = [b for b in boards if b.role_is_tx]
        rx_boards = [b for b in boards if not b.role_is_tx]
        if not tx_boards:
            raise RuntimeError("No TX board (N4 / cli_pub=1) found in RTT ports")

        for idx in indices:
            retx, ntx, ttl = EXP_TN3_TABLE[idx]
            tag = f"r{retx}_t{ntx}_ttl{ttl}"
            success = False

            for attempt in range(1, max_retries + 2):
                print(f"\n" + "=" * 72)
                print(f"[*] CONFIG idx={idx}/23 ({tag}) | Run={run_id} | Msgs={num_msgs} | Attempt={attempt}/{max_retries + 1}")
                print("=" * 72)
                try:
                    execute_single_config(
                        boards, tx_boards, rx_boards, idx, num_msgs,
                        stabilize_s, run_id, out_dir, cond, sniffer_iface, sniffer_tool
                    )
                    success = True
                    break
                except Exception as e:
                    print(f"[!] Error on idx={idx} ({tag}) attempt {attempt}: {e}", file=sys.stderr)
                    recover_boards(boards)
                    time.sleep(3.0)

            if not success:
                print(f"[X] Skipping idx={idx} ({tag}) after {max_retries + 1} failed attempts.", file=sys.stderr)
                failed_indices.append(idx)

            time.sleep(5.0)

        if failed_indices:
            fail_file = os.path.join(out_dir, f"failed_configs_run{run_id}.json")
            with open(fail_file, "w", encoding="utf-8") as f:
                json.dump({"run_id": run_id, "failed_indices": failed_indices}, f, indent=2)
            idx_str = " ".join(str(i) for i in failed_indices)
            ports_str = " ".join(str(p) for p in ports)
            print(f"\n[!] Completed with {len(failed_indices)} failed config(s): {failed_indices}")
            print(f"[!] Re-run failed configs with:")
            print(f"    python tn3-auto.py --ports {ports_str} --indices {idx_str} --run-id {run_id}")
        else:
            print(f"\n[✓] All {len(indices)} configurations completed and verified!")

    finally:
        for b in boards:
            b.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", type=int, nargs="*", default=[19021, 19022, 19023, 19024])
    ap.add_argument("--quick-test", action="store_true")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--indices", type=int, nargs="*", default=None)
    ap.add_argument("--num-msgs", type=int, default=None)
    ap.add_argument("--stabilize-sec", type=int, default=None)
    ap.add_argument("--run-id", type=int, default=1)
    ap.add_argument("--cond", default="open")
    ap.add_argument("--out-dir", default="data")
    ap.add_argument("--sniffer-iface", default=None)
    ap.add_argument("--sniffer-tool", default="tshark", choices=["tshark", "dumpcap"])
    ap.add_argument("--max-retries", type=int, default=2)
    ap.add_argument("--verify-logs", nargs="*")
    args = ap.parse_args()

    if args.verify_logs:
        paths = [f for pat in args.verify_logs for f in sorted(glob.glob(pat))]
        ok = verify_multi_board_logs(paths, out_dir=args.out_dir, run_id=args.run_id, cond=args.cond)
        sys.exit(0 if ok else 1)

    if args.quick_test:
        indices = args.indices if args.indices is not None else [0, 9, 20]
        num_msgs = args.num_msgs or 30
        stab_s = args.stabilize_sec if args.stabilize_sec is not None else 5
        run_automated_sweep(
            args.ports, indices, num_msgs, stab_s, args.run_id,
            args.out_dir, args.cond, args.sniffer_iface, args.sniffer_tool, args.max_retries
        )
    elif args.sweep or args.indices is not None:
        indices = args.indices if args.indices is not None else list(range(24))
        num_msgs = args.num_msgs or 1000
        stab_s = args.stabilize_sec if args.stabilize_sec is not None else 60
        run_automated_sweep(
            args.ports, indices, num_msgs, stab_s, args.run_id,
            args.out_dir, args.cond, args.sniffer_iface, args.sniffer_tool, args.max_retries
        )
    else:
        ap.print_help()


if __name__ == "__main__":
    main()