"""
studentcode_124090567.py

Hybrid ABR (throughput-based primary, with buffer protection)
- Parse simulator-provided structures robustly (Available Bitrates dict/list, Chunk.time, Next Chunk Sizes).
- Maintain EWMA bandwidth estimate (bytes/sec).
- Decision logic:
    1) If bw_est available: compute bw_bits = bw_est * 8.
       Choose the highest available bitrate <= safety_factor * bw_bits.
    2) Apply buffer protection/hysteresis:
       - If buffer_sec < low_buffer_thresh -> force lowest bitrate.
       - If chosen index > last and buffer_sec < up_buffer_thresh -> block upward switch.
    3) Fallback: if no bw_est, use conservative estimate or previous choice.
- Debug prints to stderr.
"""
import math
import time
import sys

# --- Utility / parsing helpers (same robust parsing as before) ---
def _as_float_if_possible(x, default=None):
    try:
        return float(x)
    except Exception:
        return default

def extract_number_from_struct(x, default=None):
    if x is None:
        return default
    if isinstance(x, (int, float)):
        return float(x)
    if isinstance(x, str):
        try:
            return float(x)
        except:
            return default
    if isinstance(x, (list, tuple)):
        for item in x:
            v = extract_number_from_struct(item, None)
            if v is not None:
                return v
        return default
    if isinstance(x, dict):
        # prefer 'time' for buffer/ chunk time
        for k in ('time', 'Chunk_Time', 'Chunk Time', 'chunk_time', 'chunkTime'):
            if k in x:
                v = extract_number_from_struct(x[k], None)
                if v is not None:
                    return v
        # then try other numeric keys like 'current','size','value'
        for k in ('current','size','value'):
            if k in x:
                v = extract_number_from_struct(x[k], None)
                if v is not None:
                    return v
        # fallback: try any value
        for k, v in x.items():
            num = extract_number_from_struct(v, None)
            if num is not None:
                return num
        return default
    return default

def parse_available_bitrates_and_sizes(av_brs_field, next_chunk_sizes_field):
    explicit_ncs = next_chunk_sizes_field
    if isinstance(av_brs_field, dict):
        numeric_keys = []
        numeric_items = {}
        for k, v in av_brs_field.items():
            try:
                kb = int(float(k))
                numeric_keys.append(kb)
                numeric_items[kb] = v
            except Exception:
                pass
        if numeric_keys:
            br_list = sorted(numeric_keys)
            sizes = [numeric_items.get(b, None) for b in br_list]
            if explicit_ncs is None:
                explicit_ncs = sizes
            return br_list, explicit_ncs
        for key in ('Available_Bitrates', 'Available Bitrates', 'bitrates'):
            if key in av_brs_field and isinstance(av_brs_field[key], (list, tuple)):
                return list(av_brs_field[key]), explicit_ncs
        return [], explicit_ncs
    if isinstance(av_brs_field, (list, tuple)):
        try:
            brs = [int(x) for x in av_brs_field]
            return brs, explicit_ncs
        except Exception:
            return [], explicit_ncs
    return [], explicit_ncs

def normalize_next_chunk_sizes(ncs, br_list, chunk_time):
    def estimate_size_from_br(br):
        try:
            return int(max(0.1, float(chunk_time)) * (float(br) / 8.0))
        except Exception:
            return int(max(0.1, float(chunk_time)) * (500000.0 / 8.0))
    if ncs is None:
        return [estimate_size_from_br(br) for br in br_list]
    if isinstance(ncs, dict):
        sizes_map = {}
        for k, v in ncs.items():
            try:
                ik = int(float(k))
                sizes_map[ik] = int(v)
            except Exception:
                num = extract_number_from_struct(v, None)
                if num is not None:
                    try:
                        ik = int(float(k))
                        sizes_map[ik] = int(num)
                    except:
                        pass
        return [sizes_map.get(b, estimate_size_from_br(b)) for b in br_list]
    if isinstance(ncs, (list, tuple)):
        res = []
        for i, b in enumerate(br_list):
            if i < len(ncs):
                item = ncs[i]
                num = extract_number_from_struct(item, None)
                if num is not None:
                    res.append(int(num))
                else:
                    res.append(estimate_size_from_br(b))
            else:
                res.append(estimate_size_from_br(b))
        return res
    return [estimate_size_from_br(br) for br in br_list]

# --- Agent ---
class HybridAgent:
    def __init__(self, available_bitrates_bps, chunk_time, debug=False):
        self.bitrates = sorted(available_bitrates_bps) if available_bitrates_bps else [500000]
        self.chunk_time = float(chunk_time)
        self.bw_est = None                # bytes/sec
        self.ewma_alpha = 0.6
        # throughput selection params
        self.safety_factor = 0.85         # choose bitrate <= safety_factor * bw_bits
        # buffer protection params
        self.low_buffer_thresh = 0.5      # seconds -> force lowest
        self.up_buffer_thresh = max(1.0, self.chunk_time)  # need this much buffer to allow upward switch
        # switching protection
        self.switch_penalty = 0.02
        self.min_switch_interval = 0.3
        self.last_switch_time = -9999.0
        self.last_chosen_index = 0
        self.debug = debug

    def _log(self, *args):
        if self.debug:
            print("[HybridAgent]", *args, file=sys.stderr)

    def update_bandwidth(self, inst_bw_bytes_per_sec):
        if inst_bw_bytes_per_sec is None:
            return
        try:
            if inst_bw_bytes_per_sec <= 0:
                return
        except Exception:
            return
        if self.bw_est is None:
            self.bw_est = float(inst_bw_bytes_per_sec)
        else:
            self.bw_est = self.ewma_alpha * float(inst_bw_bytes_per_sec) + (1 - self.ewma_alpha) * self.bw_est
        self._log("update_bandwidth -> inst_bw_bytes/s =", inst_bw_bytes_per_sec, "bw_est =", self.bw_est)

    def choose_bitrate(self, buffer_sec, chunk_sizes_bytes, current_time=None):
        current_time = current_time if current_time is not None else time.time()
        brs = self.bitrates
        n = len(brs)
        # default to lowest index
        chosen_idx = 0

        # If no bandwidth estimate, fallback to conservative (choose lowest)
        if self.bw_est is None or self.bw_est <= 1.0:
            self._log("No bw_est, fallback to lowest")
            chosen_idx = 0
        else:
            # compute bw in bits/sec
            bw_bits = self.bw_est * 8.0
            # find highest bitrate <= safety_factor * bw_bits
            allowed = [i for i, b in enumerate(brs) if b <= self.safety_factor * bw_bits]
            if allowed:
                cand_idx = max(allowed)
            else:
                # no bitrate fits safety -> choose lowest
                cand_idx = 0

            self._log("throughput-based cand_idx", cand_idx, "br", brs[cand_idx], "bw_bits", round(bw_bits,1))

            # buffer protection: if buffer small, force lowest
            if buffer_sec is None:
                buffer_sec = 0.0
            if buffer_sec < self.low_buffer_thresh:
                self._log("buffer low", buffer_sec, "forcing lowest")
                chosen_idx = 0
            else:
                # hysteresis: prevent small upward moves unless buffer large enough
                if cand_idx > self.last_chosen_index and buffer_sec < self.up_buffer_thresh:
                    self._log("blocking upward change (cand > last) due to buffer", buffer_sec, "need", self.up_buffer_thresh)
                    chosen_idx = self.last_chosen_index
                else:
                    chosen_idx = cand_idx

            # small penalty for frequent switching (if within min interval)
            if (current_time - self.last_switch_time) < self.min_switch_interval and chosen_idx != self.last_chosen_index:
                # block aggressive switch briefly
                self._log("recent switch, blocking change for stability")
                chosen_idx = self.last_chosen_index

        # update last_switch_time if change
        if chosen_idx != self.last_chosen_index:
            self.last_switch_time = current_time
        self.last_chosen_index = chosen_idx
        self._log("choose -> chosen_idx", chosen_idx, "bitrate", brs[chosen_idx])
        return chosen_idx

# global agent
AGENT = None

def init_agent(manifest):
    global AGENT
    if isinstance(manifest, dict):
        brs, _ = parse_available_bitrates_and_sizes(manifest, None)
        ct = extract_number_from_struct(manifest.get('Chunk_Time') or manifest.get('Chunk Time') or manifest.get('ChunkTime'), 2.0)
    else:
        brs = []
        ct = 2.0
    AGENT = HybridAgent(brs if brs else [500000], ct, debug=False)
    return AGENT

def student_entrypoint(measured_bandwidth,
                       prev_throughput,
                       buffer_occupancy,
                       available_bitrates,
                       video_time,
                       chunk_time,
                       rebuffer_time,
                       preferred_bitrate,
                       next_chunk_sizes=None):
    """
    Returns actual bitrate value (bit/s)
    """
    global AGENT

    # parse bitrates and sizes (same robust parser)
    br_list, sizes_from_ab = parse_available_bitrates_and_sizes(available_bitrates, next_chunk_sizes)
    if not br_list and isinstance(chunk_time, dict):
        br_list, sizes_from_ab = parse_available_bitrates_and_sizes(chunk_time, next_chunk_sizes)
    if not br_list:
        br_list = [500000, 1000000, 5000000]

    # chunk time prefer chunk_time['time']
    ct = None
    if isinstance(chunk_time, dict):
        ct = extract_number_from_struct(chunk_time.get('time'), None)
    if ct is None:
        ct = extract_number_from_struct(chunk_time, None)
    if ct is None:
        ct = 2.0

    # buffer occupancy: prefer 'time' field in Buffer Occupancy dict
    if isinstance(buffer_occupancy, dict):
        buf = extract_number_from_struct(buffer_occupancy.get('time') if 'time' in buffer_occupancy else buffer_occupancy, 0.0)
    else:
        buf = extract_number_from_struct(buffer_occupancy, 0.0)
    if buf is None:
        buf = 0.0

    # instant bandwidth (prefer measured_bandwidth then prev_throughput)
    inst_bw = None
    if measured_bandwidth is not None:
        inst_bw = measured_bandwidth
    elif prev_throughput is not None:
        inst_bw = prev_throughput

    if isinstance(inst_bw, dict):
        inst_bw = extract_number_from_struct(inst_bw, None)
    # heuristic bits->bytes conversion
    if inst_bw is not None:
        try:
            if inst_bw > 1e6:
                maybe_bytes = inst_bw / 8.0
                if maybe_bytes * 0.5 > 1.0:
                    inst_bw = maybe_bytes
        except Exception:
            pass

    # next_chunk_sizes
    if next_chunk_sizes is None and sizes_from_ab is not None:
        next_chunk_sizes = sizes_from_ab
    normalized_sizes = normalize_next_chunk_sizes(next_chunk_sizes, br_list, ct)

    # init / update AGENT
    if AGENT is None:
        AGENT = HybridAgent(br_list, ct, debug=False)
    else:
        AGENT.bitrates = sorted(br_list)
        AGENT.chunk_time = ct
        AGENT.up_buffer_thresh = max(1.0, AGENT.chunk_time)

    if inst_bw is not None:
        try:
            AGENT.update_bandwidth(float(inst_bw))
        except Exception:
            pass

    # decision: agent returns index -> translate to bitrate value
    try:
        idx = AGENT.choose_bitrate(buf, normalized_sizes, current_time=time.time())
    except Exception as e:
        print("[student_entrypoint] choose_bitrate exception:", e, file=sys.stderr)
        idx = 0

    if idx < 0 or idx >= len(br_list):
        idx = 0

    chosen_bitrate_value = int(br_list[idx])
    print(f"[student_entrypoint] Parsed br_list={br_list} normalized_sizes_sample={normalized_sizes[:min(5,len(normalized_sizes))]} chunk_time_used={ct} buffer_sec={buf}", file=sys.stderr)
    print(f"[student_entrypoint] Returning index {idx}, bitrate_value {chosen_bitrate_value}", file=sys.stderr)
    return chosen_bitrate_value
