#!/usr/bin/env python3
"""Patched generate_target.py wrapper for Linux 6.1+ kallsyms layout.

小米 14 Pro / HyperOS 3.0 (kernel 6.1.118) 的 kallsyms 把 seqs_of_names
压缩成 u8[3] 并放在 markers 和 token_table 之间，导致原 locate_markers
从 token_table 往前找时遇到 seqs_of_names 数据而失败。

本 wrapper monkey-patch recover_kallsyms：先找 offsets(u32 RVA 表)，
再推导 relative_base/num_syms/names，最后从 names 结束处往后找 markers。
"""
import sys, struct, importlib.util

sys.path.insert(0, ".")
spec = importlib.util.spec_from_file_location("gt", "generate_target.py")
gt = importlib.util.module_from_spec(spec)
sys.modules["gt"] = gt
spec.loader.exec_module(gt)


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def _is_canonical_kernel_pointer(v):
    return 0xFFFFFFC000000000 <= v <= 0xFFFFFFFFFFFFFFFF or 0xFFFF000000000000 <= v <= 0xFFFFFFFFFFFFFFFF


def _locate_offsets_and_derive(data, image_size, token_table_off):
    """Find kallsyms_offsets by searching for relative_base (canonical kernel
    pointer) then deriving offsets/num_syms backwards.

    Layout: [offsets(u32×N)][relative_base(u64)][num_syms(u32)][names...]
    """
    # Search for relative_base: a canonical arm64 kernel pointer (0xffffffc0...)
    # For 39-bit VA: range 0xffffff8000000000 - 0xffffffffffffffff
    # Little-endian high bytes: \x80..\xff \xff \xff \xff
    # We search for \xff\xff\xff (3 high bytes) then verify 8-byte aligned u64
    candidates = []
    pos = 0
    needle = b"\xff\xff\xff"
    while True:
        pos = data.find(needle, pos, token_table_off)
        if pos < 0:
            break
        # the \xff\xff\xff could be at bytes 5,6,7 of the u64 (big-endian high)
        # u64 LE: b0 b1 b2 b3 b4 b5 b6 b7  where b7,b6,b5 are high bytes
        # so rb_off = pos - 5  (b5=pos, b6=pos+1, b7=pos+2)
        rb_off = (pos - 5) & ~7  # align to 8
        if rb_off + 12 > len(data) or rb_off < 0:
            pos += 1
            continue
        rb = _u64(data, rb_off)
        if not (0xFFFFFF8000000000 <= rb <= 0xFFFFFFFFFFFFFFFF):
            pos += 1
            continue
        if rb & 0xFFF:  # usually page-aligned
            pos += 1
            continue
        ns = _u32(data, rb_off + 8)
        if not (1000 <= ns <= 2000000):
            pos += 1
            continue
        offsets_start = rb_off - ns * 4
        if offsets_start < 0 or offsets_start & 3:
            pos += 1
            continue
        # verify: offsets[0] should be 0 (_text RVA=0)
        if _u32(data, offsets_start) != 0:
            pos += 1
            continue
        # verify: offsets non-decreasing (sampled), <= image_size
        ok = True
        prev = 0
        for i in range(0, ns, max(1, ns // 200)):
            v = _u32(data, offsets_start + i * 4)
            if v < prev or v > image_size:
                ok = False
                break
            prev = v
        if not ok:
            pos += 1
            continue
        last_v = _u32(data, offsets_start + (ns - 1) * 4)
        if last_v > image_size:
            pos += 1
            continue
        candidates.append((offsets_start, ns, rb_off, rb))
        pos += 1
    if not candidates:
        gt.fail("patched: 找不到 kallsyms_offsets (relative_base 搜索失败)")
    if len(candidates) > 1:
        # prefer the one where offsets[1] == 0x10000 (_stext)
        for c in candidates:
            if _u32(data, c[0] + 4) == 0x10000:
                return c
        gt.fail("patched: kallsyms_offsets 候选不唯一: " + repr([(hex(p), n) for p, n, _, _ in candidates]))
    return candidates[0]


def _locate_markers_after_names(data, names_end, token_table_off, num_syms):
    """Find kallsyms_markers right after names end.

    markers: u32 array, strictly increasing, starts at 0, len = ceil(num_syms/256).
    In standard layout, markers immediately follow names (with possible padding).
    """
    expected_len = (num_syms + 255) // 256
    # try names_end aligned to 4, then +4
    for pad in range(0, 32, 4):
        start = (names_end + pad + 3) & ~3
        if start + expected_len * 4 > token_table_off:
            continue
        if pad and any(data[names_end:start]):
            continue
        if _u32(data, start) != 0:
            continue
        vals = [0]
        p = start + 4
        ok = True
        for i in range(1, expected_len):
            v = _u32(data, p)
            if v <= vals[-1]:
                ok = False
                break
            vals.append(v)
            p += 4
        if ok and len(vals) == expected_len and vals[-1] < token_table_off:
            return start, tuple(vals)
    gt.fail("patched: 在 names 后未找到 markers")


def patched_recover_kallsyms(data, kernel_size, image_size):
    token_table_off, token_index_off, token_index = gt.locate_token_tables(data)

    # Try standard path first
    try:
        markers_off, markers = gt.locate_markers(data, token_table_off)
        num_syms, names_off, names_end = gt.locate_names(data, markers_off, markers)
        decoded_names = gt.decode_kallsyms_names(
            data, names_off, num_syms, token_table_off, token_index, markers_off
        )
        address_table_off, addresses = gt.locate_u32_offset_table(
            data, decoded_names, token_index_off, image_size
        )
    except gt.GenerationError as e:
        msg = str(e)
        if "markers" not in msg and "offset" not in msg.lower():
            raise
        # Fallback: 6.1+ layout with compressed seqs_of_names between markers and token_table
        print(f"警告: 标准路径失败({msg})，尝试 6.1+ 布局...", file=sys.stderr)

        # 1. Find offsets (u32 RVA table)
        pos, num_syms, rb_off, relative_base = _locate_offsets_and_derive(data, image_size, token_table_off)
        address_table_off = pos
        addresses = tuple(_u32(data, pos + i * 4) for i in range(num_syms))
        print(f"  offsets @ 0x{pos:x}, num_syms={num_syms}, relative_base=0x{relative_base:x}", file=sys.stderr)

        # 2. names after relative_base(8) + num_syms(4), aligned to 8
        num_syms_off = rb_off + 8
        names_off = num_syms_off + 4
        # align to 8 (kernel often pads num_syms to 8-byte boundary)
        if names_off & 7:
            names_off = (names_off + 7) & ~7
        print(f"  names @ 0x{names_off:x}", file=sys.stderr)

        # 3. decode names to find names_end
        decoded_names = gt.decode_kallsyms_names(
            data, names_off, num_syms, token_table_off, token_index, token_table_off
        )
        # compute names_end
        pos_n = names_off
        for _ in range(num_syms):
            length = data[pos_n]
            pos_n += 1
            if length & 0x80:
                length = (length & 0x7F) | (data[pos_n] << 7)
                pos_n += 1
            pos_n += length
        names_end = pos_n
        # align
        if names_end & 3:
            names_end = (names_end + 3) & ~3
        print(f"  names_end @ 0x{names_end:x}", file=sys.stderr)

        # 4. markers after names_end
        markers_off, markers = _locate_markers_after_names(data, names_end, token_table_off, num_syms)
        print(f"  markers @ 0x{markers_off:x}, count={len(markers)}", file=sys.stderr)

    symbols = [
        (index, typ, name, addresses[index])
        for index, (typ, name) in enumerate(decoded_names)
    ]
    info = gt.KallsymsInfo(
        num_syms=num_syms,
        names_off=names_off,
        markers_off=markers_off,
        token_table_off=token_table_off,
        token_index_off=token_index_off,
        address_table_off=address_table_off,
        relative_base_off=0,
        relative_base=0,
        symbols=symbols,
        names_end=names_end if "names_end" in dir() else 0,
        marker_count=len(markers),
        address_schema="u32-base-relative",
    )

    # relative_base
    rb_off = address_table_off + num_syms * 4
    if rb_off + 8 <= len(data):
        rb = _u64(data, rb_off)
        if _is_canonical_kernel_pointer(rb):
            info.relative_base_off = rb_off
            info.relative_base = rb
        else:
            info.relative_base_off, info.relative_base = gt.infer_relative_base_off_66(data, address_table_off, num_syms)
    else:
        info.relative_base_off, info.relative_base = gt.infer_relative_base_off_66(data, address_table_off, num_syms)

    if not _is_canonical_kernel_pointer(info.relative_base):
        gt.fail(f"patched: relative_base 不是规范指针: 0x{info.relative_base:x}")

    # fixed-point checks
    if info.one("_text") != 0 or info.one("_stext") != 0x10000:
        gt.fail("patched: _text/_stext 固定点校验失败")
    end = info.offsets_for("_end")
    if end and end[0] != image_size:
        gt.fail(f"patched: _end 校验失败: 0x{end[0]:x} != 0x{image_size:x}")
    print(f"  _text=0 ✓ _stext=0x10000 ✓ _end=0x{image_size:x} {'✓' if end else '(无符号)'}", file=sys.stderr)
    return info


# ============================================================
# BTF fallback: Linux 6.1 没有 rt_waiter_node 子结构体，
# prio/deadline 直接在 rt_mutex_waiter 中。
# 当 btf.field("rt_waiter_node", X) 失败时，自动回退为
# btf.field("rt_mutex_waiter", X) - btf.field("rt_mutex_waiter", "tree")
# ============================================================
_orig_btf_field = gt.BTFInfo.field
_orig_btf_dfs = gt.BTFInfo.direct_field_size

def _patched_btf_field(self, struct_name, field_name):
    try:
        return _orig_btf_field(self, struct_name, field_name)
    except gt.GenerationError:
        if struct_name == "rt_waiter_node":
            base_off = _orig_btf_field(self, "rt_mutex_waiter", "tree")
            field_off = _orig_btf_field(self, "rt_mutex_waiter", field_name)
            print(f"  BTF fallback: rt_waiter_node.{field_name} -> "
                  f"rt_mutex_waiter.{field_name}({field_off}) - tree({base_off}) = {field_off - base_off}",
                  file=sys.stderr)
            return field_off - base_off
        raise

def _patched_btf_dfs(self, struct_name, field_name):
    try:
        return _orig_btf_dfs(self, struct_name, field_name)
    except gt.GenerationError:
        if struct_name == "rt_waiter_node":
            return _orig_btf_dfs(self, "rt_mutex_waiter", field_name)
        raise

gt.BTFInfo.field = _patched_btf_field
gt.BTFInfo.direct_field_size = _patched_btf_dfs


# Patch
gt.recover_kallsyms = patched_recover_kallsyms

if __name__ == "__main__":
    sys.exit(gt.main())
