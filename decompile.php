<?php

// TODO:
// - identify bblocks from 0x4308* computed addresses?

class program_binary
{
	public $data;

	public function __construct($path, $ranges)
	{
		$this->data = file_get_contents($path);

		$this->code_ranges = [];
		$this->data_ranges = [];

		foreach ($ranges as $range) {
			if ($range[0] == 'c' || $range[0] == 'v') {
				$this->code_ranges[] = [to_phys_addr($range[1]), to_phys_addr($range[2])];
			}

			if ($range[0] == 's') {
				$this->data_ranges[] = [to_phys_addr($range[1]), to_phys_addr($range[2])];
			}
		}
	}

	public function is_in_code_range($v)
	{
		$v = to_phys_addr($v);

		foreach ($this->code_ranges as $range)
			if ($v >= $range[0] && $v <= $range[1])
				return true;

		return false;
	}

	public function is_in_data_range($v)
	{
		$v = to_phys_addr($v);

		foreach ($this->data_ranges as $range)
			if ($v >= $range[0] && $v <= $range[1])
				return true;

		return false;
	}

	public function read_word($addr)
	{
		if ($addr > strlen($this->data) - 4)
			throw new Exception('Out of bounds access');

		$unpacked = unpack("Naddr", substr($this->data, $addr, 4));

		return $unpacked['addr'];
	}

	public function read_cstring($addr)
	{
		$str = "";
		while ($this->data[$addr] != "\0" && $addr < strlen($this->data)) {
			$str .= $this->data[$addr];
			$addr++;
		}

		return $str;
	}

	public function read_cstring_formatted($addr)
	{
		return '"' . addcslashes($this->read_cstring($addr), "\0..\37!@\177..\377") . '"';
	}

	public function read_string_table($addr)
	{
		$addr = to_phys_addr($addr);
		$strings = [];

		while (true) {
			$item = $this->read_word($addr);
			if (!$this->is_in_data_range($item) || $item == 0)
				break;
			
			$strings[] = $this->read_cstring_formatted(to_phys_addr($item));
			$addr += 4;
		}

		return $strings;
	}

	public function read_code_address_table($addr)
	{
		$addr = to_phys_addr($addr);
		$addresses = [];

		while (true) {
			$item = $this->read_word($addr);
			if (!$this->is_in_code_range($item))
				break;
			
			$addresses[] = $item;
			$addr += 4;
		}

		return $addresses;
	}
}

class cpu_state
{
	public $regs;

	public function __construct()
	{
		$this->regs_known = [];
		$this->regs = [];

		$this->set_all_regs_unknown();
	}

	public function set_all_regs_unknown()
	{
		for ($i = 1; $i <= 32; $i++)
		{
			$this->regs[$i] = 0;
			$this->regs_known[$i] = false;
		}
	}

	public function set_reg_unknown($r)
	{
		$this->regs[$r] = 0;
		$this->regs_known[$r] = false;
	}

	public function set_reg($r, $v)
	{
		$this->regs[$r] = $v;
		$this->regs_known[$r] = true;
	}

	public function is_reg_known($r)
	{
		if ($r == 0)
			return true;
		return $this->regs_known[$r];
	}

	public function get_reg($r)
	{
		if ($r == 0)
			return 0;
		return $this->regs[$r];
	}

	public function fmt_reg($r)
	{
		global $ranges, $register_map;

		$v = $this->get_reg($r);

		if (isset($register_map[$v]))
			return $register_map[$v] . " /* " . to_hex32($v) . " */";

		foreach ($ranges as $range) {
			if ($v >= $range[1] && $v <= $range[2]) {
				$paddr = to_phys_addr($v);

				// resolve jump tables first
				global $jump_tables, $str_tables_map;
				foreach ($jump_tables as $t)
					if ($t[0] == $v)
						return to_hex32($v) . " /* JUMP TABLE " . to_addr_label($paddr) . " */";
				if (isset($str_tables_map[$paddr]))
					return "C_STR_ARRAY [" . implode(', ', $str_tables_map[$paddr]) . "] /* " . to_hex32($v) . " */";

				if ($range[0] == 's') {
					// pointer to data segment
					global $data;

					return "C_STR " . $data->read_cstring_formatted($paddr) . " /* " . to_hex32($v) . " at " . to_hex32($paddr) . " */";
				} else if ($range[0] == 'c') {
					return to_addr_label($paddr) . "/* " . to_hex32($v) . " at " . to_hex32($paddr) . " */";
				} else if ($range[0] == 'v') {
					; /* ignore vectors */
				} else if ($range[0] == 'd') {
					return to_hex32($v) . " /* DATA " . $range[3] . " AT " . to_hex32($paddr) . " OFF +0x" . (dechex($v - $range[1])) . " */";
				} else if ($range[0] == 'r') {
					return to_hex32($v) . " /* REG_OF " . $range[3] . " AT +0x" . (dechex($v - $range[1])) . " */";
				} else {
					return to_hex32($v) . " /* RANGE_OF " . $range[3] . " AT +0x" . (dechex($v - $range[1])) . " */";
				}

				break;
			}
		}

		if ($v >= -128 && $v <= 127)
			return $v . " /* " . to_hex32($v) . " */";

		return to_hex32($v);
	}
}

class insn
{
	public $addr;
	public $name;
	public $operands;
	public $orig;

	public function __construct($addr, $name, $ops)
	{
		$this->addr = $addr;
		$this->name = $name;
		$this->orig = $name . " " . $ops;

		switch ($name)
		{
			case "l.add":
			case "l.and":
			case "l.sub":
			case "l.xor":
			case "l.or":
			case "l.mul":
			case "l.sll":
			case "l.sra":
			case "l.srl":
				$this->operands = $this->parse_operands("d,a,b", $ops);
				break;

			case "l.addi":
			case "l.andi":
			case "l.xori":
			case "l.ori":
			case "l.slli":
			case "l.srai":
			case "l.srli":
				$this->operands = $this->parse_operands("d,a,i", $ops);
				break;

			case "l.movhi":
				$this->operands = $this->parse_operands("d,k", $ops);
				break;

			case "l.bf":
			case "l.bnf":
			case "l.j":
			case "l.jal":
				$this->operands = $this->parse_operands("n", $ops);
				break;

			case "l.jalr":
			case "l.jr":
				$this->operands = $this->parse_operands("d", $ops);
				break;

			case "l.lbs":
			case "l.lbz":
			case "l.lhz":
			case "l.lwz":
				$this->operands = $this->parse_operands("d,i(a)", $ops);
				break;

			case "l.sw":
			case "l.sb":
				$this->operands = $this->parse_operands("i(d),a", $ops);
				break;

			case "l.mfspr":
				$this->operands = $this->parse_operands("d,a,k", $ops);
				break;

			case "l.mtspr":
				$this->operands = $this->parse_operands("a,b,k", $ops);
				break;

			case "l.sfeq":
			case "l.sfges":
			case "l.sfgeu":
			case "l.sfgtu":
			case "l.sfles":
			case "l.sfleu":
			case "l.sflts":
			case "l.sfltu":
			case "l.sfne":
				$this->operands = $this->parse_operands("a,b", $ops);
				break;

			case "l.sfeqi":
			case "l.sfgesi":
			case "l.sfgtsi":
			case "l.sfgtui":
			case "l.sflesi":
			case "l.sfleui":
			case "l.sfltsi":
			case "l.sfltui":
			case "l.sfnei":
				$this->operands = $this->parse_operands("a,i", $ops);
				break;

			case "l.nop":
			case "l.csync":
			case "l.msync":
			case "l.psync":
			case "l.rfe":
				break;

			default:
				die("ERROR: Unknown insn $name\n");
		}
	}

	public function parse_operands($spec, $ops)
	{
		$op_specs = preg_split("#\s*,\s*#", $spec);
		$ops_list = preg_split("#\s*,\s*#", $ops);

		if (count($op_specs) != count($ops_list))
			die("ERROR: Invalid ops\n");

		$ops_map = [];
		foreach ($op_specs as $idx => $op_spec) {
			$op = $ops_list[$idx];

			if ($op_spec == 'a' || $op_spec == 'b' || $op_spec == 'd') {
				$ops_map[$op_spec] = $op;
			} else if ($op_spec == 'n') {
				if (preg_match('#^([0-9a-f]+)#', $op, $m))
					$ops_map[$op_spec] = hexdec($m[1]);
				else
					die("Invalid op\n");
			} else if ($op_spec == 'i' || $op_spec == 'k') {
				if (preg_match('#^0x([0-9a-f]+)$#', $op, $m))
					$op = hexdec($m[1]);
				else if (preg_match('#^(-?[0-9]+)$#', $op, $m))
					$op = (int)$m[1];
				else
					die("Invalid op\n");

				$ops_map[$op_spec] = $op;
			} else if ($op_spec == 'i(a)' || $op_spec == 'i(d)') {
				if (preg_match('#^(-?[0-9]+)\\((r[0-9]+)\\)$#', $op, $m)) {
					$ops_map['i'] = (int)$m[1];
					if ($op_spec == 'i(d)')
						$ops_map['d'] = $m[2];
					else
						$ops_map['a'] = $m[2];
				} else
					die("Invalid op\n");

			} else {
				die("ERROR: Unparsed op $op_spec\n");
			}
		}

		return (object)$ops_map;
	}

	public function sign_extend($n)
	{
		if ($n & 0x8000)
			return $n | 0xffff0000;
		return $n & 0xffffffff;
	}

	public function rename_reg($r)
	{
		switch ($r) {
			case 'r0': return '0';
			case 'r1': return 'SP';
			case 'r2': return 'FP';
			case 'r3': return 'A1';
			case 'r4': return 'A2';
			case 'r5': return 'A3';
			case 'r6': return 'A4';
			case 'r7': return 'A5';
			case 'r8': return 'A6';
			case 'r9': return 'LR';
			case 'r11': return 'RV';
		}
		return $r;
	}

	public function reg_index($r)
	{
		return (int)str_replace('r', '', $r);
	}

	public function explain($sim)
	{
		if (isset($this->operands->n))
			$jmp_desti = to_addr_label($this->operands->n);

		if (isset($this->operands->i)) {
			$i = $this->operands->i;
			$i_zhex = to_hex32($i & 0xffff);
			$i_shex = to_hex32($this->sign_extend($i));
			$i_shex_expl = sprintf("%d /* %s */", $i, to_hex32($this->sign_extend($i)) . ($i >= 0x20 && $i <= 0x7f ? ' \'' . chr($i) . '\'' : ''));
			$i_idx = $i > 0 ? "+$i" : ($i == 0 ? '' : $i);
		}

		if (isset($this->operands->a)) {
			$a = $this->rename_reg($this->operands->a);
			$a_idx = $this->reg_index($this->operands->a);
		}

		if (isset($this->operands->b)) {
			$b = $this->rename_reg($this->operands->b);
			$b_idx = $this->reg_index($this->operands->b);
		}

		if (isset($this->operands->d)) {
			$d = $this->rename_reg($this->operands->d);
			$d_idx = $this->reg_index($this->operands->d);
		}

		if (isset($this->operands->k))
			$k = $this->operands->k;

		switch ($this->name)
		{
			case "l.add":
				if ($sim->is_reg_known($a_idx) && $sim->is_reg_known($b_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) + $sim->get_reg($b_idx));
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				if ($this->operands->a == 'r0')
					return "$d = $b";
				return "$d = $a + $b";
			case "l.and":
				if ($sim->is_reg_known($a_idx) && $sim->is_reg_known($b_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) & $sim->get_reg($b_idx));
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				return "$d = $a & $b";
			case "l.sub":
				if ($sim->is_reg_known($a_idx) && $sim->is_reg_known($b_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) - $sim->get_reg($b_idx));
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				if ($this->operands->a == 'r0')
					return "$d = -$b";
				return "$d = $a - $b";
			case "l.xor":
				$sim->set_reg_unknown($d_idx);
				if ($sim->is_reg_known($a_idx) && $sim->is_reg_known($b_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) ^ $sim->get_reg($b_idx));
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				return "$d = $a ^ $b";
			case "l.or":
				if ($sim->is_reg_known($a_idx) && $sim->is_reg_known($b_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) | $sim->get_reg($b_idx));
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				return "$d = $a | $b";
			case "l.mul":
				$sim->set_reg_unknown($d_idx);
				return "$d = $a * $b";
			case "l.sll":
				if ($sim->is_reg_known($a_idx) && $sim->is_reg_known($b_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) << $sim->get_reg($b_idx));
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				return "$d = $a << $b";
			case "l.sra":
				if ($sim->is_reg_known($a_idx) && $sim->is_reg_known($b_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) >> $sim->get_reg($b_idx));
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				return "$d = arith $a >> $b";
			case "l.srl":
				$sim->set_reg_unknown($d_idx);

				return "$d = logical $a >> $b";

			case "l.addi":
				if ($sim->is_reg_known($a_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) + $i);
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				if ($this->operands->a == 'r0')
					return "$d = $i";
				if ($i < 0)
					return "$d = $a - " . -$i;
				if ($i == 0)
					return "$d = $a";
				return "$d = $a + $i";
			case "l.andi":
				if ($sim->is_reg_known($a_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) & $i);
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				return "$d = $a & $i_zhex";
			case "l.xori":
				if ($sim->is_reg_known($a_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) ^ $i);
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				return "$d = $a ^ $i_shex";
			case "l.ori":
				if ($sim->is_reg_known($a_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) | $i);
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				if ($i == 0)
					return "$d = $a";
				return "$d = $a | $i_zhex";
			case "l.slli":
				$sim->set_reg_unknown($d_idx);
				if ($sim->is_reg_known($a_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) << $i);
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				return "$d = $a << $i";
			case "l.srai":
				if ($sim->is_reg_known($a_idx)) {
					$sim->set_reg($d_idx, $sim->get_reg($a_idx) >> $i);
					return "$d = " . $sim->fmt_reg($d_idx);
				}

				$sim->set_reg_unknown($d_idx);

				return "$d = arith $a >> $i";
			case "l.srli":
				$sim->set_reg_unknown($d_idx);

				return "$d = logical $a >> $i";

			case "l.movhi":
				$sim->set_reg($d_idx, $k << 16);

				if ($k == 0)
					return "$d = 0";
				return "$d = 0x" . sprintf("%04x", $k) . "0000";

			case "l.bf":
				return "if (FLAG) goto $jmp_desti";
			case "l.bnf":
				return "if (!FLAG) goto $jmp_desti";

			case "l.j":
				return "goto $jmp_desti";
			case "l.jal":
				return "call $jmp_desti";
				//return "LR = " . to_addr_label($this->addr + 8) . " ; goto $jmp_desti";

			case "l.jalr":
				return "call $d";
				//return "LR = " . to_addr_label($this->addr + 8) . " ; goto $d";
			case "l.jr":
				if ($d == 'LR')
					return "return";
				return "goto $d";

			case "l.lbs":
				$sim->set_reg_unknown($d_idx);
				return "$d = [s8 {$a}$i_idx]";
			case "l.lbz":
				$sim->set_reg_unknown($d_idx);
				return "$d = [u8 {$a}$i_idx]";
			case "l.lhz":
				$sim->set_reg_unknown($d_idx);
				return "$d = [u16 {$a}$i_idx]";
			case "l.lwz":
				$sim->set_reg_unknown($d_idx);
				return "$d = [u32 {$a}$i_idx]";

			case "l.sw":
				if ($sim->is_reg_known($a_idx)) {
					return "[u32 {$d}$i_idx] = " . $sim->fmt_reg($a_idx);
				}

				return "[u32 {$d}$i_idx] = $a";
			case "l.sb":
				if ($sim->is_reg_known($a_idx)) {
					return "[u8 {$d}$i_idx] = " . $sim->fmt_reg($a_idx & 0xff);
				}

				return "[u8 {$d}$i_idx] = $a";

			case "l.mfspr":
				$kv = to_hex32($k & 0xffff);
				$k_help = sprintf(" /* grp = %d, reg = %d */", ($k >> 11) & 0x1f, $k & 0x7ff);
				$reg = "$a | $kv$k_help";
				if ($this->operands->a == 'r0')
					$reg = "$kv$k_help";
				else if ($k == 0)
					$reg = $a;

				$sim->set_reg_unknown($d_idx);
				return "$d = SPR($reg)";

			case "l.mtspr":
				$kv = to_hex32($k & 0xffff);
				$k_help = sprintf(" /* grp = %d, reg = %d */", ($k >> 11) & 0x1f, $k & 0x7ff);
				$reg = "$a | $kv$k_help";
				if ($this->operands->a == 'r0')
					$reg = "$kv$k_help";
				else if ($k == 0)
					$reg = $a;

				if ($sim->is_reg_known($b_idx)) {
					return "SPR($reg) = " . $sim->fmt_reg($b_idx);
				}

				return "SPR($reg) = $b";

			case "l.sfeq":
				return "FLAG = $a == $b";
			case "l.sfges":
				return "FLAG = signed $a >= $b";
			case "l.sfgeu":
				return "FLAG = unsigned $a >= $b";
			case "l.sfgtu":
				return "FLAG = unsigned $a > $b";
			case "l.sfles":
				return "FLAG = signed $a <= $b";
			case "l.sfleu":
				return "FLAG = unsigned $a <= $b";
			case "l.sflts":
				return "FLAG = signed $a < $b";
			case "l.sfltu":
				return "FLAG = unsigned $a < $b";
			case "l.sfne":
				return "FLAG = $a != $b";

			case "l.sfeqi":
				return "FLAG = $a == $i_shex_expl";
			case "l.sfgesi":
				return "FLAG = $a >= $i_shex_expl";
			case "l.sfgtsi":
				return "FLAG = signed $a > $i_shex_expl";
			case "l.sfgtui":
				return "FLAG = unsigned $a > $i_shex_expl";
			case "l.sflesi":
				return "FLAG = signed $a <= $i_shex_expl";
			case "l.sfleui":
				return "FLAG = unsigned $a <= $i_shex_expl";
			case "l.sfltsi":
				return "FLAG = signed $a < $i_shex_expl";
			case "l.sfltui":
				return "FLAG = unsigned $a < $i_shex_expl";
			case "l.sfnei":
				return "FLAG = $a != $i_shex_expl";

			case "l.nop":
			case "l.csync":
			case "l.msync":
			case "l.psync":
			case "l.rfe":
				return "asm \"{$this->name}\"";

			default:
				die("ERROR: Unknown insn $this->name\n");
		}
	}
}

function to_phys_addr($v) {
	if ($v >= 0x43080000 && $v < (0x43080000 + 128*1024)) {
		return $v - 0x43074000;
	}

	return $v;
}

function to_addr_label($a, $numeric = false)
{
	global $addr_names, $jump_tables, $fns;

	foreach ($jump_tables as $t)
		if (to_phys_addr($t[0]) == to_phys_addr($a))
			return "jt_" . sprintf("%06x", to_phys_addr($a));

	if (isset($addr_names[$a]) && !$numeric)
		return $addr_names[$a];

	if (isset($fns[$a]))
		return sprintf("fn_%06x", $a);

	return sprintf("l_%06x", $a);
}

function to_hex32($n)
{
	$hex = sprintf("0x%08x", $n);
	if (preg_match("#^0xffffffff([a-f0-9]{8})$#", $hex, $m))
		return "0x" . $m[1];
	return $hex;
}

// decompile

$register_list = [
	[0x1c00024, "VER_REG"],
	[0x1c00030, "EMAC_EPHY_CLK_REG"],
	[0x1c17000, "MSGBOX_CTRL_REG0"],
	[0x1c17004, "MSGBOX_CTRL_REG1"],
	[0x1c17040, "MSGBOX0_IRQ_EN_REG"],
	[0x1c17050, "MSGBOX0_IRQ_STATUS_REG"],
	[0x1c17060, "MSGBOX1_IRQ_EN_REG"],
	[0x1c17070, "MSGBOX1_IRQ_STATUS_REG"],
	[0x1c18000, "SPINLOCK_SYSTATUS_REG"],
	[0x1c18010, "SPINLOCK_STATUS_REG"],
	[0x1c20000, "PLL_CPUX_CTRL_REG"],
	[0x1c20008, "PLL_AUDIO_CTRL_REG"],
	[0x1c20010, "PLL_VIDEO_CTRL_REG"],
	[0x1c20018, "PLL_VE_CTRL_REG"],
	[0x1c20020, "PLL_DDR_CTRL_REG"],
	[0x1c20028, "PLL_PERIPH0_CTRL_REG"],
	[0x1c20038, "PLL_GPU_CTRL_REG"],
	[0x1c20044, "PLL_PERIPH1_CTRL_REG"],
	[0x1c20048, "PLL_DE_CTRL_REG"],
	[0x1c20050, "CPUX_AXI_CFG_REG"],
	[0x1c20054, "AHB1_APB1_CFG_REG"],
	[0x1c20058, "APB2_CFG_REG"],
	[0x1c2005c, "AHB2_CFG_REG"],
	[0x1c20060, "BUS_CLK_GATING_REG0"],
	[0x1c20064, "BUS_CLK_GATING_REG1"],
	[0x1c20068, "BUS_CLK_GATING_REG2"],
	[0x1c2006c, "BUS_CLK_GATING_REG3"],
	[0x1c20070, "BUS_CLK_GATING_REG4"],
	[0x1c20074, "THS_CLK_REG"],
	[0x1c20080, "NAND_CLK_REG"],
	[0x1c20088, "SDMMC0_CLK_REG"],
	[0x1c2008c, "SDMMC1_CLK_REG"],
	[0x1c20090, "SDMMC2_CLK_REG"],
	[0x1c2009c, "CE_CLK_REG"],
	[0x1c200a0, "SPI0_CLK_REG"],
	[0x1c200a4, "SPI1_CLK_REG"],
	[0x1c200b0, "I2S/PCM0_CLK_REG"],
	[0x1c200b4, "I2S/PCM1_CLK_REG"],
	[0x1c200b8, "I2S/PCM2_CLK_REG"],
	[0x1c200c0, "OWA_CLK_REG"],
	[0x1c200cc, "USBPHY_CFG_REG"],
	[0x1c200f4, "DRAM_CFG_REG"],
	[0x1c200fc, "MBUS_RST_REG"],
	[0x1c20100, "DRAM_CLK_GATING_REG"],
	[0x1c20118, "TCON0_CLK_REG"],
	[0x1c20120, "TVE_CLK_REG"],
	[0x1c20124, "DEINTERLACE_CLK_REG"],
	[0x1c20130, "CSI_MISC_CLK_REG"],
	[0x1c20134, "CSI_CLK_REG"],
	[0x1c2013c, "VE_CLK_REG"],
	[0x1c20140, "AC_DIG_CLK_REG"],
	[0x1c20144, "AVS_CLK_REG"],
	[0x1c20150, "HDMI_CLK_REG"],
	[0x1c20154, "HDMI_SLOW_CLK_REG"],
	[0x1c2015c, "MBUS_CLK_REG"],
	[0x1c201a0, "GPU_CLK_REG"],
	[0x1c20200, "PLL_STABLE_TIME_REG0"],
	[0x1c20204, "PLL_STABLE_TIME_REG1"],
	[0x1c20220, "PLL_CPUX_BIAS_REG"],
	[0x1c20224, "PLL_AUDIO_BIAS_REG"],
	[0x1c20228, "PLL_VIDEO_BIAS_REG"],
	[0x1c2022c, "PLL_VE_BIAS_REG"],
	[0x1c20230, "PLL_DDR_BIAS_REG"],
	[0x1c20234, "PLL_PERIPH0_BIAS_REG"],
	[0x1c2023c, "PLL_GPU_BIAS_REG"],
	[0x1c20244, "PLL_PERIPH1_BIAS_REG"],
	[0x1c20248, "PLL_DE_BIAS_REG"],
	[0x1c20250, "PLL_CPUX_TUN_REG"],
	[0x1c20260, "PLL_DDR_TUN_REG"],
	[0x1c20280, "PLL_CPUX_PAT_CTRL_REG"],
	[0x1c20284, "PLL_AUDIO_PAT_CTRL_REG0"],
	[0x1c20288, "PLL_VIDEO_PAT_CTRL_REG0"],
	[0x1c2028c, "PLL_VE_PAT_CTRL_REG"],
	[0x1c20290, "PLL_DDR_PAT_CTRL_REG0"],
	[0x1c2029c, "PLL_GPU_PAT_CTRL_REG"],
	[0x1c202a4, "PLL_PERIPH1_PAT_CTRL_REG1"],
	[0x1c202a8, "PLL_DE_PAT_CTRL_REG"],
	[0x1c202c0, "BUS_SOFT_RST_REG0"],
	[0x1c202c4, "BUS_SOFT_RST_REG1"],
	[0x1c202c8, "BUS_SOFT_RST_REG2"],
	[0x1c202d0, "BUS_SOFT_RST_REG3"],
	[0x1c202d8, "BUS_SOFT_RST_REG4"],
	[0x1c202f0, "CCU_SEC_SWITCH_REG"],
	[0x1c20300, "PS_CTRL_REG"],
	[0x1c20304, "PS_CNT_REG"],
	[0x1c20c00, "TMR_IRQ_EN_REG"],
	[0x1c20c04, "TMR_IRQ_STA_REG"],
	[0x1c20c10, "TMR0_CTRL_REG"],
	[0x1c20c14, "TMR0_INTV_VALUE_REG"],
	[0x1c20c18, "TMR0_CUR_VALUE_REG"],
	[0x1c20c20, "TMR1_CTRL_REG"],
	[0x1c20c24, "TMR1_INTV_VALUE_REG"],
	[0x1c20c28, "TMR1_CUR_VALUE_REG"],
	[0x1c20c80, "AVS_CNT_CTL_REG"],
	[0x1c20c84, "AVS_CNT0_REG"],
	[0x1c20c88, "AVS_CNT1_REG"],
	[0x1c20c8c, "AVS_CNT_DIV_REG"],
	[0x1c20ca0, "WDOG0_IRQ_EN_REG"],
	[0x1c20ca4, "WDOG0_IRQ_STA_REG"],
	[0x1c20cb0, "WDOG0_CTRL_REG"],
	[0x1c20cb4, "WDOG0_CFG_REG"],
	[0x1c20cb8, "WDOG0_MODE_REG"],
	[0x1c25000, "THS_CTRL0"],
	[0x1c25004, "THS_CTRL1"],
	[0x1c25014, "ADC_CDAT"],
	[0x1c25040, "THS_CTRL2"],
	[0x1c25044, "THS_INT_CTRL"],
	[0x1c25048, "THS_STAT"],
	[0x1c25050, "THS_ALARM_CTRL"],
	[0x1c25060, "THS_SHUTDOWN_CTRL"],
	[0x1c25070, "THS_FILTER"],
	[0x1c25074, "THS_CDATA"],
	[0x1c25080, "THS_DATA"],
	[0x1c28000, "UART0_DLL"],
	[0x1c28000, "UART0_RBR"],
	[0x1c28000, "UART0_THR"],
	[0x1c28004, "UART0_DLH"],
	[0x1c28004, "UART0_IER"],
	[0x1c28008, "UART0_FCR"],
	[0x1c28008, "UART0_IIR"],
	[0x1c2800c, "UART0_LCR"],
	[0x1c28010, "UART0_MCR"],
	[0x1c28014, "UART0_LSR"],
	[0x1c28018, "UART0_MSR"],
	[0x1c2801c, "UART0_SCH"],
	[0x1c2807c, "UART0_USR"],
	[0x1c28080, "UART0_TFL"],
	[0x1c28084, "UART0_RFL"],
	[0x1c280a4, "UART0_HALT"],
	[0x1c28400, "UART1_DLL"],
	[0x1c28400, "UART1_RBR"],
	[0x1c28400, "UART1_THR"],
	[0x1c28404, "UART1_DLH"],
	[0x1c28404, "UART1_IER"],
	[0x1c28408, "UART1_FCR"],
	[0x1c28408, "UART1_IIR"],
	[0x1c2840c, "UART1_LCR"],
	[0x1c28410, "UART1_MCR"],
	[0x1c28414, "UART1_LSR"],
	[0x1c28418, "UART1_MSR"],
	[0x1c2841c, "UART1_SCH"],
	[0x1c2847c, "UART1_USR"],
	[0x1c28480, "UART1_TFL"],
	[0x1c28484, "UART1_RFL"],
	[0x1c284a4, "UART1_HALT"],
	[0x1c28800, "UART2_DLL"],
	[0x1c28800, "UART2_RBR"],
	[0x1c28800, "UART2_THR"],
	[0x1c28804, "UART2_DLH"],
	[0x1c28804, "UART2_IER"],
	[0x1c28808, "UART2_FCR"],
	[0x1c28808, "UART2_IIR"],
	[0x1c2880c, "UART2_LCR"],
	[0x1c28810, "UART2_MCR"],
	[0x1c28814, "UART2_LSR"],
	[0x1c28818, "UART2_MSR"],
	[0x1c2881c, "UART2_SCH"],
	[0x1c2887c, "UART2_USR"],
	[0x1c28880, "UART2_TFL"],
	[0x1c28884, "UART2_RFL"],
	[0x1c288a4, "UART2_HALT"],
	[0x1c28c00, "UART3_DLL"],
	[0x1c28c00, "UART3_RBR"],
	[0x1c28c00, "UART3_THR"],
	[0x1c28c04, "UART3_DLH"],
	[0x1c28c04, "UART3_IER"],
	[0x1c28c08, "UART3_FCR"],
	[0x1c28c08, "UART3_IIR"],
	[0x1c28c0c, "UART3_LCR"],
	[0x1c28c10, "UART3_MCR"],
	[0x1c28c14, "UART3_LSR"],
	[0x1c28c18, "UART3_MSR"],
	[0x1c28c1c, "UART3_SCH"],
	[0x1c28c7c, "UART3_USR"],
	[0x1c28c80, "UART3_TFL"],
	[0x1c28c84, "UART3_RFL"],
	[0x1c28ca4, "UART3_HALT"],
	[0x1c2ac00, "TWI0_ADDR"],
	[0x1c2ac04, "TWI0_XADDR"],
	[0x1c2ac08, "TWI0_DATA"],
	[0x1c2ac0c, "TWI0_CNTR"],
	[0x1c2ac10, "TWI0_STAT"],
	[0x1c2ac14, "TWI0_CCR"],
	[0x1c2ac18, "TWI0_SRST"],
	[0x1c2ac1c, "TWI0_EFR"],
	[0x1c2ac20, "TWI0_LCR"],
	[0x1c2b000, "TWI1_ADDR"],
	[0x1c2b004, "TWI1_XADDR"],
	[0x1c2b008, "TWI1_DATA"],
	[0x1c2b00c, "TWI1_CNTR"],
	[0x1c2b010, "TWI1_STAT"],
	[0x1c2b014, "TWI1_CCR"],
	[0x1c2b018, "TWI1_SRST"],
	[0x1c2b01c, "TWI1_EFR"],
	[0x1c2b020, "TWI1_LCR"],
	[0x1c2b400, "TWI2_ADDR"],
	[0x1c2b404, "TWI2_XADDR"],
	[0x1c2b408, "TWI2_DATA"],
	[0x1c2b40c, "TWI2_CNTR"],
	[0x1c2b410, "TWI2_STAT"],
	[0x1c2b414, "TWI2_CCR"],
	[0x1c2b418, "TWI2_SRST"],
	[0x1c2b41c, "TWI2_EFR"],
	[0x1c2b420, "TWI2_LCR"],
	[0x1f01800, "TWD_STATUS_REG"],
	[0x1f01810, "TWD_CTRL_REG"],
	[0x1f01814, "TWD_RESTART_REG"],
	[0x1f01820, "TWD_LOW_CNT_REG"],
	[0x1f01824, "TWD_HIGH_CNT_REG"],
	[0x1f01830, "TWD_INTV_VAL_REG"],
	[0x1f01840, "TWD_LOW_CNT_CMP_REG"],
	[0x1f01844, "TWD_HIGH_CNT_CMP_REG"],
	[0x1f01900, "SST_NV_CNT_REG"],
	[0x1f01910, "SYN_DATA_CNT_REG0"],
	[0x1f01914, "SYN_DATA_CNT_REG1"],
	[0x1f01918, "SYN_DATA_CNT_REG2"],
	[0x1f0191c, "SYN_DATA_CNT_REG3"],
	[0x1f01c00, "CPUS_RST_CTRL_REG"],
	[0x1f01c40, "CPU0_RST_CTRL"],
	[0x1f01c44, "CPU0_CTRL_REG"],
	[0x1f01c48, "CPU0_STATUS_REG"],
	[0x1f01c80, "CPU1_RST_CTRL"],
	[0x1f01c84, "CPU1_CTRL_REG"],
	[0x1f01c88, "CPU1_STATUS_REG"],
	[0x1f01cc0, "CPU2_RST_CTRL"],
	[0x1f01cc4, "CPU2_CTRL_REG"],
	[0x1f01cc8, "CPU2_STATUS_REG"],
	[0x1f01d00, "CPU3_RST_CTRL"],
	[0x1f01d04, "CPU3_CTRL_REG"],
	[0x1f01d08, "CPU3_STATUS_REG"],
	[0x1f01d40, "CPU_SYS_RST_REG"],
	[0x1f01d44, "CPU_CLK_GATING_REG"],
	[0x1f01d84, "GENER_CTRL_REG"],
	[0x1f01da0, "SUP_STAN_FLAG_REG"],
	[0x1f01e80, "CNT64_CTRL_REG"],
	[0x1f01e84, "CNT64_LOW_REG"],
	[0x1f01e88, "CNT64_HIGH_REG"],
	[0x1f02000, "CIR_CTL"],
	[0x1f02010, "CIR_RXCTL"],
	[0x1f02020, "CIR_RXFIFO"],
	[0x1f0202c, "CIR_RXINT"],
	[0x1f02030, "CIR_RXSTA"],
	[0x1f02034, "CIR_CONFIG"],
	[0x1f02400, "R_TWI_ADDR"],
	[0x1f02404, "R_TWI_XADDR"],
	[0x1f02408, "R_TWI_DATA"],
	[0x1f0240c, "R_TWI_CNTR"],
	[0x1f02410, "R_TWI_STAT"],
	[0x1f02414, "R_TWI_CCR"],
	[0x1f02418, "R_TWI_SRST"],
	[0x1f0241c, "R_TWI_EFR"],
	[0x1f02420, "R_TWI_LCR"],
	[0x1f02800, "R_UART_DLL"],
	[0x1f02800, "R_UART_RBR"],
	[0x1f02800, "R_UART_THR"],
	[0x1f02804, "R_UART_DLH"],
	[0x1f02804, "R_UART_IER"],
	[0x1f02808, "R_UART_FCR"],
	[0x1f02808, "R_UART_IIR"],
	[0x1f0280c, "R_UART_LCR"],
	[0x1f02810, "R_UART_MCR"],
	[0x1f02814, "R_UART_LSR"],
	[0x1f02818, "R_UART_MSR"],
	[0x1f0281c, "R_UART_SCH"],
	[0x1f0287c, "R_UART_USR"],
	[0x1f02880, "R_UART_TFL"],
	[0x1f02884, "R_UART_RFL"],
	[0x1f028a4, "R_UART_HALT"],
	[0x1f00000, "LOSC_CTRL_REG"],
	[0x1f00004, "LOSC_AUTO_SWT_STA_REG"],
	[0x1f00008, "INTOSC_CLK_PRESCAL_REG"],
	[0x1f00010, "RTC_YY_MM_DD_REG"],
	[0x1f00014, "RTC_HH_MM_SS_REG"],
	[0x1f00020, "ALARM0_COUNTER_REG"],
	[0x1f00024, "ALARM0_CUR_VLU_REG"],
	[0x1f00028, "ALARM0_ENABLE_REG"],
	[0x1f0002c, "ALARM0_IRQ_EN"],
	[0x1f00030, "ALARM0_IRQ_STA_REG"],
	[0x1f00040, "ALARM1_WK_HH_MM_SS"],
	[0x1f00044, "ALARM1_ENABLE_REG"],
	[0x1f00048, "ALARM1_IRQ_EN"],
	[0x1f0004c, "ALARM1_IRQ_STA_REG"],
	[0x1f00050, "ALARM_CONFIG_REG"],
	[0x1f00060, "LOSC_OUT_GATING_REG"],
	[0x1f00100, "GP_DATA_REG0"],
	[0x1f00104, "GP_DATA_REG1"],
	[0x1f00108, "GP_DATA_REG2"],
	[0x1f0010c, "GP_DATA_REG3"],
	[0x1f00110, "GP_DATA_REG4"],
	[0x1f00114, "GP_DATA_REG5"],
	[0x1f00118, "GP_DATA_REG6"],
	[0x1f0011c, "GP_DATA_REG7"],
	[0x1f00170, "RTC_DEB_REG"],
	[0x1f00180, "GPL_HOLD_OUTPUT_REG"],
	[0x1f00190, "VDD_RTC_REG"],
	[0x1f001f0, "IC_CHARA_REG"],
	[0x1F02C00, "R_PIO_PL_CFG0"],
	[0x1F02C04, "R_PIO_PL_CFG1"],
	[0x1F02C08, "R_PIO_PL_CFG2"],
	[0x1F02C0C, "R_PIO_PL_CFG3"],
	[0x1F02C10, "R_PIO_PL_DAT"],
	[0x1F02C14, "R_PIO_PL_DRV0"],
	[0x1F02C18, "R_PIO_PL_DRV1"],
	[0x1F02C1C, "R_PIO_PL_PUL0"],
	[0x1F02C20, "R_PIO_PL_PUL1"],
	[0x1F02E00, "R_PIO_PL_INT_CFG0"],
	[0x1F02E04, "R_PIO_PL_INT_CFG1"],
	[0x1F02E08, "R_PIO_PL_INT_CFG2"],
	[0x1F02E0C, "R_PIO_PL_INT_CFG3"],
	[0x1F02E10, "R_PIO_PL_INT_CTL"],
	[0x1F02E14, "R_PIO_PL_INT_STA"],
	[0x1F02E18, "R_PIO_PL_INT_DEB"],
	[0x1f01000 + 0x00, "R_WDOG_IRQ_EN"],
	[0x1f01000 + 0x04, "R_WDOG_IRQ_STA"],
	[0x1f01000 + 0x10, "R_WDOG_CTRL"],
	[0x1f01000 + 0x14, "R_WDOG_CFG"],
	[0x1f01000 + 0x18, "R_WDOG_MODE"],

	//[0x1f01400 + 0x0000, "R_PRCM_"],
	[0x1f01400 + 0x0100, "R_PRCM_CPU_PWROFF_REG"],
	[0x1f01400 + 0x0140 + 0 * 0x4, "R_PRCM_CPU0_PWR_CLAMP"],
	[0x1f01400 + 0x0140 + 1 * 0x4, "R_PRCM_CPU1_PWR_CLAMP"],
	[0x1f01400 + 0x0140 + 2 * 0x4, "R_PRCM_CPU2_PWR_CLAMP"],
	[0x1f01400 + 0x0140 + 3 * 0x4, "R_PRCM_CPU3_PWR_CLAMP"],

	[0x1f01c00 + 0x40 + 0 * 0x40, "R_CPUCFG_CPU0_RESET_CTL"],
	[0x1f01c00 + 0x40 + 1 * 0x40, "R_CPUCFG_CPU1_RESET_CTL"],
	[0x1f01c00 + 0x40 + 2 * 0x40, "R_CPUCFG_CPU2_RESET_CTL"],
	[0x1f01c00 + 0x40 + 3 * 0x40, "R_CPUCFG_CPU3_RESET_CTL"],
	[0x1f01c00 + 0x44 + 0 * 0x40, "R_CPUCFG_CPU0_CONTROL"],
	[0x1f01c00 + 0x44 + 1 * 0x40, "R_CPUCFG_CPU1_CONTROL"],
	[0x1f01c00 + 0x44 + 2 * 0x40, "R_CPUCFG_CPU2_CONTROL"],
	[0x1f01c00 + 0x44 + 3 * 0x40, "R_CPUCFG_CPU3_CONTROL"],
	[0x1f01c00 + 0x48 + 0 * 0x40, "R_CPUCFG_CPU0_STATUS"],
	[0x1f01c00 + 0x48 + 1 * 0x40, "R_CPUCFG_CPU1_STATUS"],
	[0x1f01c00 + 0x48 + 2 * 0x40, "R_CPUCFG_CPU2_STATUS"],
	[0x1f01c00 + 0x48 + 3 * 0x40, "R_CPUCFG_CPU3_STATUS"],
	[0x1f01c00 + 0x0000, "R_CPUCFG_REG0"], // bit 0 is arisc reset bit
	[0x1f01c00 + 0x01a4, "R_CPUCFG_P_REG0"],
	[0x1f01c00 + 0x01a8, "R_CPUCFG_P_REG1"],
	[0x1f01c00 + 0x01e0, "R_CPUCFG_DBGCTL0"],
	[0x1f01c00 + 0x01e4, "R_CPUCFG_DBGCTL1"],

	// DRAMCOM/DRAMCTL known regs
	[0x1c62000 + 0x00, "DRAMCOM_MC_WORK_MODE"],

	[0x1c63000 + 0x00, "DRAMCTL0_PIR"],
	[0x1c63000 + 0x04, "DRAMCTL0_PWRCTL"],
	[0x1c63000 + 0x10, "DRAMCTL0_PGSR0"],
	[0x1c63000 + 0x18, "DRAMCTL0_STATR"],
	[0x1c63000 + 0xc0, "DRAMCTL0_DTCR"],
	[0x1c63000 + 0x120, "DRAMCTL0_ODTMAP"],
	[0x1c63000 + 0x344 + 0x80 * 0 , "DRAMCTL0_DX0GCR0"],
	[0x1c63000 + 0x344 + 0x80 * 1 , "DRAMCTL0_DX1GCR0"],
	[0x1c63000 + 0x344 + 0x80 * 2 , "DRAMCTL0_DX2GCR0"],
	[0x1c63000 + 0x344 + 0x80 * 3 , "DRAMCTL0_DX3GCR0"],

#define SRAM_DDRFREQ_SIZE           (SZ_8K)

/* register define */

	//TODO: CCU R_INTC R_CPUCFG DRAMCOM DRAMCTL0 DE
];

for ($i = 0; $i < 8; $i++) {
	$register_list[] = [0x1c17100 + $i * 4, "MSGBOX{$i}_FIFO_STATUS_REG"];
	$register_list[] = [0x1c17140 + $i * 4, "MSGBOX{$i}_MSG_STATUS_REG"];
	$register_list[] = [0x1c17180 + $i * 4, "MSGBOX{$i}_MSG_REG"];
}

for ($i = 0; $i < 32; $i++)
	$register_list[] = [0x1c18100 + $i * 4, "SPINLOCK_LOCK_REG$i"];

$ports = ['A', 'B', 'C', 'D', 'E', 'F', 'G'];
foreach ($ports as $n => $port) {
	if ($n == 1)
		continue;

	$register_list[] = [0x01C20800 + $n * 0x24 + 0x00, "PIO_P${port}_CFG0"];
	$register_list[] = [0x01C20800 + $n * 0x24 + 0x04, "PIO_P${port}_CFG1"];
	$register_list[] = [0x01C20800 + $n * 0x24 + 0x08, "PIO_P${port}_CFG2"];
	$register_list[] = [0x01C20800 + $n * 0x24 + 0x0C, "PIO_P${port}_CFG3"];
	$register_list[] = [0x01C20800 + $n * 0x24 + 0x10, "PIO_P${port}_DAT"];
	$register_list[] = [0x01C20800 + $n * 0x24 + 0x14, "PIO_P${port}_DRV0"];
	$register_list[] = [0x01C20800 + $n * 0x24 + 0x18, "PIO_P${port}_DRV1"];
	$register_list[] = [0x01C20800 + $n * 0x24 + 0x1C, "PIO_P${port}_PUL0"];
	$register_list[] = [0x01C20800 + $n * 0x24 + 0x20, "PIO_P${port}_PUL1"];
	if ($n == 0 || $n == 6) {
		$i = $n == 0 ? 0 : 1;
		$register_list[] = [0x01C20800 + 0x200 + $i * 0x20 + 0x00, "PIO_P${port}_INT_CFG0"];
		$register_list[] = [0x01C20800 + 0x200 + $i * 0x20 + 0x04, "PIO_P${port}_INT_CFG1"];
		$register_list[] = [0x01C20800 + 0x200 + $i * 0x20 + 0x08, "PIO_P${port}_INT_CFG2"];
		$register_list[] = [0x01C20800 + 0x200 + $i * 0x20 + 0x0C, "PIO_P${port}_INT_CFG3"];
		$register_list[] = [0x01C20800 + 0x200 + $i * 0x20 + 0x10, "PIO_P${port}_INT_CTL"];
		$register_list[] = [0x01C20800 + 0x200 + $i * 0x20 + 0x14, "PIO_P${port}_INT_STA"];
		$register_list[] = [0x01C20800 + 0x200 + $i * 0x20 + 0x18, "PIO_P${port}_INT_DEB"];
	}
}

$register_map = [];
foreach ($register_list as $r) {
	$register_map[$r[0]] = $r[1];
	//printf("%-30s %s\n", $r[1], to_hex32($r[0]));
}

$ranges = [
	["v", 0x00000,    0x03fff,    "exception vectors code"],
	["c", 0x04000,    0x0817B,    "code"],
	["d", 0x0817C,    0x0828B,    "sram params1"],
	["s", 0x0828C,    0x0881B,    "sram strings"],
	["d", 0x0881C,    0x08AD7,    "sram params2"],
	["d", 0x08AD8,    0x08F5F,    "sram globals"],
	["d", 0x08F60,    0x0963F,    "sram stack"],
	["d", 0x09640,    0x0BFFF,    "?????"],
	["c", 0x43080000, 0x43088E0F, "dram code"],
	["s", 0x43088E10, 0x43088EF3, "dram strings"],
	["d", 0x43088EF4, 0x430894F7, "dram params1"],
	["s", 0x430894F8, 0x4308A93F, "dram strings2"],

	["r", 0x01000000, 0x013fffff, "DE"                  ], 
	["r", 0x01400000, 0x0141ffff, "De-interlaced"       ], 
	["r", 0x01c00000, 0x01c00fff, "System-Control"      ], 
	["r", 0x01c02000, 0x01c02fff, "DMA"                 ], 
	["r", 0x01c03000, 0x01c03fff, "NFDC"                ], 
	["r", 0x01c06000, 0x01c06fff, "TS"                  ], 
	["r", 0x01c0b000, 0x01c0bfff, "Key-Memory-Space"    ], 
	["r", 0x01c0c000, 0x01c0cfff, "LCD-0"               ], 
	["r", 0x01c0d000, 0x01c0dfff, "LCD-1"               ], 
	["r", 0x01c0e000, 0x01c0efff, "VE"                  ], 
	["r", 0x01c0f000, 0x01c0ffff, "SD/MMC-0"            ], 
	["r", 0x01c10000, 0x01c10fff, "SD/MMC-1"            ], 
	["r", 0x01c11000, 0x01c11fff, "SD/MMC-2"            ], 
	["r", 0x01c14000, 0x01c143ff, "SID"                 ], 
	["r", 0x01c15000, 0x01c15fff, "Crypto-Engine"       ], 
	["r", 0x01c17000, 0x01c17fff, "MSG_BOX"             ], 
	["r", 0x01c18000, 0x01c18fff, "SPINLOCK"            ], 
	["r", 0x01c19000, 0x01c19fff, "USB-OTG_Device"      ], 
	["r", 0x01c1a000, 0x01c1afff, "USB-OTG_EHCI0/OHCI0" ], 
	["r", 0x01c1b000, 0x01c1bfff, "USB-HCI1"            ], 
	["r", 0x01c1c000, 0x01c1cfff, "USB-HCI2"            ], 
	["r", 0x01c1d000, 0x01c1dfff, "USB-HCI3"            ], 
	["r", 0x01c1e000, 0x01c1efff, "SMC"                 ], 
	["r", 0x01c20000, 0x01c203ff, "CCU"                 ], 
	["r", 0x01c20800, 0x01c20bff, "PIO"                 ], 
	["r", 0x01c20c00, 0x01c20fff, "TIMER"               ], 
	["r", 0x01c21000, 0x01c213ff, "OWA"                 ], 
	["r", 0x01c21400, 0x01c217ff, "PWM"                 ], 
	["r", 0x01c21800, 0x01c21bff, "KEYADC"              ], 
	["r", 0x01c22000, 0x01c223ff, "I2S/PCM-0"           ], 
	["r", 0x01c22400, 0x01c227ff, "I2S/PCM-1"           ], 
	["r", 0x01c22800, 0x01c22bff, "I2S/PCM-2"           ], 
	["r", 0x01c22c00, 0x01c233ff, "AC"                  ], 
	["r", 0x01c23400, 0x01c237ff, "SMTA"                ], 
	["r", 0x01c25000, 0x01c253ff, "THS"                 ], 
	["r", 0x01c28000, 0x01c283ff, "UART-0"              ], 
	["r", 0x01c28400, 0x01c287ff, "UART-1"              ], 
	["r", 0x01c28800, 0x01c28bff, "UART-2"              ], 
	["r", 0x01c28c00, 0x01c28fff, "UART-3"              ], 
	["r", 0x01c2ac00, 0x01c2afff, "TWI-0"               ], 
	["r", 0x01c2b000, 0x01c2b3ff, "TWI-1"               ], 
	["r", 0x01c2b400, 0x01c2b7ff, "TWI-2"               ], 
	["r", 0x01c2c400, 0x01c2c7ff, "SCR"                 ], 
	["r", 0x01c30000, 0x01c3ffff, "EMAC"                ], 
	["r", 0x01c40000, 0x01c4ffff, "GPU"                 ], 
	["r", 0x01c60000, 0x01c60fff, "HSTMR"               ], 
	["r", 0x01c62000, 0x01c62fff, "DRAMCOM"             ], 
	["r", 0x01c63000, 0x01c63fff, "DRAMCTL0"            ], 
	["r", 0x01c65000, 0x01c65fff, "DRAMPHY0"            ], 
	["r", 0x01c68000, 0x01c68fff, "SPI0"                ], 
	["r", 0x01c69000, 0x01c69fff, "SPI1"                ], 
	["r", 0x01c80000, 0x01c80fff, "SCU"                 ], 
	["r", 0x01c81000, 0x01c81fff, "GIC_DIST"            ], 
	["r", 0x01c82000, 0x01c82fff, "GIC_CPUIF"           ], 
	["r", 0x01cb0000, 0x01cfffff, "CSI"                 ], 
	["r", 0x01e00000, 0x01e0ffff, "TVE"                 ], 
	["r", 0x01ee0000, 0x01efffff, "HDMI"                ], 
	["r", 0x01f00000, 0x01f003ff, "RTC"                 ], 
	["r", 0x01f00800, 0x01f00bff, "R_TIMER"             ], 
	["r", 0x01f00c00, 0x01f00fff, "R_INTC"              ], 
	["r", 0x01f01000, 0x01f013ff, "R_WDOG"              ], 
	["r", 0x01f01400, 0x01f017ff, "R_PRCM"              ], 
	["r", 0x01f01800, 0x01f01bff, "R_TWD"               ], 
	["r", 0x01f01c00, 0x01f01fff, "R_CPUCFG"            ], 
	["r", 0x01f02000, 0x01f023ff, "R_CIR-RX"            ], 
	["r", 0x01f02400, 0x01f027ff, "R_TWI"               ], 
	["r", 0x01f02800, 0x01f02bff, "R_UART"              ], 
	["r", 0x01f02c00, 0x01f02fff, "R_PIO"               ], 
	["r", 0x01f03800, 0x01f03bff, "R_PWM"               ], 
	["r", 0x3f500000, 0x3f51ffff, "CoreSight-Debug"     ], 
	["r", 0x3f506000, 0x3f506fff, "TSGEN-RO"            ], 
	["r", 0x3f507000, 0x3f507fff, "TSGEN-CTRL"          ], 
	//["r", 0x40000000, 0xbfffffff, "DDR-III/LPDDR-II"    ], 
	//["r", 0xffff0000, 0xffff7fff, "N-BROM"              ], 
	//["r", 0xffff0000, 0xffffffff, "S-BROM"              ], 
];

/*
5 fn_007cec
5 fn_00d314
5 fn_00e938
5 fn_0125b8
6 fn_00c000
6 fn_00c6d8
6 fn_00c744
6 fn_0103a0
6 fn_014d94
7 fn_00d8f0
7 fn_00ed4c
7 fn_00ffd4
7 fn_0116a4
7 fn_012eec
7 fn_014170
8 fn_0061cc
8 fn_00d2fc
8 fn_00d800
8 fn_00f5ec
8 fn_0118d4
8 fn_012f14
9 fn_00ea68
10 fn_0133ac
11 fn_00d968
12 fn_00f298
13 fn_011794
18 fn_014c1c
21 fn_00e590
23 fn_007a10
27 fn_014c34
30 fn_00fe70
58 fn_007c6c
77 fn_007a24
193 fn_dprintf
 */

$addr_names = [
	0x7d68 => "fn_exception_reset",
	0x7ea8 => "fn_exception_bus_error",
	0x7ecc => "fn_exception_data_page_fault",
	0x7ef0 => "fn_exception_insn_page_fault",
	0x7f14 => "fn_exception_tick_timer",
	0x7f38 => "fn_exception_alignment",
	0x7f5c => "fn_exception_illegal_insn",
	0x7f80 => "fn_exception_ext_interrupt",
	0x7fa4 => "fn_exception_dtlb_miss",
	0x7fc8 => "fn_exception_itlb_miss",
	0x7fec => "fn_exception_range",
	0x8010 => "fn_exception_system_call",
	0x8034 => "fn_exception_floating_point",
	0x8058 => "fn_exception_trap",
	0x13404 => "fn_dprintf",
	0x130f4 => "fn_main",
	0x12f24 => "fn_exit",
	0x7974 => "fn_format_num_hex",
	0x7808 => "fn_sram_r_uart_putc",
	0x7860 => "fn_sram_r_uart_puts", // encodes 0xa as 0x0d0a on the line
	0x10fcc => "fn_dram_r_uart_putc",
	0x110a4 => "fn_dram_r_uart_puts", // encodes 0xa as 0x0d0a on the line
	0x133e8 => "fn_dram_r_uart_puts_always_ok", // encodes 0xa as 0x0d0a on the line
	0x78b4 => "fn_space_padding",
	0x7a24 => "fn_sram_dprintf",
	0x792c => "fn_strcpy",
	0x117b4 => "fn_strcpy2",
	0x7954 => "fn_strlen",
	0x11794 => "fn_strlen2",
	0x807c => "fn_shared_exception_handler",
	0x12f44 => "fn_shared_exception_handler_main",
	0x7a10 => "fn_write_r_rtc_gp_data_reg2",
	0xf5ec => "fn_ccu_get_clk_freq",
	0xf404 => "fn_ccu_set_clk_freq",
	0x14c1c => "fn_delay_loop",
	0xdcf0 => "fn_set_voltage",
	0xdf8c => "fn_get_voltage",
	0x7c08 => "fn_read_cnt64",
	0x7c6c => "fn_delay_cnt64",
	0x4480 => "fn_dram_sdrclk_update",
	0x5c4c => "fn_cir_rx_data",
	0x5ce8 => "fn_cir_receive",
	0x67c0 => "fn_dram_crc",
	0x55bc => "fn_dram_powerup0",
	0x590c => "fn_dram_powerup1",
	0x5c20 => "fn_dram_powerup2",
	0x5618 => "fn_dram_powerdown1",
	0x5bf4 => "fn_dram_powerdown2",
	0x61cc => "fn_delay_busyloop",
	0x6218 => "fn_r_pio_set_pin",
	0x6514 => "fn_power_off_24mhz_osc",
	0x659c => "fn_power_on_24mhz_osc",
	0x125b8 => "fn_print_and_call_fn_with_arg",
	0xe384 => "fn_dram_reboot",
	0x62d8 => "fn_sram_reboot",
	0xf064 => "fn_set_poweroff_gating_for_power_module",
	0xf114 => "fn_shutdown_24mhz_osc",
	0xf834 => "fn_shutdown_24mhz_osc_done_callback",
	0xec30 => "fn_apb_clock_change",
	0xe5a8 => "fn_clock_set_source",
	0xed4c => "fn_clock_module_set_source",
	0xf298 => "fn_clock_module_set_reset",
	0xea68 => "fn_clock_set_divider",
	0x7300 => "fn_suspend_cpu",
	0xfdb8 => "fn_del_timer",
	0xfd40 => "fn_add_timer",
	0x12d54 => "fn_verify_init",
	0x142cc => "fn_message_alloc",
	0x14440 => "fn_message_free",
	0x141b0 => "fn_message_manager_init",
	0x12f14 => "fn_write_sr_reg",
	0x10a58 => "fn_read_twi_r_reg",
	0x10b9c => "fn_write_twi_r_reg",
	0xd6a0 => "fn_set_ir_paras",
	0x12600 => "fn_standby_get_info",
	0x11ba4 => "fn_cpux_dvfs_request",
	0x11ed8 => "fn_cpux_dvfs_config_request",
	0xd32c => "fn_install_isr",
	0xd394 => "fn_uninstall_isr",
	0xd1d8 => "fn_isr_dummy_function",
	0xd2a8 => "fn_init_all_isr_to_dummy_fn",
	0xcef0 => "fn_take_hw_spinlock",
	0xcfd0 => "fn_release_hw_spinlock",
	0xce80 => "fn_init_hw_spinlock",
	0x1372c => "fn_init_debugger",
	0x14544 => "fn_process_message",
	0x148e4 => "fn_receive_message",
	0xc7b4 => "fn_msgbox_isr",
	0xc990 => "fn_hwmsgbox_init",
	0x10ea4 => "fn_r_uart_init",
	0x13da4 => "fn_r_uart_isr",
	0xd2fc => "fn_interrupt_enable",
	0xd314 => "fn_interrupt_disable",
	0xd218 => "fn_save_interrupts",
	0xd268 => "fn_restore_interrupts",
	0x12eec => "fn_disable_iee_tee_exceptions",
	0x12ed4 => "fn_enable_iee_exceptions",
	0x11b70 => "fn_set_dram_crc_params",
	0x11ad4 => "fn_get_dram_crc_params",
	0xcc38 => "fn_send_loopback_message",
	0x11f68 => "fn_enter_standby",
	0x11df0 => "fn_print_dvfs_table",
	0x11128 => "fn_r_uart_chnage_baudrate",
	0x118d4 => "fn_memcpy_optimized",
	0x11990 => "fn_memset",
	0x1188c => "fn_strcmp",
	0x11814 => "fn_strncpy",
	0x1174c => "fn_dec_str_to_uint32",
	0x116a4 => "fn_hex_str_to_uint32",
	0x11598 => "fn_uint32_to_hex_str",
	0x14c34 => "__udivsi3",
	0x14d94 => "__umodsi3",
	0x14db4 => "__modsi3",
	0x14d30 => "__divsi3",
	0x13950 => "fn_dbg_cmd_cat",
	0x13b18 => "fn_dbg_cmd_print",
	0x13c40 => "fn_dbg_cmd_set_baudrate",
	0x13cf4 => "fn_dbg_cmd_set_debuglevel",
	0x13844 => "fn_dbg_cmd_echo",
	0x13824 => "fn_dbg_cmd_reboot",
	0x137c8 => "fn_dbg_cmd_help",
	0x13774 => "fn_dbg_set_mask",
	0xfa88 => "fn_timer_install",
	0xf794 => "fn_timer_isr",
	0x14a18 => "fn_notifier_allocate",
	0xebf8 => "fn_add_clock_change_notifier",
	0x14bc0 => "fn_notifier_broadcast",
	0x13048 => "fn_timer_server_setup",
	0x149cc => "fn_notifiers_clear",
	0xe4b8 => "fn_init_clock_source",
	0xd7d4 => "fn_init_clock_divider",
	0xc114 => "fn_le_config_add",
	0xc218 => "fn_le_config_remove",
	0xc054 => "fn_le_config_init",
	0x10080 => "fn_set_twi_clock",
	0x101d8 => "fn_twi_clock_change_callback",
	0x10264 => "fn_twi_init",
	0xe2f4 => "fn_pmu_pin_driver_init",
	0xf984 => "fn_timer_driver_init",
	0x1256c => "fn_standby_service_init",
	0x1133c => "fn_watchdog_init",
	0xca94 => "fn_message_send",
	0x13000 => "fn_timer_server_callback",
	0x13034 => "fn_timer_server_get_counter",
	0x637c => "fn_apb_clock_change_do",
	0x6b78 => "fn_plls_change_suspend",
	0x710c => "fn_plls_change_resume",
	0x686c => "fn_bus_change_suspend",
	0x6aec => "fn_bus_change_resume",
	0xcd5c => "fn_message_receive",
	0xe780 => "fn_clock_mod_set_divider",
	0xe6dc => "fn_clock_mod_set_divider_inner",
	0x10038 => "fn_twi_reset",
	0x10008 => "fn_twi_master_start",
	0xffd4 => "fn_twi_wait_int",
	0x128bc => "fn_save_cpux_ctrl",
	0x1291c => "fn_restore_cpux_ctrl",
	0x12e90 => "fn_verify_confirmed",
	0xe590 => "fn_write_reg",
	0xe938 => "fn_get_clk_divider",
	0xefec => "fn_get_cpu_clk_params"
];

$register_map[0x9014] = "timer_server_counter";
$register_map[0x8aa0] = "debug_mask";
$register_map[0x8c04] = "r_prcm_base_addr";
$register_map[0x8c00] = "ccu_base_addr";
$register_map[0x8bfc] = "pll_periph0_ctrl_reg_addr";
$register_map[0x8854] = "r_uart_enabled";
$register_map[0x8828] = "timers_array";
$register_map[0x90b0] = "notifiers_array";
$register_map[0x881c] = "little_endian_config_array4";
$register_map[0x8fd0] = "dvfs_state_freq_voltage_axidiv";
//$register_map[0x8fac] = "clock_notifier_list";


$hand_found_fns = [
	0x101d8,
	0xf794,
	0xf834,
	0x7bf4,
	0x12f44,
	0x12f24,
	0x126ac,
	0x130f4,
	0x62d8,
	0xda14,
	0x7300,
	0xfdb8,
	0xd394,
	0xd1d8,
	0xc7b4,
	0x13da4,
	0x119b8,
	0xd194,
	0xd1b4,
	0x13950,
	0x13b18,
	0x13c40,
	0x13cf4,
	0x13844,
	0x13824,
	0x137c8,
];

$jump_tables = [
	[0x43089480, [0xf2c4]], 
	[0x43088e54, [0xe5d4]], 
	[0x43088ec0, [0xea94]], 
	[0x430894b8, [0xf618]], 
];
$str_tables = [0x00008a60, 0x43089570, 0x4308952c];

$asm = file_get_contents($argv[1]);
$data = new program_binary($argv[2], $ranges);

/*
get pll1_factors table
for ($i = 0; $i <= 336; $i++) {
	$param = $data->read_word(0x14f3c + $i * 4);
	$p = $param & 0xff;
	$m = ($param >> 8) & 0xff;
	$k = ($param >> 16) & 0xff;
	$n = ($param >> 24) & 0xff;
	$f = (24*($n+1)*($k+1))/(($m+1)*(2**$p));
	$ff = $i * 6;
	//echo "// $f = " . to_hex32($data->read_word(0x14f3c + $i * 4)) . ",\n";
	echo "\t{ .n = $n, .k = $k, .m = $m, .p = $p }, // ${ff} => {$f} MHz\n";
}
die();
*/

$lines = explode("\n", $asm);
$insns = [];
$new_insns = [];
$bblocks = [];
$xrefs = [];
$fns = [];
$delay_slots = [];
$jt_targets = [];
$delayed = null;

foreach ($hand_found_fns as $a) {
	$fns[$a] = true;
	$bblocks[$a] = true;
}

// parse code ranges
foreach ($lines as $l) {
	if (preg_match('#^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ){3}[0-9a-f]{2})\s+(l\\.[a-z]+)\s*(.*)$#', $l, $m)) {
		$addr = hexdec($m[1]);
		$insn = $m[3];
		$ops = $m[4];

		if (!$data->is_in_code_range($addr)) {
			continue;
		}

		$insns[$addr] = new insn($addr, $insn, $ops);
	} else {
		//echo "SKIP: $l\n";
	}
}

// process jump tables to identify bb edges
foreach ($jump_tables as $jt) {
	$jtaddr = to_phys_addr($jt[0]);
	foreach ($data->read_code_address_table($jtaddr) as $i => $addr) {
		$paddr = to_phys_addr($addr);

		$bblocks[$paddr] = true;
		if (!isset($jt_targets[$paddr]))
			$jt_targets[$paddr] = [];
		$jt_targets[$paddr][] = [to_addr_label($jtaddr), $i];
	}
}

// read string tables
$str_tables_map = [];
foreach ($str_tables as $st) {
	$str_tables_map[to_phys_addr($st)] = $data->read_string_table($st);
}

// identify bblocks and reorder delay slots
foreach ($insns as $k => $i)
{
	if ($i->name == 'l.jal')
		$fns[$i->operands->n] = true;

	switch ($i->name) {
		case "l.bf":
		case "l.bnf":
		case "l.j":
		case "l.jal":
			$bblocks[$i->operands->n] = true;
			if (!isset($xrefs[$paddr]))
				$xrefs[$paddr] = [];
			$xrefs[$i->operands->n][] = ($i->name == 'l.jal' ? 'call:' : 'jump:') . to_addr_label($i->addr);
		case "l.jalr":
		case "l.jr":
			if ($delayed)
				die("ERROR: double deylay\n");
			$delayed = $i;
			break;
		default:
			if ($i->name == 'l.nop' && $delayed)
				; // skip l.nop in delay slots
			else
				$new_insns[$i->addr] = $i;

			$i->no_start = false;
			if ($delayed) {
				$delayed->no_start = ($i->name == 'l.nop' && $delayed) ? false : true;

				$delay_slots[$i->addr] = true;
				$i->addr = $delayed->addr;
				$new_insns[$delayed->addr] = $delayed;
				$delayed = null;
			}

			break;
	}
}

// check that code doesn't jump to delay slots (sanity check)
foreach ($insns as $k => $i)
{
	switch ($i->name) {
		case "l.bf":
		case "l.bnf":
		case "l.j":
		case "l.jal":
			if (isset($delay_slots[$i->operands->n]))
				die("ERROR: jump to delay slot\n");
	}
}

// decompile
$sim = new cpu_state();
foreach ($new_insns as $i)
{
	if (!$i->no_start && isset($bblocks[$i->addr]))
		$sim->set_all_regs_unknown();

	if (!$i->no_start) {
		if (isset($bblocks[$i->addr]))
			echo "\n\n";

		if (isset($fns[$i->addr])) {
			echo "--------------------------------------------------------------\n\n\n";
		}

		if (isset($xrefs[$i->addr])) {
			echo '// xrefs from:';
			foreach ($xrefs[$i->addr] as $ref)
				echo " $ref";
			echo "\n";
		}

		if (isset($jt_targets[$i->addr])) {
			foreach ($jt_targets[$i->addr] as $t)
				echo "$t[0][$t[1]]:\n";
		}
	}

	if (to_addr_label($i->addr, true) != to_addr_label($i->addr))
		echo to_addr_label($i->addr) . ":\n";

	printf("%s:   %-90s // %s\n", to_addr_label($i->addr, true), $i->explain($sim), $i->orig);

	if ($i->name == 'l.j')
		$sim->set_all_regs_unknown();
}
