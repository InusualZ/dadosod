use std::io::Write as IoWrite;
use std::fmt::Write as FmtWrite;

use ppc750cl::{self, Ins, Opcode, Argument, formatter::FormattedIns};
use dol::DolHeaderData;

pub struct Analyser {
    pub r2_addr: u32,
    pub r13_addr: u32,
    pub labels: std::collections::BTreeSet<u32>,
    pub label_names: std::collections::BTreeMap<u32, String>,
    pub lis_insns: std::collections::HashMap<u32, Ins>,
    pub split_data_loads: std::collections::BTreeMap<u32, u32>,
    pub linked_insns: std::collections::HashMap<u32, Ins>
}

impl Analyser {
    pub fn new(entry_point: u32) -> Self {
        let mut data = Self {
            r2_addr: 0,
            r13_addr: 0,
            labels: Default::default(),
            label_names: Default::default(),
            lis_insns: Default::default(),
            split_data_loads: Default::default(),
            linked_insns: Default::default(),
        };

        // Add entry point
        data.labels.insert(entry_point.clone());
        data.label_names.insert(entry_point, "__start".into());

        data
    }

    pub fn analyze_text_section(&mut self, dol_header: &DolHeaderData, code: &[u8], code_address: u32) {
        for ins in ppc750cl::disasm_iter(code, code_address) {
            self.calculate_labels(&dol_header, &ins);
        }
    }

    fn calculate_labels(&mut self, dol_header: &DolHeaderData, ins: &Ins) {
 
        // Detect Branches
        if matches!(ins.op, Opcode::B | Opcode::Bc) {
            let branch_dest = ins.branch_dest().unwrap();
            self.lis_insns.clear();
    
            if is_addr_in_section(dol_header, branch_dest.clone()) {
                // Since at least is a branch into a known section treat it as a label
                self.labels.insert(branch_dest);

                // if is not a conditional branch, treat it as a function
                if ins.op == Opcode::B || ins.field_BO() == 20 {
                    self.add_label(branch_dest, format!("func_{:08X}", branch_dest))
                }
            }

            return;
        }
        
        if ins.op == Opcode::Addis && ins.field_rA() == 0 { // lis rD, 0x%%%
            // Record instruction that loads into register with 'lis'
            self.lis_insns.insert(ins.field_rD() as u32, ins.clone());
            return;
        } else if (ins.op == Opcode::Addi && ins.field_rA() != 0 && self.lis_insns.contains_key(&(ins.field_rA() as u32)) || 
                   (ins.op == Opcode::Ori && !(ins.field_rA() == 0 && ins.field_rS() == 0 && ins.field_uimm() == 0) && self.lis_insns.contains_key(&(ins.field_rS() as u32)))) || 
                  (is_load_store(ins) && self.lis_insns.contains_key(&(get_load_store_base_reg_uncheked(ins) as u32))) {
            // Detect split load (low part)
            // this is either 'addi/ori rY, rX, lopart' or 'load/store rY, lopart(rX)'
            let mut is_ori = false;
            let hi_load_reg = if is_load_store(ins) || ins.op == Opcode::Addi {
                get_load_store_base_reg_uncheked(ins)
            } else { // Opcode::Ori
                is_ori = true;
                ins.field_rS()
            } as u32;
    
            let hi_load_insn = &self.lis_insns[&hi_load_reg];
    
            // Compute combined value
            let address = combine_split_load_value(hi_load_insn, ins);
    
            if is_addr_in_section(dol_header, address) {
                self.labels.insert(address.clone());
                if !is_label_addr_in_ins_section(dol_header, address.clone(), ins.addr) {
                    self.label_names.insert(address.clone(), self.get_label_for(address.clone()));
                }
            }

            // Record linked instruction
            self.linked_insns.insert(hi_load_insn.addr.clone(), ins.clone());
            self.split_data_loads.insert(hi_load_insn.addr.clone(), address.clone());
            self.split_data_loads.insert(ins.addr.clone(), address.clone());
            self.lis_insns.remove(&hi_load_reg); // TODO: This is not necessary
    
            // detect r2/r13 initialization
            if is_ori && ins.field_rA() == ins.field_rS() {
                if self.r2_addr == 0 && ins.field_rA() == 2 {
                    self.r2_addr = address;
                } else if self.r13_addr == 0 && ins.field_rA() == 13 {
                    self.r13_addr = address;
                }
            }
        } else if !is_store_insn(ins) && !is_storef_insn(ins) {
            // Remove record if register is overwritten
            let simplified = ins.clone().simplified();
            if simplified.args.len() >= 1 {
                if let Argument::GPR(r) = &simplified.args[0] {
                    self.lis_insns.remove(&(r.0 as u32));
                }
            }
        }
    
        if ins.op == Opcode::Addi {
            let base_address = if ins.field_rA() == 13 && self.r13_addr != 0 {
                self.r13_addr
            } else if ins.field_rA() == 2 && self.r2_addr != 0 {
                self.r2_addr
            } else {
                return;
            };

            let offset = ins.field_simm() as i32;
            let address = if offset >= 0 {
                base_address.wrapping_add(offset as u32)
            } else {
                base_address.wrapping_sub((-offset) as u32)
            };

            if is_addr_in_section(dol_header, address) {
                self.labels.insert(address);
            }
        } else if let Some(rdest) = get_load_store_base_reg(&ins) {
            let base_address = if rdest == 13 && self.r13_addr != 0 {
                self.r13_addr
            } else if rdest == 2 && self.r2_addr != 0 {
                self.r2_addr
            } else {
                return;
            };

            let simplified = ins.clone().simplified();
            if simplified.args.len() >= 2 {
                if let Argument::Offset(o) = &simplified.args[1] {
                    let offset = o.0;
                    let address = if offset >= 0 {
                        base_address.wrapping_add(offset as u32)
                    } else {
                        base_address.wrapping_sub((offset as i32).abs() as u32)
                    };

                    if is_addr_in_section(dol_header, address) {
                        self.labels.insert(address);
                    }
                }
            }
        }
    }

    fn add_label(&mut self, addr: u32, name: String) {
        self.labels.insert(addr.clone());
        self.label_names.insert(addr, name);
    }

    pub fn write_text_section<W>(&self, dst: &mut W, code: &[u8], code_address: u32, file_offset: u32) -> Result<(), Box<dyn std::error::Error>>
    where
        W: IoWrite, 
    {
        for ins in ppc750cl::disasm_iter(code, code_address) {
            let ins_addr = ins.addr;
            let ins_offset = ins_addr - code_address;
            let ins_bytes = vec![code[(ins_offset + 0) as usize], code[(ins_offset + 1) as usize], 
                code[(ins_offset + 2) as usize], code[(ins_offset + 3) as usize]];

            if self.labels.contains(&ins_addr) {
                if self.label_names.contains_key(&ins_addr) {
                    writeln!(dst, "\n.global {}", self.get_label_for(ins_addr))?;
                }

                writeln!(dst, "{}:", self.get_label_for(ins_addr))?;
            }

            let prefix_comment = format!("/* {:08X} {:08X}  {:02X} {:02X} {:02X} {:02X} */", 
                ins_addr, file_offset + ins_offset, ins_bytes[0], ins_bytes[1], ins_bytes[2], ins_bytes[3]);

            let ins_str = if let Ok(s) = self.format_instruction(&ins) {
                s
            } else {
                format!("{}", FormattedIns(ins.clone()))
            };

            writeln!(dst, "{}\t{}", prefix_comment, ins_str)?;
        }

        Ok(())
    }

    fn format_instruction(&self, ins: &Ins) -> Result<String, Box<dyn std::error::Error>> {
        
        if ins.op == Opcode::Illegal {
            return Ok(if ins.code == 0 {
                // Most likely alignment bytes
                format!(".4byte 0x{:08X}", ins.code)
            } else {
                format!(".4byte 0x{:08X}  /* <ilegal> */", ins.code)
            });
        }

        // Special Case - Assembler doesn't handle the instruction mnemonic
        if ins.op == Opcode::Lmw && ins.field_rD() == 0 {
            return Ok(format!(".4byte 0x{:08X}  /* illegal {} */", ins.code, FormattedIns(ins.clone())))
        }

        // Special Case - Most likely data as instruction
        if ins.op == Opcode::Bc && !ins.field_AA() {
            if ins.field_BD() == 0 {
                return Ok(format!(".4byte 0x{:08X}  /* {} */", ins.code, FormattedIns(ins.clone())));
            }
        }

        let simple = ins.clone().simplified();
        let mut f = String::new();

        let is_addi = ins.op == Opcode::Addi;
        let is_ori = ins.op == Opcode::Ori;
        let is_sda_offset = (is_addi || is_load_store(ins)) && (ins.field_rA() == 2 || ins.field_rA() == 13);
        
        let offset_suffix =  if let Some(lo_load_ins) = self.linked_insns.get(&ins.addr) {
            if lo_load_ins.op == Opcode::Ori {
                "@h"
            } else {
                "@ha"
            }
        } else if is_sda_offset {
            "@sda21"
        } else if is_ori || is_addi || is_load_store(ins) {
            "@l"
        } else {
            ""
        };

        write!(f, "{}{}", simple.mnemonic, ins.suffix())?;
        let mut writing_offset = false;
        for (i, arg) in simple.args.iter().enumerate() {
            if i == 0 {
                write!(f, " ")?;
            }
            if i > 0 && !writing_offset {
                write!(f, ", ")?;
            }

            if let Argument::Offset(val) = arg {
                let address = if let Some(v) = self.split_data_loads.get(&ins.addr) {
                    format!("{}{}", self.get_label_for(*v), offset_suffix)
                } else if is_sda_offset {
                    let mut address = if ins.field_rA() == 2 {
                        self.r2_addr
                    } else {
                        self.r13_addr
                    };

                    if val.0 >= 0 {
                        address = address.wrapping_add(val.0 as u32);
                    } else {
                        address = address.wrapping_sub((val.0 as i32).abs() as u32);
                    }

                    if self.labels.contains(&address) {
                        format!("{}{}", self.get_label_for(address), offset_suffix)
                    } else {
                        format!("{}", val)
                    }
                } else {
                    format!("{}", val)
                };

                write!(f, "{}(", address)?;
                writing_offset = true;
                continue;
            } else if let Argument::Simm(val) = arg {
                let val = if let Some(v) = self.split_data_loads.get(&ins.addr) {
                    format!("{}{}", self.get_label_for(*v), offset_suffix)
                } else if is_sda_offset {
                    let mut address = if ins.field_rA() == 2 {
                        self.r2_addr
                    } else {
                        self.r13_addr
                    };

                    if val.0 >= 0 {
                        address = address.wrapping_add(val.0 as u32);
                    } else {
                        address = address.wrapping_sub((val.0 as i32).abs() as u32);
                    }

                    if self.labels.contains(&address) {
                        format!("{}{}", self.get_label_for(address), offset_suffix)
                    } else {
                        format!("{}", val)
                    }
                } else {
                    format!("{}", arg)
                };

                write!(f, "{}", val)?;
            } else if let Argument::Uimm(val) = arg {
                let val = if let Some(v) = self.split_data_loads.get(&ins.addr) {
                    format!("{}{}", self.get_label_for(*v), offset_suffix)
                } else if is_sda_offset {
                    let address = if ins.field_rA() == 2 {
                        self.r2_addr
                    } else {
                        self.r13_addr
                    } + (val.0 as u32);

                    if self.labels.contains(&address) {
                        format!("{}{}", self.get_label_for(address), offset_suffix)
                    } else {
                        format!("{}", val)
                    }
                } else {
                    format!("{}", arg)
                };

                write!(f, "{}", val)?;
            } else if let Argument::BranchDest(_) = arg {
                let branch_dest = ins.branch_dest().unwrap();
                let val = if self.labels.contains(&branch_dest) {
                    format!("{}", self.get_label_for(branch_dest))
                } else {
                    format!("{}", arg)
                };

                write!(f, "{}", val)?;
            } else {
                write!(f, "{}", arg)?;
            }

            if writing_offset {
                write!(f, ")")?;
                writing_offset = false;
            }
        }

        Ok(f)
    }

    fn get_label_for(&self, addr: u32) -> String {
        if self.labels.contains(&addr) {
            if let Some(lbl) = self.label_names.get(&addr) {
                lbl.clone()
            } else {
                format!("lbl_{:08X}", addr)
            }
        } else {
            format!("0x{:08X}", addr)
        }
    }

    pub fn write_data_section<W>(&self, dst: &mut W, data: &[u8], data_address: u32, file_offset: u32, dol_name: &String) -> Result<(), Box<dyn std::error::Error>>
    where
        W: IoWrite, 
    {
        let data_address_end = data_address + data.len() as u32;

        let mut section_label_index = 0usize;
        let section_labels: Vec<u32> = self.labels.iter().filter(|&&l| l >= data_address && l < data_address_end).cloned().collect();

        let mut offset = 0u32;
        while (offset as usize) < data.len() {
            let label_file_offset = file_offset + offset;

            let label_address = offset + data_address;
            let size = if let Some(&nearest_label) = section_labels.get(section_label_index) {
                if label_address == nearest_label {
                    // The address have a label
                    writeln!(dst, ".global {0}\n{0}:", self.get_label_for(label_address))?;
                    
                    // Find the next nearest label so we we can, calculate the size
                    section_label_index += 1;

                    if let Some(&next_nearest_label) = section_labels.get(section_label_index) {
                        assert!(next_nearest_label > label_address);
                        // Gap between labels
                        next_nearest_label - label_address
                    } else {
                        // Gap between the label and the end of the section
                        data_address_end - label_address
                    }
                } else {
                    // The address did not had a label, calculate the gap between labels
                    nearest_label - label_address
                }
            } else {
                (data.len() as u32) - offset
            };

            assert!(label_address + size <= data_address_end);

            writeln!(dst, "\t.incbin \"{}\", {:#X}, {:#X}", dol_name, label_file_offset, size)?;

            offset += size;
        }

        assert_eq!(offset, data.len() as u32);
        Ok(())
    }
    
    pub fn write_bss_section<W>(&self, dst: &mut W, section_size: u32, data_address: u32) -> Result<(), Box<dyn std::error::Error>>
    where
        W: IoWrite, 
    {
        let data_address_end = data_address + section_size;

        let mut section_label_index = 0usize;
        let section_labels: Vec<u32> = self.labels.iter().filter(|&&l| l >= data_address && l < data_address_end).cloned().collect();

        let mut offset = 0u32;
        while offset < section_size {
            let label_address = offset + data_address;
            let size = if let Some(&nearest_label) = section_labels.get(section_label_index) {
                if label_address == nearest_label {
                    // The address have a label
                    writeln!(dst, ".global {0}\n{0}:", self.get_label_for(label_address))?;
                    
                    // Find the next nearest label so we we can, calculate the size
                    section_label_index += 1;

                    if let Some(&next_nearest_label) = section_labels.get(section_label_index) {
                        assert!(next_nearest_label > label_address);
                        // Gap between labels
                        next_nearest_label - label_address
                    } else {
                        // Gap between the label and the end of the section
                        data_address_end - label_address
                    }
                } else {
                    // The address did not had a label, calculate the gap between labels
                    nearest_label - label_address
                }
            } else {
                section_size - offset
            };

            assert!(label_address + size <= data_address_end);

            writeln!(dst, "\t.skip {:#X}", size)?;

            offset += size;
        }

        assert_eq!(offset, section_size);

        Ok(())
    }

}

pub fn is_addr_in_section(dol: &DolHeaderData, addr: u32) -> bool {
    let section_offset = if addr & 3 == 0 {
        0 // If addr is multiple of 4, it could be a instruction
    } else {
        7 // else is a data address
    };

    // Check if it's inside on of the sections
    for i in section_offset..dol.section_sizes.len() {
        if addr >= dol.section_targets[i] && addr < dol.section_targets[i] + dol.section_sizes[i] {
            return true;
        }
    }

    // Check if it's inside the bss section
    return addr >= dol.bss_target && addr < dol.bss_target + dol.bss_size
}

// Check if label address belong to the same section than the instruction
pub fn is_label_addr_in_ins_section(dol: &DolHeaderData, label_addr: u32, ins_addr: u32) -> bool {
    for i in 0..dol.section_sizes.len() {
        let start = dol.section_targets[i];
        let size =  dol.section_sizes[i];
        if size == 0 {
            continue;
        }

        let end = dol.section_targets[i] + size;
        if label_addr >= start && label_addr < end {
            return ins_addr >= start && ins_addr < end;
        }
    }

    // We don't check the bss section, because even if the label belong to it, the ins cannot
    return false
}

pub fn is_load_insn(ins: &Ins) -> bool {
    matches!(ins.op, Opcode::Lbz | Opcode::Lbzu | Opcode::Lbzux | Opcode::Lbzx | Opcode::Lha | Opcode::Lhau | Opcode::Lhaux | Opcode::Lhax | Opcode::Lhbrx | Opcode::Lhz | Opcode::Lhzu | Opcode::Lhzux | Opcode::Lhzx | Opcode::Lmw | Opcode::Lwz | Opcode::Lwzu | Opcode::Lwzux | Opcode::Lwzx)
}

pub fn is_loadf_insn(ins: &Ins) -> bool {
    matches!(ins.op, Opcode::Lfd | Opcode::Lfdu | Opcode::Lfdux | Opcode::Lfdx | Opcode::Lfs | Opcode::Lfsu | Opcode::Lfsux | Opcode::Lfsx)
}

pub fn is_store_insn(ins: &Ins) -> bool {
    matches!(ins.op, Opcode::Stb | Opcode::Stbu | Opcode::Stbux | Opcode::Stbx | Opcode::Sth | Opcode::Sthbrx | Opcode::Sthu | Opcode::Sthux | Opcode::Sthx | Opcode::Stmw | Opcode::Stw | Opcode::Stwbrx | Opcode::Stwcx_ | Opcode::Stwu | Opcode::Stwux | Opcode::Stwx)
}

pub fn is_storef_insn(ins: &Ins) -> bool {
    matches!(ins.op, Opcode::Stfd | Opcode::Stfdu | Opcode::Stfdux | Opcode::Stfdx | Opcode::Stfiwx | Opcode::Stfs | Opcode::Stfsu | Opcode::Stfsux | Opcode::Stfsx)
}

// get load/store base register
pub fn get_load_store_base_reg(ins: &Ins) -> Option<usize> {
    if is_load_insn(&ins) || is_loadf_insn(&ins) || is_store_insn(&ins) || is_storef_insn(&ins) {
        Some(ins.field_rA())
    } else {
        None
    }
}

pub fn is_load_store(ins: &Ins) -> bool {
    return is_load_insn(&ins) || is_loadf_insn(&ins) || is_store_insn(&ins) || is_storef_insn(&ins);
}

pub fn get_load_store_base_reg_uncheked(ins: &Ins) -> usize {
    return ins.field_rA();
}

/// returns true if the instruction is a load or store with the given register as a base 
pub fn is_load_store_reg_offset(ins: &Ins, reg: Option<usize>) -> bool {
    if let Some(r_a) = get_load_store_base_reg(ins) {
        if let Some(r) = reg {
            return r_a == r;
        }

        return true;
    }

    return false;
}

/// Computes the combined value from a lis, addi/ori instruction pairr
pub fn combine_split_load_value(hi_load: &Ins, lo_load: &Ins) -> u32 {
    assert!(hi_load.op == Opcode::Addis && hi_load.field_rA() == 0); // Make sure the is `lis rX, 0x8000`
    let mut value = (hi_load.field_uimm() << 16) as u32;
    
    //loLoadInsn must be "addi rY, rX, loPart"
    if lo_load.op == Opcode::Ori {
        value |= lo_load.field_uimm() as u32;
    } else if lo_load.op == Opcode::Addi {
        let imm = lo_load.field_simm() as i32;
        if imm >= 0 {
            value = value.wrapping_add(imm as u32);
        } else {
            value = value.wrapping_sub(imm.unsigned_abs());
        }
    } else if is_load_store_reg_offset(lo_load, Some(hi_load.field_rD())) {
        let imm = lo_load.field_offset() as i32;
        if imm >= 0 {
            value = value.wrapping_add(imm as u32);
        } else {
            value = value.wrapping_sub(imm.unsigned_abs());
        }
    } else {
        unreachable!()
    }
    return value
}