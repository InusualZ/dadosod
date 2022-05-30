use std::{path::PathBuf, fs::{File, OpenOptions}, io::{Read, Seek}};
use std::io::Write;
use argh::FromArgs;
use dol::DolHeaderData;

use crate::analysis::Analyser;

#[derive(Debug, PartialEq, FromArgs)]
#[argh(subcommand, name = "dol")]
/// disassembly operations for `.dol` Wii/GC executable file
pub struct DolCmd {
    /// path of the `.dol` Wii/GC executable file
    #[argh(positional)]
    dol_file_path: PathBuf,
}

// TODO: Handle error/result properly

impl DolCmd {
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Dadosods DOL\n");

        let mut dol_file = File::open(&self.dol_file_path).unwrap();
        let dol_header = DolHeaderData::read_from(&dol_file).unwrap();
        let text_sections_offset = &dol_header.section_offsets[0..7];
        let text_sections_target = &dol_header.section_targets[0..7];
        let text_sections_size = &dol_header.section_sizes[0..7];
        let text_sections_count = text_sections_size.iter().filter(|&&s| s > 0u32).count();

        // Analyse sections
        let mut analysis_data = Analyser::new(dol_header.entry_point);

        for i in 0..text_sections_count {

            // Read Section Data
            let section_size = text_sections_size[i] as usize;
            let mut section_data = vec![0u8; section_size];
            dol_file.seek(std::io::SeekFrom::Start(text_sections_offset[i] as u64)).unwrap();
            dol_file.read_exact(&mut section_data).unwrap();

            analysis_data.analyze_text_section(&dol_header, &section_data, text_sections_target[i]);
        }

        let dol_full_path = std::fs::canonicalize(&self.dol_file_path)?;
        let dol_file_name = dol_full_path.file_name().unwrap().to_string_lossy().to_string();
        let dol_parent_path = dol_full_path.parent().unwrap();

        let asm_path = dol_parent_path.join("asm");
        std::fs::create_dir_all(&asm_path)?;

        let macro_file_path = asm_path.join("macros.inc");
        {
            let mut macro_file = OpenOptions::new().write(true).truncate(true).create(true).open(&macro_file_path)?;
            self.write_macro_file(&mut macro_file, &dol_header, &analysis_data)?;
        }

        for i in 0..text_sections_count {
            let section_name = calculate_section_name(i, text_sections_count, false);
            let section_file_name = format!("{}.s", section_name.replace(".", ""));
            let section_file_path = asm_path.join(section_file_name);
            let mut section_file = OpenOptions::new().write(true).truncate(true).create(true).open(&section_file_path)?;
            let start = text_sections_target[i];
            let size = text_sections_size[i];
            let end = start + size;

            writeln!(section_file, ".include \"macros.inc\"\n")?;
            writeln!(section_file, ".section {}, \"ax\"  # 0x{:08X} - 0x{:08X} ; 0x{:08X}", section_name, start, end, size as u32)?;

            let mut section_data = vec![0u8; size as usize];
            dol_file.seek(std::io::SeekFrom::Start(text_sections_offset[i] as u64)).unwrap();
            dol_file.read_exact(&mut section_data).unwrap();
            analysis_data.write_text_section(&mut section_file, &section_data, start, text_sections_offset[i])?;
        }

        let data_sections_offset = &dol_header.section_offsets[7..];
        let data_sections_target = &dol_header.section_targets[7..];
        let data_sections_size = &dol_header.section_sizes[7..];
        let data_sections_count = data_sections_size.iter().filter(|&&s| s > 0u32).count();

        for i in 0..data_sections_count {
            let section_name = calculate_section_name(i, data_sections_count, true);
            let section_file_name = format!("{}.s", section_name.replace(".", ""));
            let section_file_path = asm_path.join(section_file_name);
            let mut section_file = OpenOptions::new().write(true).truncate(true).create(true).open(&section_file_path)?;
            let start = data_sections_target[i];
            let size = data_sections_size[i];
            let end = start + size;

            writeln!(section_file, ".include \"macros.inc\"\n")?;
            writeln!(section_file, ".section {}, \"wa\"  # 0x{:08X} - 0x{:08X} ; 0x{:08X}", section_name, start, end, size as u32)?;

            let mut section_data = vec![0u8; size as usize];
            dol_file.seek(std::io::SeekFrom::Start(data_sections_offset[i] as u64)).unwrap();
            dol_file.read_exact(&mut section_data).unwrap();
            analysis_data.write_data_section(&mut section_file, &section_data, start, data_sections_offset[i], &dol_file_name)?;
        }


        // Write .bss, .sbss, .sbss2 sections

        {
            let section_name = ".bss";
            let section_file_name = format!("{}.s", section_name.replace(".", ""));
            let section_file_path = asm_path.join(section_file_name);
            let mut section_file = OpenOptions::new().write(true).truncate(true).create(true).open(&section_file_path)?;
            let start = dol_header.bss_target;
            let size = dol_header.bss_size;
            let end = start + size;

            writeln!(section_file, ".include \"macros.inc\"\n")?;
            writeln!(section_file, ".section {}, \"wa\"  # 0x{:08X} - 0x{:08X} ; 0x{:08X}", section_name, start, end, size as u32)?;

            analysis_data.write_bss_section(&mut section_file, size, start)?;
        }

        Ok(())
    }

    fn write_macro_file<W>(&self, dst: &mut W, dol_header: &DolHeaderData, analysis_data: &Analyser) -> Result<(), Box<dyn std::error::Error>>
    where
        W: Write,
    {
        let text_sections_offset = &dol_header.section_offsets[0..7];
        let text_sections_target = &dol_header.section_targets[0..7];
        let text_sections_size = &dol_header.section_sizes[0..7];
        let text_sections_count = text_sections_size.iter().filter(|s| **s > 0u32).count();

        writeln!(dst, "/*")?;
        writeln!(dst, "Code sections:")?;
        for i in 0..text_sections_count {
            if text_sections_size[i] == 0 || text_sections_offset[i] == 0 || text_sections_target[i] == 0 {
                continue;
            }

            let section_name = calculate_section_name(i, text_sections_count, false);
            write!(dst, "\t{:<12}", section_name)?;
            writeln!(dst, "0x{:08X}  0x{:08X}  0x{:08X}", text_sections_offset[i], text_sections_target[i], 
                     text_sections_target[i] + text_sections_size[i])?;
        }

        let data_sections_offset = &dol_header.section_offsets[7..];
        let data_sections_target = &dol_header.section_targets[7..];
        let data_sections_size = &dol_header.section_sizes[7..];
        let data_sections_count = data_sections_size.iter().filter(|s| **s > 0u32).count();

        writeln!(dst, "Data sections:")?;
        for i in 0..data_sections_count {
            if data_sections_size[i] == 0 || data_sections_offset[i] == 0 || data_sections_target[i] == 0 {
                continue;
            }

            write!(dst, "\t{:<12}", calculate_section_name(i, data_sections_count, true))?;
            writeln!(dst, "0x{:08X}  0x{:08X}  0x{:08X}", data_sections_offset[i], data_sections_target[i], 
                     data_sections_target[i] + data_sections_size[i])?;
        }
        writeln!(dst, "BSS section:")?;
        writeln!(dst, "\t{:<12}0x{:08X}  0x{:08X}  0x{:08X}", ".bss", 0, dol_header.bss_target, dol_header.bss_target + dol_header.bss_size)?;
        writeln!(dst, "Entry Point: 0x{:08X}", dol_header.entry_point)?;
        writeln!(dst, "*/")?;

        // Write macros
        writeln!(dst, "# PowerPC Register Constants")?;
        for i in 0..32 {
            writeln!(dst, ".set r{}, {}", i, i)?;
        }

        for i in 0..32 {
            writeln!(dst, ".set f{}, {}", i, i)?; 
        }
        
        for i in 0..8 {
            writeln!(dst, ".set qr{}, {}", i, i)?;
        }

        if analysis_data.r13_addr != 0 {
            writeln!(dst, "# Small Data Area (read/write) Base")?;
            writeln!(dst, ".set _SDA_BASE_, 0x{:08X}", analysis_data.r13_addr)?;
        }
        if analysis_data.r2_addr != 0 {
            writeln!(dst, "# Small Data Area (read only) Base")?;
            writeln!(dst, ".set _SDA2_BASE_, 0x{:08X}", analysis_data.r2_addr)?;
        }

        writeln!(dst)?;

        Ok(())
    }

}

/// CodeWarrior/MetroWerks compiler emit a limited set of section so for 
/// most game we can infer them. **THIS IS NOT EXPECTED TO BE PERFECT**
fn calculate_section_name(index: usize, count: usize, is_data_section: bool) -> String {
    if is_data_section {
        let section_index_offset = match count {
            8 => 0, // extab,extabindex,.ctors,.dtors,.rodata,.data,.sdata,.sdata2
            7 => 0, // extab,extabindex,.ctors,.dtors,.rodata,.data,.sdata
            6 => 2, // .ctors,.dtors,.rodata,.data,.sdata,.sdata2
            5 => 2, // .ctors,.dtors,.rodata,.data,.sdata
            4 => 2, // .ctors,.dtors,.rodata,.data
            _ => usize::max_value()
        };

        if section_index_offset == usize::max_value() {
            return format!(".data{}", index);
        }

        match section_index_offset + index {
            0 => String::from("extab_"),
            1 => String::from("extabindex_"),
            2 => String::from(".ctors"),
            3 => String::from(".dtors"),
            4 => String::from(".rodata"),
            5 => String::from(".data"),
            6 => String::from(".sdata"),
            7 => String::from(".sdata2"),
            _ => unreachable!()
        }
    } else {
        match index {
            0 => String::from(".init"),
            1 => String::from(".text"),
            _ => format!(".text{}", index-1)
        }
    }
}