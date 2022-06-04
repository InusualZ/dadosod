use std::{path::PathBuf, fs::{File, OpenOptions}};
use std::io::Write;
use argh::FromArgs;
use dol::{Dol, DolSectionType};

use crate::analysis::Analyser;

#[derive(Debug, PartialEq, FromArgs)]
#[argh(subcommand, name = "dol")]
/// disassembly operations for `.dol` Wii/GC executable file
pub struct DolCmd {
    /// path of the `.dol` Wii/GC executable file
    #[argh(positional)]
    dol_file_path: PathBuf,
}

impl DolCmd {
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Dadosods DOL\n");

        let dol_file = File::open(&self.dol_file_path)?;
        let dol_file = Dol::read_from(&dol_file)?;

        // Analyse sections
        let mut analysis_data = Analyser::new(dol_file.header.entry_point);

        for section in &dol_file.header.sections {
            if section.kind != DolSectionType::Text {
                continue;
            }

            // Read Section Data
            let section_data = dol_file.section_data(section);
            analysis_data.analyze_text_section(&dol_file, &section_data, section.target);
        }

        let dol_full_path = std::fs::canonicalize(&self.dol_file_path)?;
        let dol_file_name = dol_full_path.file_name().unwrap().to_string_lossy().to_string();
        let dol_parent_path = dol_full_path.parent().unwrap();

        let asm_path = dol_parent_path.join("asm");
        std::fs::create_dir_all(&asm_path)?;

        let macro_file_path = asm_path.join("macros.inc");
        {
            let mut macro_file = OpenOptions::new().write(true).truncate(true).create(true).open(&macro_file_path)?;
            self.write_macro_file(&mut macro_file, &dol_file, &analysis_data)?;
        }

        let text_sections_count = dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Text).count();
        for section in dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Text) {
            let section_name = calculate_section_name(section.index, text_sections_count, false);
            let section_file_name = format!("{}.s", section_name.replace(".", ""));
            let section_file_path = asm_path.join(section_file_name);
            let mut section_file = OpenOptions::new().write(true).truncate(true).create(true).open(&section_file_path)?;
            let start = section.target;
            let size = section.size;
            let end = start + size;

            writeln!(section_file, ".include \"macros.inc\"\n")?;
            writeln!(section_file, ".section {}, \"ax\"  # 0x{:08X} - 0x{:08X} ; 0x{:08X}", section_name, start, end, size as u32)?;

            let section_data = dol_file.section_data(section);
            analysis_data.write_text_section(&mut section_file, &section_data, start, section.offset)?;
        }

        let data_sections_count = dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Data).count();
        for section in dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Data) {
            let section_name = calculate_section_name(section.index - 7, data_sections_count, true);
            let section_file_name = format!("{}.s", section_name.replace(".", ""));
            let section_file_path = asm_path.join(section_file_name);
            let mut section_file = OpenOptions::new().write(true).truncate(true).create(true).open(&section_file_path)?;
            let start = section.target;
            let size = section.size;
            let end = start + size;

            writeln!(section_file, ".include \"macros.inc\"\n")?;
            writeln!(section_file, ".section {}, \"wa\"  # 0x{:08X} - 0x{:08X} ; 0x{:08X}", section_name, start, end, size as u32)?;

            let section_data = dol_file.section_data(section);
            analysis_data.write_data_section(&mut section_file, &section_data, start, section.offset, &dol_file_name)?;
        }


        // Write .bss, .sbss, .sbss2 sections
        let mut bss_index = 0;
        for section in dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Bss) {
            let section_name = if bss_index == 0 {
                ".bss".into()
            } else {
                format!(".bss{}", bss_index)
            };

            let section_file_name = format!("{}.s", section_name.replace(".", ""));
            let section_file_path = asm_path.join(section_file_name);
            let mut section_file = OpenOptions::new().write(true).truncate(true).create(true).open(&section_file_path)?;
            let start = section.target;
            let size = section.size;
            let end = start + size;

            writeln!(section_file, ".include \"macros.inc\"\n")?;
            writeln!(section_file, ".section {}, \"wa\"  # 0x{:08X} - 0x{:08X} ; 0x{:08X}", section_name, start, end, size as u32)?;

            analysis_data.write_bss_section(&mut section_file, size, start)?;

            bss_index += 1;
        }

        Ok(())
    }

    fn write_macro_file<W>(&self, dst: &mut W, dol_file: &Dol, analysis_data: &Analyser) -> Result<(), Box<dyn std::error::Error>>
    where
        W: Write,
    {
        writeln!(dst, "/*")?;
        writeln!(dst, "Code sections:")?;

        let text_sections_count = dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Text).count();
        for section in dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Text) {
            let section_name = calculate_section_name(section.index, text_sections_count, false);
            write!(dst, "\t{:<12}", section_name)?;
            writeln!(dst, "0x{:08X}  0x{:08X}  0x{:08X}", section.offset, section.target, 
            section.target + section.size)?;
        }

        writeln!(dst, "Data sections:")?;

        let data_sections_count = dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Data).count();
        for section in dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Data) {
            write!(dst, "\t{:<12}", calculate_section_name(section.index - 7, data_sections_count, true))?;
            writeln!(dst, "0x{:08X}  0x{:08X}  0x{:08X}", section.offset, section.target, 
            section.target + section.size)?;
        }

        writeln!(dst, "BSS section:")?;

        let mut bss_index = 0;
        for section in dol_file.header.sections.iter().filter(|s| s.kind == DolSectionType::Bss) {
            let section_name = if bss_index == 0 {
                ".bss".into()
            } else {
                format!(".bss{}", bss_index)
            };

            writeln!(dst, "\t{:<12}0x{:08X}  0x{:08X}  0x{:08X}", section_name, section.offset, section.target, section.target + section.size)?;
            bss_index += 1;
        }

        writeln!(dst, "Entry Point: 0x{:08X}", dol_file.header.entry_point)?;
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