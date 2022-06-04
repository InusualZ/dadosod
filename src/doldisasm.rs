use std::{path::{PathBuf, Path}, fs::{File, OpenOptions}, collections::BTreeMap};
use std::io::Write;
use argh::FromArgs;
use dol::{Dol, DolSectionType, DolSection};

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
        let dol_file = File::open(&self.dol_file_path)?;
        let mut dol_file = Dol::read_from(&dol_file)?;

        // Try giving each section a name
        let section_name_map = calculate_section_names(&mut dol_file);
        assert_eq!(section_name_map.len(), dol_file.header.sections.len());

        println!("Sections:");
        for (si, section) in dol_file.header.sections.iter().enumerate() {
            let section_name = section_name_map.get(&si).unwrap();
            println!("[{:2}] => {:<12} 0x{:08X} 0x{:08X} 0x{:08X} 0x{:08X}", si, section_name, 
            section.offset, section.target, section.target + section.size, section.size);
        }

        // Analyse sections
        let mut analysis_data = Analyser::new(dol_file.header.entry_point);

        for section in &dol_file.header.sections {
            if section.kind != DolSectionType::Text {
                continue;
            }

            let section_data = dol_file.section_data(section);
            analysis_data.analyze_text_section(&dol_file, &section_data, section.target);
        }

        let dol_full_path = std::fs::canonicalize(&self.dol_file_path)?;
        let dol_file_name = dol_full_path.file_name().unwrap().to_string_lossy().to_string();
        let dol_parent_path = dol_full_path.parent().unwrap();

        let asm_path = dol_parent_path.join("asm");
        std::fs::create_dir_all(&asm_path)?;

        let include_path = dol_parent_path.join("include");
        std::fs::create_dir_all(&include_path)?;

        let macro_file_path = include_path.join("macros.inc");
        {
            let mut macro_file = create_file(&macro_file_path)?;
            self.write_macro_file(&mut macro_file, &dol_file, &section_name_map, &analysis_data)?;
        }

        for (si, section) in dol_file.header.sections.iter().enumerate() {
            let section_name = section_name_map.get(&si).unwrap();
            let section_file_name = format!("{}.s", section_name.replace(".", ""));
            let section_file_path = asm_path.join(section_file_name);
            let mut section_file = create_file(&section_file_path)?;
            let start = section.target;
            let size = section.size;
            let end = start + size;

            let section_type: String = match section.kind {
                DolSectionType::Text => "\"ax\"".into(),
                DolSectionType::Data => "\"wa\"".into(),
                DolSectionType::Bss => "\"\", @nobits".into(),
            };

            writeln!(section_file, ".include \"macros.inc\"\n")?;
            writeln!(section_file, ".section {}, {}  # 0x{:08X} - 0x{:08X} ; 0x{:08X}\n", section_name, section_type, start, end, size as u32)?;

            let section_data = dol_file.section_data(section);

            match section.kind {
                DolSectionType::Text => analysis_data.write_text_section(&mut section_file, &section_data, start, section.offset)?,
                DolSectionType::Data => analysis_data.write_data_section(&mut section_file, &section_data, start, section.offset, &dol_file_name)?,
                DolSectionType::Bss => analysis_data.write_bss_section(&mut section_file, size, start)?,
            }
        }

        Ok(())
    }

    fn write_macro_file<W>(&self, dst: &mut W, dol_file: &Dol, section_name_map: &BTreeMap<usize, String>, analysis_data: &Analyser) -> Result<(), Box<dyn std::error::Error>>
    where
        W: Write,
    {
        writeln!(dst, "/*")?;
        writeln!(dst, "Sections:")?;

        for (si, section) in dol_file.header.sections.iter().enumerate() {
            let section_name = section_name_map.get(&si).unwrap();
            write!(dst, "\t{:<12}", section_name)?;
            writeln!(dst, "0x{:08X}  0x{:08X}  0x{:08X}  0x{:08X}", section.offset, section.target, 
            section.target + section.size, section.size)?;
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
fn calculate_section_names(dol_file: &mut Dol) -> BTreeMap<usize, String> {
    let mut names_map: BTreeMap<usize, String> = Default::default();

    let sections = &mut dol_file.header.sections;

    // In any case, Use a dummy name for the text sections
    let mut bss_counter = 0usize;
    {
        let mut text_counter = 0usize;
        let mut data_counter = 0usize;
        for (si, section) in sections.iter().enumerate() {
            match section.kind {
                DolSectionType::Text => {
                    names_map.insert(si, format!(".text{}", text_counter));
                    text_counter += 1;
                },
                DolSectionType::Data => {
                    names_map.insert(si, format!(".data{}", data_counter));
                    data_counter += 1;
                },
                DolSectionType::Bss => {
                    assert_eq!(bss_counter, 0);
                    names_map.insert(si, ".bss".into());
                    bss_counter += 1;
                },
            }
        }
    }
    
    assert_eq!(bss_counter, 1);
    let bss_section_index = sections.iter().position(|s| s.kind == DolSectionType::Bss).unwrap();

    let section_after_bss_count = sections.iter().skip(bss_section_index + 1).count();

    if section_after_bss_count == 2 {
        // The Wii/GC SDK generate a little bit of content for the `.sdata` and `.sdata2` section
        // So, there should always be atleast does two section

        // How are we calculating the `.sbss` and `.sbss2` section?
        // The CodeWarrior/Metrowerks compiler order the `.sbss` and `.sbss2` like so:
        //     .bss
        //     .sdata
        //     .sbss
        //     .sdata2
        //     .sbss2 (optional)
        // The things is that this section are unified into a singular section and that
        // unified section's size is calculated like so:
        //     unified_bss_size = last_bss_section_rom_end - bss_rom
        // With this information we can divide the dol's bss section back into his original form

        let sdata_section_index = bss_section_index + 1;
        let mut sdata2_section_index = bss_section_index + 2;
        let sdata_section = &sections[sdata_section_index];
        let sdata2_section = &sections[sdata2_section_index];

        let bss_section = &sections[bss_section_index];
        let bss_section_rom_end = bss_section.target + bss_section.size;
        let sdata2_rom_end = sdata2_section.target + sdata2_section.size;

        // Set the sdata section name
        names_map.insert(sdata_section_index, ".sdata".into());

        // Calculate sbss section
        let sdata_rom_end = sdata_section.target + sdata_section.size;
        let sbss_size = sdata2_section.target - sdata_rom_end;
        if sbss_size > 0 {
            // Insert .sbss section name
            names_map.insert(sdata2_section_index, ".sbss".into());

            // We are going to introduce a new section to the dol, so we have to give the sdata2 section a new index
            sdata2_section_index += 1;

            // Insert newly discover section
            let sbss_target = sdata_rom_end;
            sections.insert(sdata_section_index + 1, DolSection { 
                kind: DolSectionType::Bss, 
                index: 0,
                offset: 0,
                target: sbss_target,
                size: sbss_size 
            });
        }

        // Insert sdata2 section name
        names_map.insert(sdata2_section_index, ".sdata2".into());

        // Calculate sbss2 size
        let sbss2_size = bss_section_rom_end - sdata2_rom_end;
        if sbss2_size > 0 {
            // Insert `.sbss2` section name
            names_map.insert(sdata2_section_index + 1, ".sbss2".into());

            // Insert newly discover section
            let sbss2_target = bss_section_rom_end - sbss2_size;
            sections.push(DolSection { 
                kind: DolSectionType::Bss, 
                index: 0,
                offset: 0,
                target: sbss2_target,
                size: sbss2_size 
            });
        }
    } else {
        println!("WARNING! Unexpected number `{}` of section were found after the `.bss` section", section_after_bss_count);
    }

    // Set the correct size to the bss size
    if section_after_bss_count >= 1 {
        // Since the bss "section" given by the dol is simply the size of the range created by the 
        // elf's bss section start address and the end address of the last bss (NOBITS) section,
        // we can calculate the real size, by substracting the next section's start address and the bss
        // section target address

        let bss_section = &sections[bss_section_index];
        let section_after = &sections[bss_section_index + 1];
        let bss_size = section_after.target - bss_section.target;

        let bss_section = &mut sections[bss_section_index];
        bss_section.size = bss_size;
    }

    let mut last_text_section_index = 0;

    // How many text section? We are only expecting `.init`
    let text_section_count = sections.iter().filter(|s| s.kind == DolSectionType::Text).count();
    if text_section_count == 2 {
        let init_section_index = 0usize;

        // The CodeWarrior/MetroWerk compiler emit the text section like so:
        //     [0] .init (required)
        //     [1] .extab (optional)
        //     [2] .extabindex (optional)
        //     [3] .text (required)

        let text_section_index = if sections[init_section_index + 1].kind == DolSectionType::Text {
            init_section_index + 1
        } else {
            init_section_index + 3
        };

        last_text_section_index = text_section_index;

        let text_section = &sections[text_section_index];
        if text_section.kind == DolSectionType::Text {
            names_map.insert(init_section_index, ".init".into());
            names_map.insert(text_section_index, ".text".into());

            // How many section between the `.init` and `.text` section
            if text_section_index - init_section_index - 1 == 2 {
                // Make sure that the two section in-between are data section
                if sections.iter().skip(init_section_index + 1).take(2).filter(|s| s.kind == DolSectionType::Data).count() == 2 {
                    // Mark them as `extab` and `extabindex`
                    // We have to add a `_`, because if manually linking those data section
                    // the linker would throw error because does section are suppose to be auto-generated
                    names_map.insert(init_section_index + 1, "extab_".into());
                    names_map.insert(init_section_index + 2, "extabindex_".into());
                } else {
                    println!("WARNING! Unknown section type was found between the two expected data section");
                }
            }
        } else {
            println!("WARNING! Unknown Section ({:?}, {:#X}, 0x{:08X}, {:#X})", text_section.kind, text_section.offset, text_section.target, text_section.size);
        }
    } else {
        println!("WARNING! Too many text section were found `{}`", text_section_count);
        for section in sections.iter().enumerate() {
            if section.1.kind == DolSectionType::Text {
                last_text_section_index = section.0;
            }
        }
    }

    // CodeWarrior/MetroWerks compiler emit the remaining .data section like so:
    //     .text (last_text_section_index)
    //     .ctors
    //     .dtors
    //     .file (only seen in ogws)
    //     .rodata
    //     .data
    //     .bss (bss_section_index)

    let data_section_count = bss_section_index - last_text_section_index - 1;
    if data_section_count == 5 {
        names_map.insert(last_text_section_index + 1, ".ctors".into());
        names_map.insert(last_text_section_index + 2, ".dtors".into());
        names_map.insert(last_text_section_index + 3, ".file".into());
        names_map.insert(last_text_section_index + 4, ".rodata".into());
        names_map.insert(last_text_section_index + 5, ".data".into());
    } else if data_section_count == 4 {
        names_map.insert(last_text_section_index + 1, ".ctors".into());
        names_map.insert(last_text_section_index + 2, ".dtors".into());
        names_map.insert(last_text_section_index + 3, ".rodata".into());
        names_map.insert(last_text_section_index + 4, ".data".into());
    } else {
        println!("WARNING! Unknown data section count `{}` were found between the `.text` and `.bss` section", data_section_count);
    }


    return names_map;
}

#[inline]
fn create_file<P>(path: P) -> std::io::Result<File>
where
    P: AsRef<Path> 
{
    OpenOptions::new().write(true).truncate(true).create(true).open(&path)
}
