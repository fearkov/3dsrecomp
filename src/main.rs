//! 3dsrecomp, a static recompiler for 3DS titles built on the Zakuro runtime.
//!
//! for now it only analyzes, finding how much of a title's code a generic
//! pass can discover on its own.

mod arm;
mod discover;
mod image;
mod thumb;

use discover::{Byte, Mode, Source};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(command), Some(path)) = (args.next(), args.next()) else {
        eprintln!("usage, 3dsrecomp analyze <rom>");
        std::process::exit(2);
    };
    if command != "analyze" {
        eprintln!("unknown command {command}");
        std::process::exit(2);
    }

    let title = match zakuro_fs::Title::load(&path) {
        Ok(title) => title,
        Err(error) => {
            eprintln!("could not load {path}, {error}");
            std::process::exit(1);
        }
    };
    let image = match image::Image::from_title(&title) {
        Ok(image) => image,
        Err(error) => {
            eprintln!("could not read the code, {error}");
            std::process::exit(1);
        }
    };

    let start = std::time::Instant::now();
    let analysis = discover::analyze(&image);
    let elapsed = start.elapsed();

    let text_size = image.text.bytes.len();
    let percent = |bytes: usize| bytes as f64 * 100.0 / text_size.max(1) as f64;
    let from = |source: Source| analysis.functions.values().filter(|f| f.source == source).count();
    let code = analysis.count(Byte::Code);
    let literal = analysis.count(Byte::Literal);
    let unknown = analysis.count(Byte::Unknown);

    println!("title        {}", title.exheader.title);
    println!("text         0x{:08X}, {} KiB", image.text.base, text_size / 1024);
    println!(
        "functions    {} ({} from calls, {} from pointers)",
        analysis.functions.len(),
        from(Source::Call),
        from(Source::Pointer)
    );
    let instructions: usize = analysis.functions.values().map(|f| f.instructions).sum();
    println!(
        "instructions {} decoded, {} per function on average",
        instructions,
        instructions / analysis.functions.len().max(1)
    );
    let thumb = analysis.functions.values().filter(|f| f.mode == Mode::Thumb).count();
    println!("modes        {} ARM, {} Thumb", analysis.functions.len() - thumb, thumb);
    println!("code         {:.1}% of text", percent(code));
    println!("literals     {:.1}% of text", percent(literal));
    println!("unreached    {:.1}% of text", percent(unknown));
    println!(
        "indirect     {} sites, {} switch tables, {} svc",
        analysis.indirect_sites, analysis.jump_tables, analysis.svc_sites
    );
    println!("dead ends    {} paths ran into something that cannot be code", analysis.dead_ends);
    println!("analysis     {elapsed:.2?}");
    println!("largest unreached runs");
    for (start, length) in analysis.largest_gaps(image.text.base, 8) {
        println!("  0x{start:08X}  {length} bytes");
    }
}
