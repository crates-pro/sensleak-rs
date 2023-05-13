/**
 * 配置命令行参数
 */
use clap::Parser;


#[derive(Parser, Debug)]
#[command(author="cyj", version="0.1.0", about="", long_about = "A tool to detect sensitive information in Git repository")]
pub struct Config {
    //TODO: 修改为Git仓库路径
    ///The path to the target file
    #[arg(short, long)]
    pub filepath: String,
    
    /// he path to the rules file
    #[arg(short, long)]
    pub ruleslist: String,
}
