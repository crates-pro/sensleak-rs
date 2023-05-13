use std::error::Error;
use std::fs;
use std::path::{Path};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use clap::Parser;
use std::process;
use regex::Regex;
use crate::{Config, read_allowlist, is_file_in_whitelist, contains_keyword, is_path_in_allowlist,read_ruleslist};
/**
 * 接受参数，开始检测
 */
pub fn git_detector() {
    let args=Config::parse();
    if let Err(e) = detect(args) {
        eprintln!("Application error:{}", e);
        process::exit(0);
    }
}
/**
 * 检测
 */
pub fn detect(config: Config) -> Result<(), Box<dyn Error>> {
    let path = Path::new(&config.filepath);
    let allowlist_paths = read_allowlist(&config.ruleslist,&config.filepath); // 读取白名单
    if path.is_dir() {
        visit_dirs(path, &config, &allowlist_paths)?; // 对目录进行搜索
    } else if path.is_file() {
        if !is_file_in_whitelist(&path, &allowlist_paths) { // 如果文件在白名单中，忽略
            search_file(path, &config)?; // 对文件进行搜索
        }
    } else {
        eprintln!("{} is not a valid file or directory", path.display()); // 输入无效路径
    }

    Ok(())
}
/**
 * 递归检查文件夹中的文件
 */
fn visit_dirs(dir: &Path, config: &Config, allowlist_paths: &[String]) -> Result<(), Box<dyn Error>> {
    if dir.is_dir() {
        let entries: Vec<_> = fs::read_dir(dir)?.collect();
        entries.par_iter().for_each(|entry| {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Some(filename) = entry.file_name().to_str() {
                    //忽略以点号开头的文件或者文件夹
                    if filename.starts_with('.') {
                        return;
                    }
                    //忽略文件名或者文件夹名中包含波浪号的文件或者文件夹
                    if filename.contains('~') {
                        return;
                    }
                }
                if path.is_dir() {
                    if is_path_in_allowlist(&config.filepath,&path, allowlist_paths){
                        // 如果文件在白名单中，直接返回
                        return;
                    } else {
                        visit_dirs(&path, config, allowlist_paths).unwrap();
                    }
                    // visit_dirs(&path, config, allowlist_paths).unwrap();
                } else if path.is_file() {
                    if is_path_in_allowlist(&config.filepath,&path, allowlist_paths){
                        // 如果文件在白名单中，直接返回
                        return;
                    } else {
                        search_file(&path, config).unwrap();
                    }
                    
                }
            }
        });
    }
    Ok(())
}
/**
 * 输出（打印纸控制台上）
 */
#[derive(Debug, Serialize, Deserialize)]
struct OutputItem {
    finding: String,
    line_number: u32,
    secret: String,
    entropy:String,
    commit: String,
    repo: String,
    rule: String,
    commit_message: String,
    author: String,
    email: String,
    file: String,
    date: String,
    tags: String,
    operation: String,
}
/**
 * 检查内容
 */
fn search_file(path: &Path, config: &Config) -> Result<(), Box<dyn Error>> {

    let (regexlist,keywords) = read_ruleslist(&config.ruleslist);
    
    let contents = fs::read_to_string(&path)?;

    if !contains_keyword(&contents, &keywords) {
        // If the file contents do not contain any keywords, return early
        return Ok(());
    }
    for rule in &regexlist {
        let results = search_regex(&rule.regex, &contents);
        for (line_number, finding, matched) in results.iter() {
            let output_item = OutputItem {
                finding: finding.to_string(),
                line_number: *line_number as u32,
                secret: matched.to_string(),
                entropy:rule.entropy.map(|n| n.to_string()).unwrap_or_default(),
                commit: "".to_string(),
                repo: "".to_string(),
                rule: rule.description.to_string(),
                commit_message: "".to_string(),
                author: "".to_string(),
                email: "".to_string(),
                file: path.to_string_lossy().to_string(),
                date: "".to_string(),
                // tags: rule.keywords.join(","),
                tags:"".to_string(),
                operation: "".to_string(),
            };
            println!("{:#?}", output_item);
        }
    }
    Ok(())
}
/**
 * 正则表达式匹配
 */
pub fn search_regex<'a>(query: &str, contents: &'a str) -> Vec<(usize, &'a str, &'a str)> {
    // 创建正则表达式对象
    let regex = Regex::new(query).unwrap();

    // 迭代字符串中的行
    contents
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            // 对每一行进行正则匹配
            regex.captures(line)
                .and_then(|captures| captures.get(0))
                .map(|matched| (i + 1, line, matched.as_str()))
        })
        .collect()
}
