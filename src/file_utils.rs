use std::fs;
use std::path::{Path, PathBuf};
use toml::Value;
use std::fs::File;
use std::io::prelude::*;


/**
 * 获取白名单列表
 */
pub fn read_allowlist(file_path: &str, _file_header: &str) -> Vec<String> {
    let toml_str = fs::read_to_string(file_path).expect("Failed to read whitelist.toml");
    let whitelist: Value = toml::from_str(&toml_str).expect("Failed to parse whitelist.toml");

    let mut paths = vec![];
    if let Some(file_list) = whitelist.get("allowlist").and_then(|v| v.get("paths").and_then(|v| v.as_array())) {
        for path in file_list.iter() {
            let path_str = path.as_str().unwrap().to_string();
            // let abs_path = format!("{}\\{}", file_header, path_str);
            paths.push(path_str);
        }
    }
 
    paths
}
/**
 * 确定该路径是否白名单中的路径
 */
pub fn is_file_in_whitelist(path: &Path, whitelist_paths: &[String]) -> bool {
    whitelist_paths.iter().any(|whitelist_path| {
        let abs_whitelist_path = Path::new(whitelist_path).canonicalize().unwrap();
        let abs_path = path.canonicalize().unwrap();
        abs_whitelist_path == abs_path
    })
}
/**
 * 用来比较是不是同一条路径
 */
pub fn is_path_in_allowlist(file_head: &str, path: &Path, whitelist_paths: &[String]) -> bool {
    let newallow = add_file_head_to_paths(file_head, &whitelist_paths);
    for whitelist_path in newallow {
        if check_string(&whitelist_path) {
            if check_string(&path.to_string_lossy()) {
                return true;
            } else {
                continue;
            }
        } else {
            let canon_path1 = PathBuf::from(whitelist_path).canonicalize();
            let canon_path2 = path.canonicalize();
            match (canon_path1, canon_path2) {
                (Ok(canon_path1), Ok(canon_path2)) => {
                    if canon_path1 == canon_path2 {
                        return true;
                    }
                },
                _ => continue,
            }
        }
    }
    false
}

/**
 * 对于配置文件中读到的白名单路径进行处理
 * 如果是路径，就加上路径前缀，得到绝对路径
 * 如果是正则表达式，直接加入
 */
fn add_file_head_to_paths(file_head: &str, whitelist_paths: &[String]) -> Vec<String> {
    let mut whitelisted_paths_with_head: Vec<String> = Vec::new();

    for path in whitelist_paths {
        if check_string(&path) {
            whitelisted_paths_with_head.push(path.clone());
        } else {
            whitelisted_paths_with_head.push(format!("{}\\{}", file_head, path));
        }
    }

    whitelisted_paths_with_head
}
/**
 * 根据配置工具的正则表达式规范
 * 检查是不是正则表达式
 */
fn check_string(s: &str) -> bool {
    s.starts_with("(") && s.ends_with("$")
}

/**
 * 检查内容是否含有关键字
 */
pub fn contains_keyword(contents: &str, keywords: &[String]) -> bool {
    for keyword in keywords {
        if contents.contains(keyword) {
            return true;
        }
    }
    false
}
/**
 * 正则表达式
 */
#[derive(Debug)]
pub struct Rule {
    pub description: String,
    pub id: String,
    pub regex: String,
    pub entropy: Option<f64>, 
    pub keywords: Vec<String>,
}

/**
 * 获取正则表达式
 */

pub fn read_ruleslist(filename: &str) -> (Vec<Rule>, Vec<String>) {
    // 打开文件并读取内容
    let mut file = File::open(filename).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    // 将TOML内容解析为Value类型
    let value = contents.parse::<Value>().unwrap();

    // 获取rules数组
    let rules_array = value.get("rules").unwrap().as_array().unwrap();

    // 遍历rules数组并创建Rule结构体实例
    let mut rules = vec![];
    let mut keywords = vec![];
    for rule in rules_array {
        let description = rule.get("description").unwrap().as_str().unwrap().to_string();
        let id = rule.get("id").unwrap().as_str().unwrap().to_string();
        let regex = rule.get("regex").unwrap().as_str().unwrap().to_string();
        let entropy = rule.get("entropy").map(|e| e.as_float().unwrap()); // new field
        let keywords_array = rule.get("keywords").unwrap().as_array().unwrap();
        for keyword in keywords_array {
            let keyword_str = keyword.as_str().unwrap().to_string();
            keywords.push(keyword_str); // 将关键词加入到Vec中
        }
        let rule = Rule {
            description,
            id,
            regex,
            entropy,
            keywords: keywords_array.iter().map(|kw| kw.as_str().unwrap().to_string()).collect(),
        };
        rules.push(rule);
    }

    // 返回解析后的rules数组和keywords数组
    (rules, keywords)
}
