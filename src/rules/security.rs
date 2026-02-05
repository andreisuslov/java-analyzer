//! Security-related rules

use super::*;

pub fn create_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(S2068HardcodedCredentials),
        Box::new(S2076CommandInjection),
        Box::new(S2078LdapInjection),
        Box::new(S2083PathInjection),
        Box::new(S2089HttpOnlyCookie),
        Box::new(S2091XPathInjection),
        Box::new(S2092CookieSecureFlag),
        Box::new(S2095ResourceLeak),
        Box::new(S2115DatabasePassword),
        Box::new(S2245PseudoRandomGenerator),
        Box::new(S2255CookieWriting),
        Box::new(S2257CustomCrypto),
        Box::new(S2277RsaPadding),
        Box::new(S2278WeakDes),
        Box::new(S2386MutableStaticField),
        Box::new(S2631RegexDos),
        Box::new(S2647BasicAuth),
        Box::new(S2658DynamicClassLoading),
        Box::new(S2755XxeVulnerability),
        Box::new(S2976TempFileCreation),
        Box::new(S3329IvReuse),
        Box::new(S3330CookieDomain),
        Box::new(S3649SqlInjection),
        Box::new(S4423WeakSslProtocol),
        Box::new(S4426CryptoKeySize),
        Box::new(S4433LdapAuth),
        Box::new(S4434UncheckedDeserialize),
        Box::new(S4502DisabledCsrf),
        Box::new(S4507DebugFeatures),
        Box::new(S4684SpringEntity),
        Box::new(S4790WeakHashing),
        Box::new(S4818SocketUsage),
        Box::new(S4823CommandLine),
        Box::new(S4829StdinUsage),
        Box::new(S4830TrustManager),
        Box::new(S4834PermissionCheck),
        Box::new(S5042ExpansionInjection),
        Box::new(S5122CorsConfig),
        Box::new(S5131XssVulnerability),
        Box::new(S5144OpenRedirect),
        Box::new(S5145LogInjection),
        Box::new(S5146HttpResponseSplitting),
        Box::new(S5167HttpRequestForward),
        Box::new(S5247SqlFormatter),
        Box::new(S5261RegexCompile),
        Box::new(S5322IntentReceiving),
        Box::new(S5324ExternalStorage),
        Box::new(S5332ClearTextProtocol),
        Box::new(S5344PasswordHash),
        Box::new(S5361RegexReplace),
        Box::new(S5443FilePermissions),
        Box::new(S5445InsecureTempFile),
        Box::new(S5527ServerCertificate),
        Box::new(S5542EncryptionAlgorithm),
        Box::new(S5547CipherBlockMode),
        Box::new(S5659JwtSignature),
        Box::new(S5689HttpResponseHeaders),
        Box::new(S5808AuthorizationCheck),
        Box::new(S5852RegexComplexity),
        Box::new(S5869CharacterClassRedundancy),
        Box::new(S6096ZipSlip),
        Box::new(S6287RegexReplace2),
        Box::new(S6293RegexComplex),
        Box::new(S6362FileWrites),
        // Batch 5 - additional security rules
        Box::new(S2069UnsafePassword),
        Box::new(S2070WeakHash),
        Box::new(S2071InsecureSession),
        Box::new(S2072DataExposure),
        Box::new(S2073InsecureFileOp),
        Box::new(S2074InsecureRedirect),
        Box::new(S2075InsecureUrl),
        Box::new(S2077SqlQuery),
        Box::new(S2079Xss),
        Box::new(S2080InsecureXml),
        Box::new(S2081InsecureDeserial),
        Box::new(S2082InsecureCors),
        Box::new(S2084InsecureContent),
        Box::new(S2085InsecureCookie),
        Box::new(S2086InsecureAuth),
        Box::new(S2087InsecureRandom),
        Box::new(S2088HardcodedKey),
        Box::new(S2090WeakTls),
        Box::new(S2093InsecureUpload),
        Box::new(S2098InsecureKeystore),
        Box::new(S2099WeakCipher),
        Box::new(S2100InsecureTrust),
        Box::new(S2101DebugSensitive),
        Box::new(S2102InsecureTmpDir),
        Box::new(S2103InsecurePerm),
        Box::new(S2104InsecureReflect),
        Box::new(S2105InsecureNative),
        Box::new(S2106InsecureSysProp),
        Box::new(S2108InsecureRegex),
        Box::new(S2112InsecureObject),
        Box::new(S2113InsecureBean),
        Box::new(S2117InsecureEntropy),
        Box::new(S2124InsecureXmlBind),
        Box::new(S2125InsecureJson),
        Box::new(S2126InsecureYaml),
        Box::new(S2132InsecurePerm),
        Box::new(S2135InsecureSsl),
        Box::new(S2136InsecureHostname),
        Box::new(S2137InsecureKeyGen),
        Box::new(S2138InsecureCert),
        Box::new(S2139InsecureEncMode),
        Box::new(S2140InsecureIv),
        // Batch 6 - additional security rules
        Box::new(S2141InsecureMac),
        Box::new(S2142InsecureSig),
        Box::new(S2143InsecureKeyAgree),
        Box::new(S2144HardcodedConnPwd),
        Box::new(S2145InsecureProtocol),
        Box::new(S2146MissingValidation),
        Box::new(S2147InsecureRedirect),
        Box::new(S2148InsecureEmail),
        Box::new(S2149InsecureLdapAuth),
        Box::new(S2150InsecureStorage),
        Box::new(S2151NullAuth),
        Box::new(S2152MissingAccess),
        Box::new(S2153HttpsEnforce),
        Box::new(S2154WeakSession),
        Box::new(S2155MissingCsrf),
        Box::new(S2156InsecureJwt),
        Box::new(S2157MissingHeaders),
        Box::new(S2158InsecureIdor),
        Box::new(S2159MissingEncrypt),
        Box::new(S2160InsecureAdmin),
        Box::new(S2161MissingRateLimit),
        Box::new(S2162InsecureApiKey),
        Box::new(S2163MissingAudit),
        Box::new(S2164InsecureDownload),
        Box::new(S2165MissingAuth),
        Box::new(S2166InsecureDefault),
        Box::new(S2167MissingLength),
        Box::new(S2168InsecureError),
        Box::new(S2169MissingFileType),
        Box::new(S2170InsecureSessionId),
    ]
}

// S2068: Credentials should not be hard-coded
pub struct S2068HardcodedCredentials;
impl Rule for S2068HardcodedCredentials {
    fn id(&self) -> &str { "S2068" }
    fn title(&self) -> &str { "Credentials should not be hard-coded" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn owasp(&self) -> Option<OwaspCategory> { Some(OwaspCategory::A07AuthenticationFailures) }
    fn cwe(&self) -> Option<u32> { Some(798) } // CWE-798: Use of Hard-coded Credentials
    fn debt_minutes(&self) -> u32 { 30 }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CRED_PATTERN: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)(password|passwd|pwd|secret|apikey|api_key|token|credential|auth_token|access_token|private_key)\s*=\s*"[^"]{4,}""#).unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if CRED_PATTERN.is_match(line) && !line.trim().starts_with("//") && !line.contains("\"\"") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Hard-coded credential detected. Use secure credential storage.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2076: OS commands should not be vulnerable to injection attacks
pub struct S2076CommandInjection;
impl Rule for S2076CommandInjection {
    fn id(&self) -> &str { "S2076" }
    fn title(&self) -> &str { "OS commands should not be vulnerable to injection attacks" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RUNTIME_EXEC: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(").unwrap()
        });
        static PROCESS_BUILDER: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"ProcessBuilder\s*\(").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if RUNTIME_EXEC.is_match(line) || PROCESS_BUILDER.is_match(line) {
                // Check if it uses string concatenation (potential injection)
                if line.contains("+") || line.contains("concat") {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Potential command injection vulnerability. Validate and sanitize input.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2078: LDAP queries should not be vulnerable to injection attacks
pub struct S2078LdapInjection;
impl Rule for S2078LdapInjection {
    fn id(&self) -> &str { "S2078" }
    fn title(&self) -> &str { "LDAP queries should not be vulnerable to injection attacks" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static LDAP_SEARCH: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\.(search|lookup)\s*\([^)]*\+").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if (line.contains("DirContext") || line.contains("LdapContext")) && LDAP_SEARCH.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Potential LDAP injection vulnerability. Use parameterized queries.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2083: I/O function calls should not be vulnerable to path injection attacks
pub struct S2083PathInjection;
impl Rule for S2083PathInjection {
    fn id(&self) -> &str { "S2083" }
    fn title(&self) -> &str { "I/O function calls should not be vulnerable to path injection" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static FILE_OPS: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"new\s+(File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\([^)]*\+").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if FILE_OPS.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Potential path injection vulnerability. Validate and canonicalize paths.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2089: HTTP response headers should not be vulnerable to injection attacks
pub struct S2089HttpOnlyCookie;
impl Rule for S2089HttpOnlyCookie {
    fn id(&self) -> &str { "S2089" }
    fn title(&self) -> &str { "Cookies should have HttpOnly flag set" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static COOKIE_NEW: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"new\s+Cookie\s*\(").unwrap()
        });
        let mut issues = Vec::new();
        let lines: Vec<&str> = ctx.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if COOKIE_NEW.is_match(line) {
                // Look for setHttpOnly in nearby lines
                let mut found_http_only = false;
                for i in line_num.saturating_sub(5)..=(line_num + 10).min(lines.len() - 1) {
                    if lines[i].contains("setHttpOnly(true)") {
                        found_http_only = true;
                        break;
                    }
                }
                if !found_http_only {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Set HttpOnly flag on cookie to prevent XSS attacks.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2092: Cookies should be "secure"
pub struct S2092CookieSecureFlag;
impl Rule for S2092CookieSecureFlag {
    fn id(&self) -> &str { "S2092" }
    fn title(&self) -> &str { "Cookies should have Secure flag set" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static COOKIE_NEW: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"new\s+Cookie\s*\(").unwrap()
        });
        let mut issues = Vec::new();
        let lines: Vec<&str> = ctx.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if COOKIE_NEW.is_match(line) {
                let mut found_secure = false;
                for i in line_num.saturating_sub(5)..=(line_num + 10).min(lines.len() - 1) {
                    if lines[i].contains("setSecure(true)") {
                        found_secure = true;
                        break;
                    }
                }
                if !found_secure {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Set Secure flag on cookie to ensure HTTPS transmission.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2095: Resources should be closed
pub struct S2095ResourceLeak;
impl Rule for S2095ResourceLeak {
    fn id(&self) -> &str { "S2095" }
    fn title(&self) -> &str { "Resources should be closed" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static RESOURCE_TYPES: &[&str] = &[
            "FileInputStream", "FileOutputStream", "BufferedReader", "BufferedWriter",
            "FileReader", "FileWriter", "Connection", "Statement", "ResultSet",
            "InputStream", "OutputStream", "Scanner", "Socket", "ServerSocket",
            "DataInputStream", "DataOutputStream", "ObjectInputStream", "ObjectOutputStream",
        ];
        static TRY_WITH: Lazy<Regex> = Lazy::new(|| Regex::new(r"try\s*\(").unwrap());

        let mut issues = Vec::new();
        let lines: Vec<&str> = ctx.source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for resource_type in RESOURCE_TYPES {
                if line.contains(&format!("new {}", resource_type)) {
                    // Check if within try-with-resources
                    let mut in_try_with = false;
                    for i in (0..=line_num).rev().take(10) {
                        if TRY_WITH.is_match(lines[i]) {
                            in_try_with = true;
                            break;
                        }
                        if lines[i].contains('{') && !lines[i].contains("try") {
                            break;
                        }
                    }
                    if !in_try_with {
                        issues.push(create_issue(
                            self,
                            ctx.file_path,
                            line_num + 1,
                            1,
                            format!("Use try-with-resources to ensure {} is closed", resource_type),
                            Some(line.trim().to_string()),
                        ));
                        break;
                    }
                }
            }
        }
        issues
    }
}

// S2245: Using pseudorandom number generators is security-sensitive
pub struct S2245PseudoRandomGenerator;
impl Rule for S2245PseudoRandomGenerator {
    fn id(&self) -> &str { "S2245" }
    fn title(&self) -> &str { "Secure random generators should be used for security" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static WEAK_RANDOM: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"new\s+Random\s*\(|Math\s*\.\s*random\s*\(").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if WEAK_RANDOM.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use SecureRandom instead of Random for security-sensitive operations.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2255: Writing cookies is security-sensitive
pub struct S2255CookieWriting;
impl Rule for S2255CookieWriting {
    fn id(&self) -> &str { "S2255" }
    fn title(&self) -> &str { "Writing cookies is security-sensitive" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static COOKIE_ADD: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\.addCookie\s*\(").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if COOKIE_ADD.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Ensure cookie is properly secured with HttpOnly and Secure flags.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S2257: Custom cryptographic algorithm should not be used
pub struct S2257CustomCrypto;
impl Rule for S2257CustomCrypto {
    fn id(&self) -> &str { "S2257" }
    fn title(&self) -> &str { "Custom cryptographic algorithms should not be used" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Look for classes that extend cryptographic classes
        if ctx.source.contains("extends MessageDigest") ||
           ctx.source.contains("extends Cipher") ||
           ctx.source.contains("implements Cipher") {
            issues.push(create_issue(
                self,
                ctx.file_path,
                1,
                1,
                "Do not implement custom cryptographic algorithms. Use standard library implementations.".to_string(),
                None,
            ));
        }
        issues
    }
}

// S2386: Mutable fields should not be "public static"
pub struct S2386MutableStaticField;
impl Rule for S2386MutableStaticField {
    fn id(&self) -> &str { "S2386" }
    fn title(&self) -> &str { "Mutable fields should not be public static" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static MUTABLE_STATIC: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"public\s+static\s+(\w+(\[\]|<[^>]+>)?)\s+\w+").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if MUTABLE_STATIC.is_match(line) && !line.contains("final") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Make this field private or final to prevent modification.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S3329: Cipher initialization vectors should be unpredictable
pub struct S3329IvReuse;
impl Rule for S3329IvReuse {
    fn id(&self) -> &str { "S3329" }
    fn title(&self) -> &str { "Cipher IVs should be unpredictable" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static IV_PATTERN: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"IvParameterSpec\s*\(\s*new\s+byte\s*\[").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if IV_PATTERN.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use SecureRandom to generate unpredictable IVs.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S3649: Database queries should not be vulnerable to injection attacks
pub struct S3649SqlInjection;
impl Rule for S3649SqlInjection {
    fn id(&self) -> &str { "S3649" }
    fn title(&self) -> &str { "Database queries should not be vulnerable to injection" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn owasp(&self) -> Option<OwaspCategory> { Some(OwaspCategory::A03Injection) }
    fn cwe(&self) -> Option<u32> { Some(89) } // CWE-89: SQL Injection
    fn debt_minutes(&self) -> u32 { 45 }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static SQL_CONCAT: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(executeQuery|executeUpdate|execute|prepareStatement)\s*\([^)]*\+"#).unwrap()
        });
        static SQL_LITERAL: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"".*?(SELECT|INSERT|UPDATE|DELETE|WHERE).*?"\s*\+"#).unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if SQL_CONCAT.is_match(line) || SQL_LITERAL.is_match(&line.to_uppercase()) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "SQL injection vulnerability. Use PreparedStatement with parameters.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S4426: Cryptographic keys should be robust
pub struct S4426CryptoKeySize;
impl Rule for S4426CryptoKeySize {
    fn id(&self) -> &str { "S4426" }
    fn title(&self) -> &str { "Cryptographic keys should be robust" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static WEAK_KEY: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\.init\s*\(\s*(512|768|1024)\s*\)").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if WEAK_KEY.is_match(line) && line.contains("KeyGenerator") || line.contains("KeyPairGenerator") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use a key size of at least 2048 bits for RSA or 256 bits for AES.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S4502: Disabling CSRF protections is security-sensitive
pub struct S4502DisabledCsrf;
impl Rule for S4502DisabledCsrf {
    fn id(&self) -> &str { "S4502" }
    fn title(&self) -> &str { "CSRF protections should not be disabled" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CSRF_DISABLE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if CSRF_DISABLE.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Do not disable CSRF protection.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S4790: Using weak hashing algorithms is security-sensitive
pub struct S4790WeakHashing;
impl Rule for S4790WeakHashing {
    fn id(&self) -> &str { "S4790" }
    fn title(&self) -> &str { "Weak hashing algorithms should not be used" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn owasp(&self) -> Option<OwaspCategory> { Some(OwaspCategory::A02CryptographicFailures) }
    fn cwe(&self) -> Option<u32> { Some(328) } // CWE-328: Reversible One-Way Hash
    fn debt_minutes(&self) -> u32 { 20 }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static WEAK_HASH: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"MessageDigest\s*\.\s*getInstance\s*\(\s*"(MD5|SHA-?1|SHA1)"\s*\)"#).unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if WEAK_HASH.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Use SHA-256 or stronger hashing algorithm.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5131: XSS attacks should be prevented
pub struct S5131XssVulnerability;
impl Rule for S5131XssVulnerability {
    fn id(&self) -> &str { "S5131" }
    fn title(&self) -> &str { "XSS attacks should be prevented" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PRINT_WRITER: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"getWriter\s*\(\s*\)\s*\.\s*(print|println|write)\s*\([^)]*\+").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if PRINT_WRITER.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Potential XSS vulnerability. Escape user input before output.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5144: Open redirects should be prevented
pub struct S5144OpenRedirect;
impl Rule for S5144OpenRedirect {
    fn id(&self) -> &str { "S5144" }
    fn title(&self) -> &str { "Open redirects should be prevented" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static REDIRECT: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\.sendRedirect\s*\([^)]*\+|\.sendRedirect\s*\(\s*\w+\s*\)").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if REDIRECT.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Validate redirect URLs to prevent open redirect attacks.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5146: HTTP response headers should not be vulnerable to injection attacks
pub struct S5146HttpResponseSplitting;
impl Rule for S5146HttpResponseSplitting {
    fn id(&self) -> &str { "S5146" }
    fn title(&self) -> &str { "HTTP response headers should not be vulnerable to injection" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static HEADER_SET: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\.(setHeader|addHeader)\s*\([^,]+,\s*[^)]*\+").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if HEADER_SET.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Sanitize header values to prevent HTTP response splitting.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5322: Receiving intents is security-sensitive
pub struct S5322IntentReceiving;
impl Rule for S5322IntentReceiving {
    fn id(&self) -> &str { "S5322" }
    fn title(&self) -> &str { "Receiving intents is security-sensitive" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();

        if ctx.source.contains("extends BroadcastReceiver") {
            issues.push(create_issue(
                self,
                ctx.file_path,
                1,
                1,
                "Ensure broadcast receiver properly validates incoming intents.".to_string(),
                None,
            ));
        }
        issues
    }
}

// S5324: Using external storage is security-sensitive
pub struct S5324ExternalStorage;
impl Rule for S5324ExternalStorage {
    fn id(&self) -> &str { "S5324" }
    fn title(&self) -> &str { "Using external storage is security-sensitive" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static EXT_STORAGE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"getExternalFilesDir|getExternalStorageDirectory").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if EXT_STORAGE.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "External storage is world-readable. Don't store sensitive data there.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5527: Server certificates should be verified
pub struct S5527ServerCertificate;
impl Rule for S5527ServerCertificate {
    fn id(&self) -> &str { "S5527" }
    fn title(&self) -> &str { "Server certificates should be verified" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static TRUST_ALL: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"TrustAllCerts|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if TRUST_ALL.is_match(line) || line.contains("ALLOW_ALL_HOSTNAME_VERIFIER") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Do not disable SSL certificate verification.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5542: Encryption algorithms should be used with secure mode and padding
pub struct S5542EncryptionAlgorithm;
impl Rule for S5542EncryptionAlgorithm {
    fn id(&self) -> &str { "S5542" }
    fn title(&self) -> &str { "Encryption should use secure mode and padding" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static WEAK_CIPHER: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"Cipher\s*\.\s*getInstance\s*\(\s*"(DES|DESede|RC2|RC4|Blowfish|AES)"\s*\)"#).unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if WEAK_CIPHER.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Specify cipher mode and padding (e.g., AES/GCM/NoPadding).".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5547: Cipher algorithms should be robust
pub struct S5547CipherBlockMode;
impl Rule for S5547CipherBlockMode {
    fn id(&self) -> &str { "S5547" }
    fn title(&self) -> &str { "Cipher block mode should be robust" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static ECB_MODE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"Cipher\s*\.\s*getInstance\s*\(\s*"[^"]*ECB[^"]*"\s*\)"#).unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if ECB_MODE.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Do not use ECB mode. Use GCM or CBC with HMAC instead.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5659: JWT should be signed and verified
pub struct S5659JwtSignature;
impl Rule for S5659JwtSignature {
    fn id(&self) -> &str { "S5659" }
    fn title(&self) -> &str { "JWT should be signed and verified" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static JWT_NONE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"\.signWith\s*\(\s*SignatureAlgorithm\s*\.\s*NONE"#).unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if JWT_NONE.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "JWT should be signed with a strong algorithm like RS256 or HS256.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5689: Disclosing information through HTTP response headers
pub struct S5689HttpResponseHeaders;
impl Rule for S5689HttpResponseHeaders {
    fn id(&self) -> &str { "S5689" }
    fn title(&self) -> &str { "Sensitive info should not be disclosed in HTTP headers" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static SERVER_HEADER: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"setHeader\s*\(\s*"Server""#).unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if SERVER_HEADER.is_match(line) || line.contains("X-Powered-By") {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Remove server version information from HTTP headers.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S5808: Authorizing requests should be security-sensitive
pub struct S5808AuthorizationCheck;
impl Rule for S5808AuthorizationCheck {
    fn id(&self) -> &str { "S5808" }
    fn title(&self) -> &str { "Authorization checks should be performed" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static PERMIT_ALL: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\.permitAll\s*\(\s*\)").unwrap()
        });
        let mut issues = Vec::new();

        for (line_num, line) in ctx.source.lines().enumerate() {
            if PERMIT_ALL.is_match(line) {
                issues.push(create_issue(
                    self,
                    ctx.file_path,
                    line_num + 1,
                    1,
                    "Ensure permitAll() is only used for truly public endpoints.".to_string(),
                    Some(line.trim().to_string()),
                ));
            }
        }
        issues
    }
}

// S6096: Extracting archives should be secure
pub struct S6096ZipSlip;
impl Rule for S6096ZipSlip {
    fn id(&self) -> &str { "S6096" }
    fn title(&self) -> &str { "Archive extraction should be secure (Zip Slip)" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }

    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static ZIP_ENTRY: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"ZipEntry|ZipInputStream|TarArchiveEntry").unwrap()
        });
        let mut issues = Vec::new();

        if ZIP_ENTRY.is_match(ctx.source) && !ctx.source.contains("normalize") && !ctx.source.contains("getCanonicalPath") {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("getName()") && line.contains("File") {
                    issues.push(create_issue(
                        self,
                        ctx.file_path,
                        line_num + 1,
                        1,
                        "Validate archive entry paths to prevent Zip Slip attacks.".to_string(),
                        Some(line.trim().to_string()),
                    ));
                }
            }
        }
        issues
    }
}

// S2091: XPath expressions should not be vulnerable to injection attacks
pub struct S2091XPathInjection;
impl Rule for S2091XPathInjection {
    fn id(&self) -> &str { "S2091" }
    fn title(&self) -> &str { "XPath expressions should not be vulnerable to injection" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static XPATH: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.evaluate\s*\([^)]*\+").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("XPath") && XPATH.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Potential XPath injection. Use parameterized XPath expressions.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S2115: A secure password should be used when connecting to a database
pub struct S2115DatabasePassword;
impl Rule for S2115DatabasePassword {
    fn id(&self) -> &str { "S2115" }
    fn title(&self) -> &str { "Database connections should use secure passwords" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static EMPTY_PASS: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"getConnection\s*\([^)]*,\s*""\s*\)"#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if EMPTY_PASS.is_match(line) || (line.contains("getConnection") && line.contains("null")) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Database connection should use a secure password.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S2277: RSA algorithms should incorporate OAEP padding
pub struct S2277RsaPadding;
impl Rule for S2277RsaPadding {
    fn id(&self) -> &str { "S2277" }
    fn title(&self) -> &str { "RSA should use OAEP padding" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static WEAK_RSA: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"Cipher\.getInstance\s*\(\s*"RSA(?:/ECB)?(?:/PKCS1Padding)?"\s*\)"#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if WEAK_RSA.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use RSA with OAEP padding (RSA/ECB/OAEPWithSHA-256AndMGF1Padding).".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S2278: Neither DES nor 3DES should be used
pub struct S2278WeakDes;
impl Rule for S2278WeakDes {
    fn id(&self) -> &str { "S2278" }
    fn title(&self) -> &str { "DES and 3DES should not be used" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static DES_CIPHER: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"Cipher\.getInstance\s*\(\s*"(DES|DESede)"#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if DES_CIPHER.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use AES instead of DES or 3DES.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S2631: Regular expressions should not be vulnerable to Denial of Service
pub struct S2631RegexDos;
impl Rule for S2631RegexDos {
    fn id(&self) -> &str { "S2631" }
    fn title(&self) -> &str { "Regex should not be vulnerable to ReDoS" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static NESTED_QUANTIFIER: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"Pattern\.compile\s*\(\s*"[^"]*\([^)]*[+*]\)[+*]"#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if NESTED_QUANTIFIER.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "This regex may be vulnerable to ReDoS attacks.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S2647: Basic authentication should not be used
pub struct S2647BasicAuth;
impl Rule for S2647BasicAuth {
    fn id(&self) -> &str { "S2647" }
    fn title(&self) -> &str { "Basic authentication should not be used" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("httpBasic()") || line.contains("BasicAuth") || line.contains("Authorization: Basic") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use OAuth2 or token-based authentication instead of Basic auth.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S2658: Classes should not be loaded dynamically
pub struct S2658DynamicClassLoading;
impl Rule for S2658DynamicClassLoading {
    fn id(&self) -> &str { "S2658" }
    fn title(&self) -> &str { "Classes should not be loaded dynamically" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CLASS_LOAD: Lazy<Regex> = Lazy::new(||
            Regex::new(r"Class\.forName\s*\([^)]*\+|\.loadClass\s*\([^)]*\+").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if CLASS_LOAD.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Dynamic class loading can lead to code injection.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S2755: XML parsers should not be vulnerable to XXE attacks
pub struct S2755XxeVulnerability;
impl Rule for S2755XxeVulnerability {
    fn id(&self) -> &str { "S2755" }
    fn title(&self) -> &str { "XML parsers should not be vulnerable to XXE" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let has_xml_parser = ctx.source.contains("DocumentBuilder") ||
                            ctx.source.contains("SAXParser") ||
                            ctx.source.contains("XMLReader");
        let has_protection = ctx.source.contains("FEATURE_SECURE_PROCESSING") ||
                            ctx.source.contains("setFeature") ||
                            ctx.source.contains("disallow-doctype-decl");
        if has_xml_parser && !has_protection {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("newDocumentBuilder") || line.contains("newSAXParser") {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Enable secure processing to prevent XXE attacks.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S2976: File.createTempFile should not be used to create a directory
pub struct S2976TempFileCreation;
impl Rule for S2976TempFileCreation {
    fn id(&self) -> &str { "S2976" }
    fn title(&self) -> &str { "Use Files.createTempDirectory for temp directories" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("createTempFile") && line.contains("mkdir") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use Files.createTempDirectory() instead.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S3330: HttpOnly cookie attribute should be set
pub struct S3330CookieDomain;
impl Rule for S3330CookieDomain {
    fn id(&self) -> &str { "S3330" }
    fn title(&self) -> &str { "Cookie domain should be properly set" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static COOKIE_DOMAIN: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"\.setDomain\s*\(\s*"\."#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if COOKIE_DOMAIN.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Cookie domain starting with '.' allows subdomains access.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S4423: Weak SSL/TLS protocols should not be used
pub struct S4423WeakSslProtocol;
impl Rule for S4423WeakSslProtocol {
    fn id(&self) -> &str { "S4423" }
    fn title(&self) -> &str { "Weak SSL/TLS protocols should not be used" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static WEAK_SSL: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"SSLContext\.getInstance\s*\(\s*"(SSL|TLSv1|TLSv1\.0|TLSv1\.1)""#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if WEAK_SSL.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use TLSv1.2 or TLSv1.3 for secure connections.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S4433: LDAP connections should be authenticated
pub struct S4433LdapAuth;
impl Rule for S4433LdapAuth {
    fn id(&self) -> &str { "S4433" }
    fn title(&self) -> &str { "LDAP connections should be authenticated" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("SECURITY_AUTHENTICATION") && line.contains("none") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "LDAP connections should use authentication.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S4434: Deserializing data should be done with caution
pub struct S4434UncheckedDeserialize;
impl Rule for S4434UncheckedDeserialize {
    fn id(&self) -> &str { "S4434" }
    fn title(&self) -> &str { "Deserialization should be done safely" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static DESERIALIZE: Lazy<Regex> = Lazy::new(||
            Regex::new(r"ObjectInputStream|XMLDecoder|readObject\s*\(").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if DESERIALIZE.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Deserializing untrusted data can lead to RCE.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S4507: Debug features should be deactivated
pub struct S4507DebugFeatures;
impl Rule for S4507DebugFeatures {
    fn id(&self) -> &str { "S4507" }
    fn title(&self) -> &str { "Debug features should be deactivated" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("setWebContentsDebuggingEnabled(true)") ||
               line.contains("android:debuggable=\"true\"") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Disable debug features in production.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S4684: Spring entities should not be used for storage
pub struct S4684SpringEntity;
impl Rule for S4684SpringEntity {
    fn id(&self) -> &str { "S4684" }
    fn title(&self) -> &str { "Persistent entities should not be used directly" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        if ctx.source.contains("@Entity") && ctx.source.contains("@RequestBody") {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("@RequestBody") && !line.contains("DTO") {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Use DTOs instead of entities in request/response.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S4818: Using sockets is security-sensitive
pub struct S4818SocketUsage;
impl Rule for S4818SocketUsage {
    fn id(&self) -> &str { "S4818" }
    fn title(&self) -> &str { "Socket usage is security-sensitive" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static SOCKET: Lazy<Regex> = Lazy::new(||
            Regex::new(r"new\s+(Socket|ServerSocket|DatagramSocket)\s*\(").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if SOCKET.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Ensure socket communications are encrypted and validated.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S4823: Using command line arguments is security-sensitive
pub struct S4823CommandLine;
impl Rule for S4823CommandLine {
    fn id(&self) -> &str { "S4823" }
    fn title(&self) -> &str { "Command line args should be validated" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("args[") && !line.contains("validate") && !line.contains("check") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Validate command line arguments before use.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S4829: Reading standard input is security-sensitive
pub struct S4829StdinUsage;
impl Rule for S4829StdinUsage {
    fn id(&self) -> &str { "S4829" }
    fn title(&self) -> &str { "Standard input should be validated" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("System.in") || line.contains("new Scanner(System.in)") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Validate and sanitize standard input data.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S4830: Server certificates should be verified
pub struct S4830TrustManager;
impl Rule for S4830TrustManager {
    fn id(&self) -> &str { "S4830" }
    fn title(&self) -> &str { "TrustManager should verify certificates" }
    fn severity(&self) -> Severity { Severity::Blocker }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        if ctx.source.contains("X509TrustManager") {
            for (line_num, line) in ctx.source.lines().enumerate() {
                if line.contains("checkServerTrusted") && line.contains("{}") {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "TrustManager must verify server certificates.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S4834: Permission check should be done
pub struct S4834PermissionCheck;
impl Rule for S4834PermissionCheck {
    fn id(&self) -> &str { "S4834" }
    fn title(&self) -> &str { "Permissions should be checked" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("SecurityManager") && line.contains("null") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Security manager should not be bypassed.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5042: Expanding archive files is security-sensitive
pub struct S5042ExpansionInjection;
impl Rule for S5042ExpansionInjection {
    fn id(&self) -> &str { "S5042" }
    fn title(&self) -> &str { "Archive expansion limits should be set" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        if ctx.source.contains("ZipInputStream") || ctx.source.contains("GZIPInputStream") {
            let has_limit = ctx.source.contains("limit") || ctx.source.contains("MAX_") || ctx.source.contains("threshold");
            if !has_limit {
                for (line_num, line) in ctx.source.lines().enumerate() {
                    if line.contains("ZipInputStream") || line.contains("GZIPInputStream") {
                        issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                            "Set size limits when extracting archives (zip bomb protection).".to_string(),
                            Some(line.trim().to_string())));
                    }
                }
            }
        }
        issues
    }
}

// S5122: CORS should be properly configured
pub struct S5122CorsConfig;
impl Rule for S5122CorsConfig {
    fn id(&self) -> &str { "S5122" }
    fn title(&self) -> &str { "CORS should be properly configured" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CORS_ALL: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"addAllowedOrigin\s*\(\s*"\*"\s*\)|allowedOrigins\s*\(\s*"\*"\s*\)"#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if CORS_ALL.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Do not allow all origins in CORS configuration.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5145: Log injection should be prevented
pub struct S5145LogInjection;
impl Rule for S5145LogInjection {
    fn id(&self) -> &str { "S5145" }
    fn title(&self) -> &str { "Log injection should be prevented" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static LOG_CONCAT: Lazy<Regex> = Lazy::new(||
            Regex::new(r"(log|logger|LOG|LOGGER)\.(info|debug|warn|error|trace)\s*\([^)]*\+").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if LOG_CONCAT.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Sanitize user input before logging to prevent log injection.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5167: HTTP request forwarding should be safe
pub struct S5167HttpRequestForward;
impl Rule for S5167HttpRequestForward {
    fn id(&self) -> &str { "S5167" }
    fn title(&self) -> &str { "HTTP request forwarding should be safe" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static FORWARD: Lazy<Regex> = Lazy::new(||
            Regex::new(r"\.forward\s*\([^)]*\+|getRequestDispatcher\s*\([^)]*\+").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if FORWARD.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Validate request forward paths to prevent unauthorized access.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5247: Using SQL query formatters is security-sensitive
pub struct S5247SqlFormatter;
impl Rule for S5247SqlFormatter {
    fn id(&self) -> &str { "S5247" }
    fn title(&self) -> &str { "SQL formatters should be avoided" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static SQL_FORMAT: Lazy<Regex> = Lazy::new(||
            Regex::new(r"String\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)").unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if SQL_FORMAT.is_match(&line.to_uppercase()) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use PreparedStatement instead of String formatting for SQL.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5261: Regex should be compiled once
pub struct S5261RegexCompile;
impl Rule for S5261RegexCompile {
    fn id(&self) -> &str { "S5261" }
    fn title(&self) -> &str { "Regex patterns should be compiled once" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static INLINE_REGEX: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"\.matches\s*\(\s*"[^"]+"\s*\)|\.split\s*\(\s*"[^"]+"\s*\)"#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if INLINE_REGEX.is_match(line) && (line.contains("for") || line.contains("while")) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Compile regex pattern once outside the loop for performance.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5332: Clear-text protocols should not be used
pub struct S5332ClearTextProtocol;
impl Rule for S5332ClearTextProtocol {
    fn id(&self) -> &str { "S5332" }
    fn title(&self) -> &str { "Clear-text protocols should not be used" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static CLEAR_TEXT: Lazy<Regex> = Lazy::new(||
            Regex::new(r#""(http|ftp|telnet|smtp)://[^"]+""#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if CLEAR_TEXT.is_match(line) && !line.contains("localhost") && !line.contains("127.0.0.1") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use encrypted protocols (HTTPS, FTPS, etc.).".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5344: Password hash functions should use appropriate settings
pub struct S5344PasswordHash;
impl Rule for S5344PasswordHash {
    fn id(&self) -> &str { "S5344" }
    fn title(&self) -> &str { "Password hashing should use proper settings" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("BCrypt") || line.contains("PBKDF2") || line.contains("Argon2") {
                if line.contains("cost") || line.contains("iterations") {
                    let cost_match = Regex::new(r"cost\s*[=:]\s*(\d+)").ok()
                        .and_then(|re| re.captures(line))
                        .and_then(|cap| cap.get(1))
                        .and_then(|m| m.as_str().parse::<i32>().ok());
                    if let Some(cost) = cost_match {
                        if cost < 10 {
                            issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                                "Use a cost factor of at least 10 for BCrypt.".to_string(),
                                Some(line.trim().to_string())));
                        }
                    }
                }
            }
        }
        issues
    }
}

// S5361: String.replace should not be called with regex
pub struct S5361RegexReplace;
impl Rule for S5361RegexReplace {
    fn id(&self) -> &str { "S5361" }
    fn title(&self) -> &str { "replaceAll should use literal replacement" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static REPLACE_ALL: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"\.replaceAll\s*\(\s*"[^"]*[^\\][.+*?^$\[\]{}|()]"#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains(".replaceAll(") && !line.contains("Pattern") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use replace() for literal strings, replaceAll() uses regex.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5443: POSIX file permissions should be used
pub struct S5443FilePermissions;
impl Rule for S5443FilePermissions {
    fn id(&self) -> &str { "S5443" }
    fn title(&self) -> &str { "File permissions should be restricted" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("setReadable(true, false)") ||
               line.contains("setWritable(true, false)") ||
               line.contains("setExecutable(true, false)") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Restrict file permissions to owner only.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5445: Insecure temporary file creation
pub struct S5445InsecureTempFile;
impl Rule for S5445InsecureTempFile {
    fn id(&self) -> &str { "S5445" }
    fn title(&self) -> &str { "Temp files should be created securely" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("File.createTempFile") && !ctx.source.contains("deleteOnExit") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Temp files should be deleted after use (call deleteOnExit()).".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5852: Regex complexity should be limited
pub struct S5852RegexComplexity;
impl Rule for S5852RegexComplexity {
    fn id(&self) -> &str { "S5852" }
    fn title(&self) -> &str { "Regex complexity should be limited" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        static COMPLEX_REGEX: Lazy<Regex> = Lazy::new(||
            Regex::new(r#"Pattern\.compile\s*\(\s*"[^"]{100,}""#).unwrap());
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if COMPLEX_REGEX.is_match(line) {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "This regex is too complex. Consider simplifying.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S5869: Character class redundancy
pub struct S5869CharacterClassRedundancy;
impl Rule for S5869CharacterClassRedundancy {
    fn id(&self) -> &str { "S5869" }
    fn title(&self) -> &str { "Character classes should not have redundancy" }
    fn severity(&self) -> Severity { Severity::Minor }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("[0-9a-zA-Z]") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Use \\w instead of [0-9a-zA-Z_].".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S6287: Regular expressions should not cause stack overflow
pub struct S6287RegexReplace2;
impl Rule for S6287RegexReplace2 {
    fn id(&self) -> &str { "S6287" }
    fn title(&self) -> &str { "Regex should not cause stack overflow" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("(.*)") || line.contains("(.+)") {
                if line.contains("Pattern.compile") {
                    issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                        "Greedy quantifiers on . can cause stack overflow.".to_string(),
                        Some(line.trim().to_string())));
                }
            }
        }
        issues
    }
}

// S6293: Regular expression should not be too complex
pub struct S6293RegexComplex;
impl Rule for S6293RegexComplex {
    fn id(&self) -> &str { "S6293" }
    fn title(&self) -> &str { "Regex should not be overly complex" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            let quantifier_count = line.matches('+').count() + line.matches('*').count() + line.matches('?').count();
            if line.contains("Pattern.compile") && quantifier_count > 5 {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "This regex has too many quantifiers. Consider simplifying.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// S6362: Files should be written safely
pub struct S6362FileWrites;
impl Rule for S6362FileWrites {
    fn id(&self) -> &str { "S6362" }
    fn title(&self) -> &str { "File writes should be safe" }
    fn severity(&self) -> Severity { Severity::Major }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in ctx.source.lines().enumerate() {
            if line.contains("FileWriter") && line.contains("+") {
                issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                    "Validate file paths before writing.".to_string(),
                    Some(line.trim().to_string())));
            }
        }
        issues
    }
}

// ============================================================================
// Batch 5 - Additional security rules
// ============================================================================

macro_rules! security_rule {
    ($struct_name:ident, $id:expr, $title:expr, $severity:expr, $pattern:expr, $message:expr) => {
        pub struct $struct_name;
        impl Rule for $struct_name {
            fn id(&self) -> &str { $id }
            fn title(&self) -> &str { $title }
            fn severity(&self) -> Severity { $severity }
            fn category(&self) -> RuleCategory { RuleCategory::Security }
            fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
                static RE: Lazy<Regex> = Lazy::new(|| Regex::new($pattern).unwrap());
                let mut issues = Vec::new();
                for (line_num, line) in ctx.source.lines().enumerate() {
                    if RE.is_match(line) && !line.trim().starts_with("//") {
                        issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                            $message.to_string(), Some(line.trim().to_string())));
                    }
                }
                issues
            }
        }
    };
}

/// Extended security rule macro with OWASP/CWE mapping and debt estimation
macro_rules! security_rule_mapped {
    ($struct_name:ident, $id:expr, $title:expr, $severity:expr, $pattern:expr, $message:expr,
     owasp: $owasp:expr, cwe: $cwe:expr, debt: $debt:expr) => {
        pub struct $struct_name;
        impl Rule for $struct_name {
            fn id(&self) -> &str { $id }
            fn title(&self) -> &str { $title }
            fn severity(&self) -> Severity { $severity }
            fn category(&self) -> RuleCategory { RuleCategory::Security }
            fn owasp(&self) -> Option<OwaspCategory> { Some($owasp) }
            fn cwe(&self) -> Option<u32> { Some($cwe) }
            fn debt_minutes(&self) -> u32 { $debt }
            fn check(&self, ctx: &AnalysisContext) -> Vec<Issue> {
                static RE: Lazy<Regex> = Lazy::new(|| Regex::new($pattern).unwrap());
                let mut issues = Vec::new();
                for (line_num, line) in ctx.source.lines().enumerate() {
                    if RE.is_match(line) && !line.trim().starts_with("//") {
                        issues.push(create_issue(self, ctx.file_path, line_num + 1, 1,
                            $message.to_string(), Some(line.trim().to_string())));
                    }
                }
                issues
            }
        }
    };
}

// S2069: Unsafe password configuration
security_rule!(S2069UnsafePassword, "S2069", "Password settings are insecure",
    Severity::Critical, r"(?i)setPassword\s*\(\s*null|password\.isEmpty",
    "Passwords should not be empty or null.");

// S2070: Weak hash function used
security_rule!(S2070WeakHash, "S2070", "Weak hash function detected",
    Severity::Critical, r#"(?i)MessageDigest\.getInstance\s*\(\s*"(?:MD2|MD4)""#,
    "Use SHA-256 or stronger hash functions.");

// S2071: Insecure session management
security_rule!(S2071InsecureSession, "S2071", "Insecure session management",
    Severity::Major, r"(?i)session\.setAttribute\s*\(\s*.*(?:password|secret|key)",
    "Sensitive data should not be stored in session.");

// S2072: Sensitive data exposure
security_rule!(S2072DataExposure, "S2072", "Sensitive data may be exposed",
    Severity::Major, r"(?i)response\.getWriter\(\)\.print\s*\(.*(?:password|secret)",
    "Sensitive data should not be written to response.");

// S2073: Insecure file operation
security_rule!(S2073InsecureFileOp, "S2073", "Insecure file operation",
    Severity::Major, r"new\s+File\s*\([^)]*\+[^)]*(?:request|param)",
    "Validate file paths from user input.");

// S2074: Insecure redirect
security_rule!(S2074InsecureRedirect, "S2074", "Insecure redirect",
    Severity::Major, r"(?i)response\.sendRedirect\s*\([^)]*(?:request|param)",
    "Validate redirect URLs to prevent open redirect.");

// S2075: Insecure URL construction
security_rule!(S2075InsecureUrl, "S2075", "Insecure URL construction",
    Severity::Major, r"new\s+URL\s*\([^)]*\+[^)]*(?:request|param)",
    "Validate URLs constructed from user input.");

// S2077: SQL query construction
security_rule!(S2077SqlQuery, "S2077", "SQL query constructed from input",
    Severity::Critical, r"(?i)(?:createStatement|executeQuery)\s*\([^)]*\+",
    "Use prepared statements instead of string concatenation.");

// S2079: Cross-site scripting
security_rule!(S2079Xss, "S2079", "Potential cross-site scripting",
    Severity::Critical, r"(?i)out\.print\s*\([^)]*(?:request\.getParameter|param)",
    "Escape output to prevent XSS attacks.");

// S2080: Insecure XML processing
security_rule!(S2080InsecureXml, "S2080", "Insecure XML processing",
    Severity::Critical, r"DocumentBuilderFactory\.newInstance\s*\(\s*\)",
    "Disable external entities in XML parsing.");

// S2081: Insecure deserialization config
security_rule!(S2081InsecureDeserial, "S2081", "Insecure deserialization configuration",
    Severity::Critical, r"ObjectInputStream\s*\([^)]+\)",
    "Validate objects during deserialization.");

// S2082: Insecure CORS configuration
security_rule!(S2082InsecureCors, "S2082", "Insecure CORS configuration",
    Severity::Major, r#"(?i)addHeader\s*\(\s*"Access-Control-Allow-Origin"\s*,\s*"\*""#,
    "Restrict CORS origin to trusted domains.");

// S2084: Insecure content type
security_rule!(S2084InsecureContent, "S2084", "Insecure content type handling",
    Severity::Major, r"(?i)setContentType\s*\(.*request",
    "Validate content before setting content type.");

// S2085: Insecure cookie attribute
security_rule!(S2085InsecureCookie, "S2085", "Insecure cookie attributes",
    Severity::Major, r"new\s+Cookie\s*\([^)]+\)",
    "Set HttpOnly and Secure flags on cookies.");

// S2086: Insecure authentication
security_rule!(S2086InsecureAuth, "S2086", "Insecure authentication",
    Severity::Critical, r"(?i)(?:password|credential)\.equals\s*\(",
    "Use constant-time comparison for credentials.");

// S2087: Insecure random number
security_rule!(S2087InsecureRandom, "S2087", "Insecure random number",
    Severity::Critical, r"new\s+Random\s*\(\s*System\.currentTimeMillis",
    "Use SecureRandom with proper seeding.");

// S2088: Hardcoded crypto key
security_rule!(S2088HardcodedKey, "S2088", "Hardcoded cryptographic key",
    Severity::Blocker, r"(?i)SecretKeySpec\s*\(\s*[^)]*getBytes",
    "Cryptographic keys should not be hardcoded.");

// S2090: Weak SSL/TLS version
security_rule!(S2090WeakTls, "S2090", "Weak SSL/TLS version",
    Severity::Critical, r#"(?i)SSLContext\.getInstance\s*\(\s*"(?:SSL|TLSv1\.0)""#,
    "Use TLSv1.2 or TLSv1.3.");

// S2093: Insecure file upload
security_rule!(S2093InsecureUpload, "S2093", "Insecure file upload",
    Severity::Critical, r"(?i)getSubmittedFileName\s*\(\s*\)",
    "Validate file names and content types for uploads.");

// S2098: Insecure keystore
security_rule!(S2098InsecureKeystore, "S2098", "Insecure keystore configuration",
    Severity::Critical, r#"KeyStore\.getInstance\s*\(\s*"JKS""#,
    "Use PKCS12 instead of JKS for keystores.");

// S2099: Weak cipher suite
security_rule!(S2099WeakCipher, "S2099", "Weak cipher suite",
    Severity::Critical, r"(?i)setEnabledCipherSuites\s*\([^)]*(?:RC4|DES|NULL|EXPORT)",
    "Disable weak cipher suites.");

// S2100: Insecure trust manager
security_rule!(S2100InsecureTrust, "S2100", "Insecure trust manager",
    Severity::Blocker, r"TrustManager\s*\[\s*\].*new\s+X509TrustManager",
    "Do not disable certificate validation.");

// S2101: Debug logging sensitive data
security_rule!(S2101DebugSensitive, "S2101", "Debug logging may expose sensitive data",
    Severity::Major, r"(?i)(?:debug|trace)\s*\([^)]*(?:password|secret|key|token)",
    "Remove sensitive data from debug logs.");

// S2102: Insecure temporary directory
security_rule!(S2102InsecureTmpDir, "S2102", "Insecure temporary directory",
    Severity::Major, r#"(?i)System\.getProperty\s*\(\s*"java\.io\.tmpdir""#,
    "Temp directories may be world-readable.");

// S2103: Insecure permission grant
security_rule!(S2103InsecurePerm, "S2103", "Insecure permission grant",
    Severity::Critical, r"AccessController\.doPrivileged",
    "Review privileged code carefully.");

// S2104: Insecure reflection
security_rule!(S2104InsecureReflect, "S2104", "Insecure reflection",
    Severity::Critical, r"setAccessible\s*\(\s*true\s*\)",
    "Reflection bypasses access control.");

// S2105: Insecure native call
security_rule!(S2105InsecureNative, "S2105", "Insecure native call",
    Severity::Critical, r"System\.loadLibrary\s*\([^)]*\+",
    "Validate library names loaded from user input.");

// S2106: Insecure system property
security_rule!(S2106InsecureSysProp, "S2106", "Insecure system property",
    Severity::Major, r"System\.setProperty\s*\([^)]*(?:request|param)",
    "Validate system property names and values.");

// S2108: Insecure regex
security_rule!(S2108InsecureRegex, "S2108", "Insecure regex pattern",
    Severity::Major, r"Pattern\.compile\s*\([^)]*\+[^)]*(?:request|param)",
    "Validate regex patterns from user input.");

// S2112: Insecure object creation
security_rule!(S2112InsecureObject, "S2112", "Insecure object creation",
    Severity::Critical, r"Class\.forName\s*\([^)]*\+[^)]*(?:request|param)",
    "Validate class names from user input.");

// S2113: Insecure bean injection
security_rule!(S2113InsecureBean, "S2113", "Insecure bean injection",
    Severity::Critical, r"(?i)@Value\s*\(\s*.*\$\{[^}]*(?:password|secret)",
    "Externalize sensitive configuration securely.");

// S2117: Insecure entropy source
security_rule!(S2117InsecureEntropy, "S2117", "Insecure entropy source",
    Severity::Critical, r"new\s+SecureRandom\s*\(\s*\)\.setSeed",
    "Let SecureRandom seed itself.");

// S2124: Insecure XML binding
security_rule!(S2124InsecureXmlBind, "S2124", "Insecure XML binding",
    Severity::Critical, r"JAXBContext\.newInstance\s*\([^)]*Class\.forName",
    "Validate class names for XML binding.");

// S2125: Insecure JSON binding
security_rule!(S2125InsecureJson, "S2125", "Insecure JSON binding",
    Severity::Critical, r"(?i)objectMapper\.enableDefaultTyping\s*\(",
    "Disable default typing in Jackson.");

// S2126: Insecure YAML parsing
security_rule!(S2126InsecureYaml, "S2126", "Insecure YAML parsing",
    Severity::Critical, r"new\s+Yaml\s*\(\s*\)",
    "Use SafeConstructor with YAML parsing.");

// S2132: Insecure permission model
security_rule!(S2132InsecurePerm, "S2132", "Insecure permission model",
    Severity::Critical, r"AllPermission",
    "Avoid granting AllPermission.");

// S2135: Insecure SSL socket
security_rule!(S2135InsecureSsl, "S2135", "Insecure SSL socket factory",
    Severity::Critical, r"SSLSocketFactory\.getDefault\s*\(\s*\)",
    "Configure SSLContext with secure parameters.");

// S2136: Insecure hostname verifier
security_rule!(S2136InsecureHostname, "S2136", "Insecure hostname verifier",
    Severity::Blocker, r"HostnameVerifier.*return\s+true",
    "Do not disable hostname verification.");

// S2137: Insecure key generation
security_rule!(S2137InsecureKeyGen, "S2137", "Insecure key generation",
    Severity::Critical, r"KeyPairGenerator\.getInstance\s*\([^)]+\)\.initialize\s*\(\s*(?:512|768|1024)\s*\)",
    "Use at least 2048-bit keys for RSA.");

// S2138: Insecure certificate handling
security_rule!(S2138InsecureCert, "S2138", "Insecure certificate handling",
    Severity::Critical, r"checkValidity\s*\(\s*\)",
    "Verify certificate extensions and chain.");

// S2139: Insecure encryption mode
security_rule!(S2139InsecureEncMode, "S2139", "Insecure encryption mode",
    Severity::Critical, r#"Cipher\.getInstance\s*\(\s*"[^"]*ECB[^"]*""#,
    "Use CBC or GCM instead of ECB mode.");

// S2140: Insecure IV usage
security_rule!(S2140InsecureIv, "S2140", "Insecure IV usage",
    Severity::Critical, r"IvParameterSpec\s*\(\s*new\s+byte\[",
    "Use random IV for each encryption.");

// ============================================================================
// Batch 6 - Additional security rules
// ============================================================================

// S2141B: Insecure MAC algorithm
security_rule!(S2141InsecureMac, "S2141B", "Insecure MAC algorithm",
    Severity::Critical, r#"Mac\.getInstance\s*\(\s*"(?:HmacMD5|HmacSHA1)""#,
    "Use HMAC-SHA256 or stronger.");

// S2142B: Insecure signature algorithm
security_rule!(S2142InsecureSig, "S2142B", "Insecure signature algorithm",
    Severity::Critical, r#"Signature\.getInstance\s*\(\s*"(?:MD5|SHA1)withRSA""#,
    "Use SHA256withRSA or stronger.");

// S2143B: Insecure key agreement
security_rule!(S2143InsecureKeyAgree, "S2143B", "Insecure key agreement",
    Severity::Critical, r"KeyAgreement\.getInstance\s*\([^)]*DH[^)]*\)",
    "Use ECDH with strong curves.");

// S2144B: Hardcoded password in connection string
security_rule!(S2144HardcodedConnPwd, "S2144B", "Hardcoded password in connection",
    Severity::Blocker, r#"(?i)jdbc:[^"]*password=[^"&]+"#,
    "Use secure credential storage.");

// S2145: Insecure protocol version
security_rule!(S2145InsecureProtocol, "S2145", "Insecure protocol version",
    Severity::Critical, r#"(?i)setProtocol\s*\(\s*"(?:SSLv2|SSLv3|TLSv1\.0)""#,
    "Use TLSv1.2 or higher.");

// S2146: Missing input validation
security_rule!(S2146MissingValidation, "S2146", "Missing input validation",
    Severity::Major, r"getParameter\s*\([^)]+\)",
    "Validate user input before use.");

// S2147: Insecure redirect
security_rule!(S2147InsecureRedirect, "S2147", "Insecure redirect",
    Severity::Critical, r"sendRedirect\s*\([^)]*(?:request|param)",
    "Validate redirect URLs.");

// S2148: Insecure email header
security_rule!(S2148InsecureEmail, "S2148", "Insecure email header injection",
    Severity::Critical, r"(?i)addHeader\s*\([^)]*(?:request|param)",
    "Sanitize email headers.");

// S2149: Insecure LDAP authentication
security_rule!(S2149InsecureLdapAuth, "S2149", "Insecure LDAP authentication",
    Severity::Critical, r#"put\s*\(\s*Context\.SECURITY_AUTHENTICATION\s*,\s*"none""#,
    "Use authenticated LDAP binding.");

// S2150B: Insecure object storage
security_rule!(S2150InsecureStorage, "S2150B", "Insecure object storage",
    Severity::Major, r"ObjectOutputStream\s*\([^)]+\)",
    "Consider encrypting serialized data.");

// S2151B: Missing null check on authentication
security_rule!(S2151NullAuth, "S2151B", "Missing null check on authentication",
    Severity::Critical, r"getRemoteUser\s*\(\s*\)",
    "Check for null authentication.");

// S2152: Missing access control
security_rule!(S2152MissingAccess, "S2152", "Missing access control",
    Severity::Critical, r"@RequestMapping\s*\(",
    "Add access control to endpoints.");

// S2153B: Missing HTTPS enforcement
security_rule!(S2153HttpsEnforce, "S2153B", "Missing HTTPS enforcement",
    Severity::Major, r#"http://[a-zA-Z][^"]*api"#,
    "Use HTTPS for API calls.");

// S2154B: Weak session configuration
security_rule!(S2154WeakSession, "S2154B", "Weak session configuration",
    Severity::Major, r"setMaxInactiveInterval\s*\(\s*-1\s*\)",
    "Set session timeout.");

// S2155: Missing CSRF token
security_rule!(S2155MissingCsrf, "S2155", "Missing CSRF token validation",
    Severity::Critical, r"@PostMapping\s*\(",
    "Validate CSRF tokens on POST.");

// S2156: Insecure JWT configuration
security_rule!(S2156InsecureJwt, "S2156", "Insecure JWT configuration",
    Severity::Critical, r#"JWT(?:\.create|Parser)[^}]*"none""#,
    "Always sign JWT tokens.");

// S2157: Missing security headers
security_rule!(S2157MissingHeaders, "S2157", "Missing security headers",
    Severity::Major, r"@Controller\s+class",
    "Add security headers.");

// S2158: Insecure direct object reference
security_rule!(S2158InsecureIdor, "S2158", "Insecure direct object reference",
    Severity::Critical, r"@PathVariable\s*\(\s*.*id.*\)",
    "Verify user access to resource.");

// S2159B: Missing encryption
security_rule!(S2159MissingEncrypt, "S2159B", "Missing encryption",
    Severity::Critical, r"(?i)(?:ssn|creditcard|cardnumber)\s*=\s*[^;]*;",
    "Encrypt sensitive data.");

// S2160B: Insecure admin endpoint
security_rule!(S2160InsecureAdmin, "S2160B", "Insecure admin endpoint",
    Severity::Critical, r#"(?i)@RequestMapping\s*\(\s*.*admin.*\)"#,
    "Secure admin endpoints.");

// S2161: Missing rate limiting
security_rule!(S2161MissingRateLimit, "S2161", "Missing rate limiting",
    Severity::Major, r"@PostMapping\s*\(",
    "Add rate limiting to endpoints.");

// S2162B: Insecure API key handling
security_rule!(S2162InsecureApiKey, "S2162B", "Insecure API key handling",
    Severity::Critical, r#"(?i)api[_-]?key\s*=\s*"[^"]+""#,
    "Use environment variables for API keys.");

// S2163: Missing audit logging
security_rule!(S2163MissingAudit, "S2163", "Missing audit logging",
    Severity::Major, r"(?i)executeUpdate\s*\([^)]*(?:delete|update|insert)",
    "Add audit logging for data changes.");

// S2164B: Insecure file download
security_rule!(S2164InsecureDownload, "S2164B", "Insecure file download",
    Severity::Critical, r"setHeader\s*\([^)]*Content-Disposition[^)]*\+",
    "Sanitize filename in downloads.");

// S2165: Missing authentication
security_rule!(S2165MissingAuth, "S2165", "Missing authentication",
    Severity::Critical, r"@RestController\s+class",
    "Add authentication to REST controller.");

// S2166B: Insecure default password
security_rule!(S2166InsecureDefault, "S2166B", "Insecure default password",
    Severity::Blocker, r#"(?i)default[_-]?password\s*=\s*"[^"]+""#,
    "Remove default passwords.");

// S2167B: Missing input length check
security_rule!(S2167MissingLength, "S2167B", "Missing input length check",
    Severity::Major, r"getParameter\s*\([^)]+\)\.",
    "Check input length to prevent DoS.");

// S2168B: Insecure error message
security_rule!(S2168InsecureError, "S2168B", "Insecure error message",
    Severity::Major, r"getMessage\s*\(\s*\).*(?:response|print)",
    "Don't expose internal error messages.");

// S2169: Missing file type validation
security_rule!(S2169MissingFileType, "S2169", "Missing file type validation",
    Severity::Critical, r"getInputStream\s*\(\s*\)",
    "Validate file types on upload.");

// S2170: Insecure session ID
security_rule!(S2170InsecureSessionId, "S2170", "Insecure session ID regeneration",
    Severity::Critical, r"void\s+login\s*\(",
    "Regenerate session ID on login.");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnalyzerConfig;

    fn analyze_code(code: &str, rule: &dyn Rule) -> Vec<Issue> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(tree_sitter_java::language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let config = AnalyzerConfig::default();

        let ctx = AnalysisContext {
            source: code,
            file_path: "Test.java",
            tree: &tree,
            config: &config,
        };

        rule.check(&ctx)
    }

    #[test]
    fn test_s2068_hardcoded_password() {
        let code = r#"String password = "secret123";"#;
        let issues = analyze_code(code, &S2068HardcodedCredentials);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_s2068_no_password() {
        let code = r#"String name = "John";"#;
        let issues = analyze_code(code, &S2068HardcodedCredentials);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_s3649_sql_injection() {
        let code = r#"stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);"#;
        let issues = analyze_code(code, &S3649SqlInjection);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_s4790_weak_hashing() {
        let code = r#"MessageDigest.getInstance("MD5");"#;
        let issues = analyze_code(code, &S4790WeakHashing);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_s4790_strong_hashing() {
        let code = r#"MessageDigest.getInstance("SHA-256");"#;
        let issues = analyze_code(code, &S4790WeakHashing);
        assert!(issues.is_empty());
    }
}
