pub const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

#[derive(Clone, Debug)]
pub enum SchemeToken {
    Range { min: usize, max: usize },
    Check,
}

#[derive(Clone)]
pub struct PaddingScheme {
    schemes: Vec<Vec<SchemeToken>>,
}

impl PaddingScheme {
    pub fn parse(bytes: &[u8]) -> Self {
        let mut schemes = Vec::new();

        for line in bytes.split(|c| *c == b'\n').skip(1) {
            let mut tokens = line.split(|c| *c == b'=' || *c == b'-' || *c == b',');
            tokens.next();

            let mut scheme_tokens = Vec::new();
            while let Some(next_token) = tokens.next() {
                if next_token == b"c" {
                    scheme_tokens.push(SchemeToken::Check);
                } else {
                    let min = String::from_utf8_lossy(next_token).parse().unwrap();
                    let max = String::from_utf8_lossy(tokens.next().unwrap())
                        .parse()
                        .unwrap();
                    scheme_tokens.push(SchemeToken::Range { min, max });
                }
            }
            schemes.push(scheme_tokens);
        }

        Self { schemes }
    }
}

impl Iterator for PaddingScheme {
    type Item = Vec<SchemeToken>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.schemes.first() {
            Some(size) => {
                let size = Some(size.to_vec());
                self.schemes.remove(0);

                size
            }
            None => None,
        }
    }
}
