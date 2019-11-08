use core::fmt::{self, Display};

pub struct Ipv4Addr {
    a: u8,
    b: u8,
    c: u8,
    d: u8,
}

//impl Ipv4Addr {
//    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
//        Ipv4Addr {a, b, c, d}
//    }
//}


impl From<[u8; 4]> for Ipv4Addr {
    fn from(octets: [u8; 4]) -> Self {
        Ipv4Addr {a: octets[0], b: octets[1], c: octets[2], d: octets[3]}
    }
}

impl Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.a, self.b, self.c, self.d)
    }
}
