use base64::decode;
use std::fmt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() == 1 || args.iter().find(|s| *s == "-h").is_some() {
        eprintln!("{} program za čitanje verifikacionih URL-ova sa fiskalnih računa RS", &args[0]);
        eprintln!("Upotreba:\n{} https://suf.purs.gov.rs/v/?vl=A041RVg5S0Y3VzZVQlBaTzCtAQAAngEAALC%2Fe... #URL sa QR koda sa fiskalnog računa.", &args[0]);
        return Ok(());
    }

    eprintln!("decoding {}", &args[1]);
    let url = url::Url::parse(&args[1])?;
    let base64 = url.query_pairs()
        .find(|(a, _)| a == "vl")
        .map(|(_, b)| b.to_string())
        .expect("could not find ur query param vl");
    let out = decode(base64)?;

    if out.len() < 16 {
        eprintln!("data smaller than 16B");
        return Err("data smaller than 16B".into());
    }

    let md5::Digest(hash) = md5::compute(&out[0..out.len()-16]);
    let data_hash = &out[out.len()-16..];
    eprintln!("hash matches: {:?}", hash==data_hash);

    if hash == data_hash {
        let verification = Verification::from_bytes(&out)?;
        println!("{}", verification);
    }

    Ok(())
}

#[allow(dead_code)]
fn format_hex<T: AsRef<[u8]>>(data: T, f: &mut fmt::Formatter) -> fmt::Result {
    f.write_str("0x")?;
    f.write_str(
        &data
            .as_ref()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>(),
    )
}

fn format_b64<T: AsRef<[u8]>>(data: T, f: &mut fmt::Formatter) -> fmt::Result {
    f.write_str(&base64::encode(data))
}

#[derive(Debug)]
enum InvoiceType {
    Normal,
    ProForma,
    Copy,
    Training,
}

impl InvoiceType {
    fn from_byte(b: u8) -> InvoiceType {
        match b {
            0x00 => InvoiceType::Normal,
            0x01 => InvoiceType::ProForma,
            0x02 => InvoiceType::Copy,
            _ => InvoiceType::Training,
        }
    }
}

#[derive(Debug)]
enum TransactionType {
    Sale,
    Refund,
}

impl TransactionType {
    fn from_byte(b: u8) -> TransactionType { 
        if b == 0x00 {
            TransactionType::Sale
        } else {
            TransactionType::Refund
        }
    }
}

#[derive(Debug)]
struct Verification {
    version: u8,
    requested_by: String,
    signed_by: String,
    total_counter: u32,
    transaction_type_counter: u32,
    total_amount: f64,
    date_and_time: chrono::DateTime<chrono::Utc>,
    invoice_type: InvoiceType,
    transaction_type: TransactionType,
    buyer_id: String,
    encrypted_internal_data: Vec<u8>,
    signature: Vec<u8>,
}

impl std::fmt::Display for Verification {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "=========== VERIFICATION ===========\n")?;
        write!(fmt, "version:     {:>23}\n", self.version)?;
        write!(fmt, "requested by: {:>22}\n", self.requested_by)?;
        write!(fmt, "signed by:    {:>22}\n", self.signed_by)?;
        write!(fmt, "total counter:{:>22}\n", self.total_counter)?;
        write!(fmt, "transaction type counter: {:>10}\n", self.transaction_type_counter)?;
        write!(fmt, "total amount: {:>22.2}\n", self.total_amount)?;
        write!(fmt, "date and time: {:>21}\n",     self.date_and_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))?;
        write!(fmt, "invoice type: {:>22}\n",     format!("{:?}", self.invoice_type))?;
        write!(fmt, "transaction type: {:>18}\n", format!("{:?}", self.transaction_type))?;
        write!(fmt, "byer id:      {:>22}\n", self.buyer_id)?;
        write!(fmt, "encrypted internal data: ")?;
        format_b64(&self.encrypted_internal_data, fmt)?;
        write!(fmt, "\nsignature: ")?;
        format_b64(&self.signature, fmt)?;
        write!(fmt, "\n")
    }
}

impl Verification {
    fn from_bytes(data: &[u8]) -> Result<Verification, String> {
        if data.len() < 43+512+16 {
            return Err("payload too small to parse".to_string());
        }

        let version = data[0];
        let requested_by = String::from_utf8_lossy(&data[1..9]).to_string();
        let signed_by = String::from_utf8_lossy(&data[9..17]).to_string();
        let total_counter = u32::from_le_bytes([data[17], data[18], data[19], data[20]]);
        let transaction_type_counter = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);
        let total_amount = u64::from_le_bytes([data[25], data[26], data[27], data[28], data[29], data[30], data[31], data[32]]) as f64 / 10_000.0f64;
        let date_and_time = u64::from_be_bytes([data[33], data[34], data[35], data[36], data[37], data[38], data[39], data[40]]);
        let date_and_time = chrono::DateTime::from_utc(chrono::NaiveDateTime::from_timestamp((date_and_time/1000) as i64, (date_and_time % 1000) as u32 * 1_000_000), chrono::Utc);
        let invoice_type = InvoiceType::from_byte(data[41]);
        let transaction_type = TransactionType::from_byte(data[42]);
        let buyerid_len = data[43] as usize;
        let buyer_id = String::from_utf8_lossy(&data[44..44+buyerid_len]).to_string();
        let offset = 43+buyerid_len;
        let payload_size = if data.len()-offset > 512+256 { 512 } else { 256 };
        let encrypted_internal_data = data[offset..offset+payload_size].to_vec();
        let signature = data[offset+payload_size..offset+payload_size+256].to_vec();

        Ok(Verification {
            version,
            requested_by,
            signed_by,
            total_counter,
            transaction_type_counter,
            total_amount,
            date_and_time,
            invoice_type,
            transaction_type,
            buyer_id,
            encrypted_internal_data,
            signature,
        })
    }
}
